import {randomUUID,createHash} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,ResultSetHeader,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {rupees,paise} from '../quotes/money';
import {ProcurementInputError,ProcurementConflictError,
 evidenceRef,purchaseHash,validateRequisition,validateSupplier} from './validation';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,err:unknown){
 if(err instanceof ProcurementInputError){res.status(400).json({error:err.message});return;}
 if(err instanceof ProcurementConflictError ||
   (err&&typeof err==='object'&&'code' in err&&err.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Procurement record already exists or request conflicts'});return;
 }
 console.error('Procurement failure',err instanceof Error?err.name:'Unknown');
 res.status(503).json({error:'Procurement service unavailable'});
}
async function event(conn:PoolConnection,actor:string,type:'SUPPLIER'|'REQUEST'|'HELD_ORDER',
 id:string,action:string,details:object|null=null){
 await conn.execute('INSERT INTO proc_audit_events(id,actor_id,entity_type,entity_id,action,detail_json) VALUES (?,?,?,?,?,?)',
  [randomUUID(),actor,type,id,action,details?JSON.stringify(details):null]);
}
router.get('/suppliers',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(
   "SELECT id,code,legal_name AS legalName,tax_id AS taxId,status,evidence_ref AS evidenceRef,created_at AS createdAt FROM proc_suppliers ORDER BY code LIMIT 200");
  res.json({items:rows,verification:'INTERNAL_ATTESTATION_ONLY',externalVerification:false});
 }catch(e){fail(res,e);}
});
router.post('/suppliers',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateSupplier>;
 try{input=validateSupplier(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const id=randomUUID(),actor=String(res.locals.auth.userId);
  await conn.execute('INSERT INTO proc_suppliers(id,code,legal_name,tax_id,created_by) VALUES (?,?,?,?,?)',
   [id,input.code,input.legalName,input.taxId,actor]);
  await event(conn,actor,'SUPPLIER',id,'CREATED_UNVERIFIED');
  await conn.commit();
  res.status(201).json({id,...input,status:'UNVERIFIED',externalVerification:false});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/requests',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT r.id,r.created_at AS createdAt,
   r.supplier_id AS supplierId,s.code AS supplierCode,s.legal_name AS supplierName,
   r.site_id AS siteId,i.code AS siteCode,r.quote_evidence_ref AS quoteEvidenceRef,
   r.subtotal,r.status,h.id AS holdId
   FROM proc_requests r
   JOIN proc_suppliers s ON s.id=r.supplier_id
   JOIN inventory_sites i ON i.id=r.site_id
   LEFT JOIN proc_po_holds h ON h.request_id=r.id
   WHERE r.created_by=? ORDER BY r.created_at DESC,r.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,dispatchEnabled:false,stockPosted:false});
 }catch(e){fail(res,e);}
});
router.get('/requests/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid request ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [requests]=await db.query<RowDataPacket[]>(`SELECT id,supplier_id AS supplierId,site_id AS siteId,
   quote_evidence_ref AS quoteEvidenceRef,subtotal,status,created_at AS createdAt
   FROM proc_requests WHERE id=? AND created_by=?`,[req.params.id,res.locals.auth.userId]);
  if(!requests.length){res.status(404).json({error:'Purchase request not found'});return;}
  const [lines]=await db.query<RowDataPacket[]>(`SELECT product_id AS productId,sku_snapshot AS sku,
   name_snapshot AS name,quantity,quoted_unit_cost AS quotedUnitCost,line_subtotal AS lineSubtotal
   FROM proc_request_items WHERE request_id=? ORDER BY position`,[req.params.id]);
  res.json({request:requests[0],items:lines,externalPurchaseOrderIssued:false});
 }catch(e){fail(res,e);}
});
router.post('/requests',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateRequisition>;
 try{input=validateRequisition(req.body);}catch(e){fail(res,e);return;}
 const key=req.get('idempotency-key');
 if(!inventoryId(key)){res.status(400).json({error:'UUID Idempotency-Key required'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 const actor=String(res.locals.auth.userId),hash=purchaseHash(input);
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const [claim]=await conn.execute<ResultSetHeader>(
   'INSERT IGNORE INTO proc_request_keys(actor_id,request_key,request_hash) VALUES (?,?,?)',
   [actor,key,hash]);
  const [keys]=await conn.query<RowDataPacket[]>(
   'SELECT request_hash,purchase_request_id FROM proc_request_keys WHERE actor_id=? AND request_key=? FOR UPDATE',
   [actor,key]);
  if(!keys.length)throw Error('Procurement idempotency reservation missing');
  if(keys[0].request_hash!==hash)throw new ProcurementConflictError('Idempotency payload mismatch');
  if(claim.affectedRows===0){
   if(!keys[0].purchase_request_id)throw Error('Incomplete committed idempotency key');
   const [prior]=await conn.query<RowDataPacket[]>(
    'SELECT id,subtotal,status FROM proc_requests WHERE id=? AND created_by=?',
    [keys[0].purchase_request_id,actor]);
   if(!prior.length)throw Error('Idempotency reference missing request');
   await conn.commit();res.status(200).json({
    id:prior[0].id,subtotal:prior[0].subtotal,status:prior[0].status,
    replayed:true,dispatchEnabled:false,stockPosted:false});return;
  }
  const [suppliers]=await conn.query<RowDataPacket[]>(
   'SELECT id,status FROM proc_suppliers WHERE id=? FOR UPDATE',[input.supplierId]);
  if(!suppliers.length||suppliers[0].status!=='REVIEWED_INTERNAL')
   throw new ProcurementInputError('Supplier requires independent internal identity review');
  const [sites]=await conn.query<RowDataPacket[]>(
   'SELECT id FROM inventory_sites WHERE id=? FOR UPDATE',[input.siteId]);
  if(!sites.length)throw new ProcurementInputError('Registered site not found');
  const snapshots:{productId:string;sku:string;name:string;quantity:number;unit:string;line:string}[]=[];
  for(const line of input.items){
   const [products]=await conn.query<RowDataPacket[]>(
    'SELECT id,sku,brand,model FROM crm_products WHERE id=? AND deleted_at IS NULL FOR UPDATE',
    [line.productId]);
   if(!products.length)throw new ProcurementInputError('Active catalog product not found');
   const product=products[0];
   snapshots.push({productId:line.productId,sku:String(product.sku),
    name:String(product.brand)+' '+String(product.model),quantity:line.quantity,
    unit:line.quotedUnitCost,line:rupees(paise(line.quotedUnitCost)*BigInt(line.quantity))});
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_requests
    (id,supplier_id,site_id,created_by,quote_evidence_ref,subtotal)
    VALUES (?,?,?,?,?,?)`,
   [id,input.supplierId,input.siteId,actor,input.quoteEvidenceRef,input.subtotal]);
  for(let i=0;i<snapshots.length;i++){
   const l=snapshots[i];
   await conn.execute(`INSERT INTO proc_request_items
     (id,request_id,position,product_id,sku_snapshot,name_snapshot,quantity,quoted_unit_cost,line_subtotal)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [randomUUID(),id,i+1,l.productId,l.sku,l.name,l.quantity,l.unit,l.line]);
  }
  await conn.execute('UPDATE proc_request_keys SET purchase_request_id=? WHERE actor_id=? AND request_key=?',
   [id,actor,key]);
  await event(conn,actor,'REQUEST',id,'SUBMITTED_FOR_INDEPENDENT_REVIEW',
   {supplierId:input.supplierId,siteId:input.siteId,lineCount:snapshots.length,subtotal:input.subtotal});
  await conn.commit();
  res.status(201).json({id,status:'PENDING',subtotal:input.subtotal,
   lineCount:snapshots.length,replayed:false,dispatchEnabled:false,stockPosted:false,
   message:'Internal purchase request saved for reviewer. No PO issued or goods received.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.post('/requests/:id/hold',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid request ID'});return;}
 if(!req.body||typeof req.body!=='object'||Array.isArray(req.body)||Object.keys(req.body).length){
  res.status(400).json({error:'Empty request body required; supplier address, amounts and recipients are server owned'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT r.id,r.status,r.supplier_id,r.site_id,
     r.subtotal,r.quote_evidence_ref,s.code AS supplier_code,s.legal_name AS supplier_name,
     s.status AS supplier_status
     FROM proc_requests r JOIN proc_suppliers s ON s.id=r.supplier_id
     WHERE r.id=? AND r.created_by=? FOR UPDATE`,[req.params.id,actor]);
  if(!rows.length){await conn.rollback();res.status(404).json({error:'Request not found'});return;}
  const reqRow=rows[0];
  if(reqRow.status!=='APPROVED_INTERNAL'||reqRow.supplier_status!=='REVIEWED_INTERNAL')
   throw new ProcurementConflictError('Independent review and supplier attestation required');
  const [decisions]=await conn.query<RowDataPacket[]>(
   "SELECT id FROM proc_review_decisions WHERE request_id=? AND decision='APPROVED_INTERNAL'",
   [req.params.id]);
  if(decisions.length!==1)throw new ProcurementConflictError('Missing independent reviewer decision');
  const [existing]=await conn.query<RowDataPacket[]>(
   'SELECT id,status,dispatch_state,snapshot_sha256 FROM proc_po_holds WHERE request_id=?',
   [req.params.id]);
  if(existing.length){
   if(existing[0].status!=='HELD'||existing[0].dispatch_state!=='DISABLED')
    throw Error('Unsafe held order state');
   await conn.commit();res.status(200).json({id:existing[0].id,
    status:'HELD',dispatchState:'DISABLED',sha256:existing[0].snapshot_sha256,replayed:true});
   return;
  }
  const [lines]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
   sku_snapshot AS sku,name_snapshot AS name,quantity,quoted_unit_cost AS quotedUnitCost,
   line_subtotal AS lineSubtotal FROM proc_request_items WHERE request_id=? ORDER BY position`,[req.params.id]);
  if(!lines.length)throw Error('Request lacks line snapshots');
  const snapshot={format:'aaditech-internal-po-hold-v1',requestId:req.params.id,
   supplierId:reqRow.supplier_id,supplierCode:reqRow.supplier_code,
   supplierName:reqRow.supplier_name,siteId:reqRow.site_id,
   supplierQuoteEvidenceRef:reqRow.quote_evidence_ref,subtotal:String(reqRow.subtotal),
   reviewId:String(decisions[0].id),lines};
  const payload=JSON.stringify(snapshot);
  const sha=createHash('sha256').update(payload).digest('hex'),id=randomUUID();
  await conn.execute(`INSERT INTO proc_po_holds
   (id,request_id,decision_id,prepared_by,snapshot_sha256,snapshot_json)
   VALUES (?,?,?,?,?,?)`,[id,req.params.id,decisions[0].id,actor,sha,payload]);
  await event(conn,actor,'HELD_ORDER',id,'INTERNAL_PO_HELD',
   {requestId:req.params.id,snapshotSha256:sha,dispatchState:'DISABLED'});
  await conn.commit();
  res.status(201).json({id,status:'HELD',dispatchState:'DISABLED',
   sha256:sha,replayed:false,externalPurchaseOrderIssued:false,stockPosted:false,
   message:'Internal held purchase-order snapshot only. No supplier delivery, goods receipt, stock movement or payment.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
