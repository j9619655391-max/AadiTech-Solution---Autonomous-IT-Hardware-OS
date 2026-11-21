import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {ProcurementInputError,ProcurementConflictError,
 validateSupplierReview,validateDecision} from './validation';

const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ProcurementInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ProcurementConflictError||
   (e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Procurement review already completed or conflicting'});return;
 }
 console.error('Procurement review unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Procurement review service unavailable'});
}
async function audit(conn:PoolConnection,actor:string,type:'SUPPLIER'|'REVIEW',
 id:string,action:string){
 await conn.execute('INSERT INTO proc_audit_events(id,actor_id,entity_type,entity_id,action) VALUES (?,?,?,?,?)',
  [randomUUID(),actor,type,id,action]);
}
router.get('/suppliers',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,code,legal_name AS legalName,
   tax_id AS taxId,status,created_by AS createdBy FROM proc_suppliers
   WHERE status='UNVERIFIED' AND created_by<>? ORDER BY created_at,id LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externalVerification:false});
 }catch(e){fail(res,e);}
});
router.post('/suppliers/:id/attest',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid supplier ID'});return;}
 let input:ReturnType<typeof validateSupplierReview>;
 try{input=validateSupplierReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(
   'SELECT id,status,created_by FROM proc_suppliers WHERE id=? FOR UPDATE',[req.params.id]);
  if(!rows.length||rows[0].created_by===actor){
   await conn.rollback();res.status(404).json({error:'Supplier not available for independent review'});return;
  }
  if(rows[0].status!=='UNVERIFIED')
   throw new ProcurementConflictError('Supplier was already attested');
  await conn.execute(`UPDATE proc_suppliers SET status='REVIEWED_INTERNAL',
     evidence_ref=?,reviewed_by=?,reviewed_at=UTC_TIMESTAMP(3) WHERE id=?`,
   [input.evidenceRef,actor,req.params.id]);
  await audit(conn,actor,'SUPPLIER',req.params.id,'INTERNAL_IDENTITY_ATTESTED');
  await conn.commit();
  res.status(201).json({id:req.params.id,status:'REVIEWED_INTERNAL',
   externalVerification:false,message:'Independent internal evidence reference recorded, not external supplier verification.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/requests',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT r.id,r.created_at AS createdAt,
   r.subtotal,r.status,r.quote_evidence_ref AS quoteEvidenceRef,
   s.code AS supplierCode,s.legal_name AS supplierName,
   s.status AS supplierStatus,i.code AS siteCode
   FROM proc_requests r
   JOIN proc_suppliers s ON s.id=r.supplier_id
   JOIN inventory_sites i ON i.id=r.site_id
   WHERE r.created_by<>? ORDER BY r.created_at DESC,r.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows});
 }catch(e){fail(res,e);}
});
router.get('/requests/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid request ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [requests]=await db.query<RowDataPacket[]>(`SELECT r.id,r.created_by AS createdBy,
   r.quote_evidence_ref AS quoteEvidenceRef,r.subtotal,r.status,
   s.code AS supplierCode,s.legal_name AS supplierName,s.status AS supplierStatus,
   i.code AS siteCode FROM proc_requests r
   JOIN proc_suppliers s ON s.id=r.supplier_id
   JOIN inventory_sites i ON i.id=r.site_id
   WHERE r.id=? AND r.created_by<>?`,[req.params.id,res.locals.auth.userId]);
  if(!requests.length){res.status(404).json({error:'Purchase request not available'});return;}
  const [lines]=await db.query<RowDataPacket[]>(`SELECT sku_snapshot AS sku,
   name_snapshot AS name,quantity,quoted_unit_cost AS quotedUnitCost,line_subtotal AS lineSubtotal
   FROM proc_request_items WHERE request_id=? ORDER BY position`,[req.params.id]);
  res.json({request:requests[0],items:lines,noSupplierDispatch:true});
 }catch(e){fail(res,e);}
});
router.post('/requests/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid request ID'});return;}
 let input:ReturnType<typeof validateDecision>;
 try{input=validateDecision(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT r.id,r.created_by,r.status,
     s.status AS supplier_status FROM proc_requests r
     JOIN proc_suppliers s ON s.id=r.supplier_id
     WHERE r.id=? FOR UPDATE`,[req.params.id]);
  if(!rows.length||rows[0].created_by===actor){
   await conn.rollback();res.status(404).json({error:'Request not available for independent review'});return;
  }
  if(rows[0].status!=='PENDING')
   throw new ProcurementConflictError('Purchase request already reviewed');
  if(input.decision==='APPROVED_INTERNAL'&&rows[0].supplier_status!=='REVIEWED_INTERNAL')
   throw new ProcurementConflictError('Supplier internal review required');
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_review_decisions
   (id,request_id,reviewer_id,decision,reason,evidence_attested) VALUES (?,?,?,?,?,?)`,
   [id,req.params.id,actor,input.decision,input.reason,input.evidenceAttested]);
  await conn.execute('UPDATE proc_requests SET status=? WHERE id=?',
   [input.decision,req.params.id]);
  await audit(conn,actor,'REVIEW',id,input.decision);
  await conn.commit();
  res.status(201).json({id,requestId:req.params.id,decision:input.decision,
   externalPurchaseOrderIssued:false,dispatchEnabled:false,
   message:'Internal review only. No supplier PO, warehouse receipt, reservation or payment.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
