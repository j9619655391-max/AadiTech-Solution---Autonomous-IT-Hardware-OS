import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection,ResultSetHeader} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {IntakeInputError,IntakeConflictError,validateInbound,canonicalIntakeHash,reconstructHoldHash} from './validation';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof IntakeInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof IntakeConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Inbound observation conflicts with existing custody evidence or held PO'});return;
 }
 console.error('Inbound intake unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Inbound custody service unavailable'});
}
function holdSnapshot(raw:unknown):Record<string,any>{
 if(typeof raw==='string'){try{return JSON.parse(raw) as Record<string,any>;}catch{throw new IntakeConflictError('Invalid held PO JSON');}}
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new IntakeConflictError('Invalid held PO JSON');
 return raw as Record<string,any>;
}
export function orderedIntakeHash(input:ReturnType<typeof validateInbound>){
 return canonicalIntakeHash({...input,items:[...input.items].sort((a,b)=>a.productId.localeCompare(b.productId))});
}
router.get('/eligible',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT h.id AS holdId,r.id AS requestId,r.site_id AS siteId,
   s.code AS supplierCode,i.code AS siteCode,h.created_at AS heldAt,
   o.id AS observationId,o.status AS observationStatus
   FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_suppliers s ON s.id=r.supplier_id JOIN inventory_sites i ON i.id=r.site_id
   LEFT JOIN inv_inbound_observations o ON o.hold_id=h.id
   WHERE r.created_by=? AND r.status='APPROVED_INTERNAL'
   AND h.status='HELD' AND h.dispatch_state='DISABLED'
   ORDER BY h.created_at DESC,h.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPoIssued:false,
   disclaimer:'HELD means the supplier was NOT sent a purchase order. Observation cannot certify goods receipt.'});
 }catch(e){fail(res,e);}
});
router.get('/observations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT o.id,o.hold_id AS holdId,
   o.request_id AS requestId,o.status,o.delivery_evidence_ref AS deliveryEvidenceRef,
   o.physical_count_ref AS physicalCountRef,o.payload_sha256 AS payloadSha256,
   o.created_at AS createdAt,o.decided_at AS decidedAt
   FROM inv_inbound_observations o WHERE o.recorded_by=?
   ORDER BY o.created_at DESC,o.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,availableToSell:null,stockMovementsEnabled:false});
 }catch(e){fail(res,e);}
});
router.get('/observations/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid observation ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(
   'SELECT id,status,hold_id AS holdId,payload_sha256 AS payloadSha256 FROM inv_inbound_observations WHERE id=? AND recorded_by=?',
   [req.params.id,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'Observation not found'});return;}
  const [lines]=await db.query<RowDataPacket[]>(`SELECT product_id AS productId,quantity,
   tracking_mode AS trackingMode,lot_code AS lotCode,serials_json AS serialNumbers
   FROM inv_inbound_lines WHERE observation_id=? ORDER BY product_id`,[req.params.id]);
  res.json({observation:rows[0],items:lines,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/observations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateInbound>;
 try{input=validateInbound(req.body);}catch(e){fail(res,e);return;}
 const key=req.get('idempotency-key');
 if(!inventoryId(key)){res.status(400).json({error:'UUID Idempotency-Key required'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const actor=String(res.locals.auth.userId),hash=orderedIntakeHash(input);
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const [claim]=await conn.execute<ResultSetHeader>(
   'INSERT IGNORE INTO inv_inbound_request_keys(actor_id,request_key,request_hash) VALUES (?,?,?)',
   [actor,key,hash]);
  const [keys]=await conn.query<RowDataPacket[]>(
   'SELECT request_hash,observation_id FROM inv_inbound_request_keys WHERE actor_id=? AND request_key=? FOR UPDATE',
   [actor,key]);
  if(!keys.length)throw Error('Inbound idempotency reservation missing');
  if(keys[0].request_hash!==hash)throw new IntakeConflictError('Idempotency key changed');
  if(claim.affectedRows===0){
   if(!keys[0].observation_id)throw Error('Incomplete previous intake request');
   const [existing]=await conn.query<RowDataPacket[]>(
    'SELECT id,status FROM inv_inbound_observations WHERE id=? AND recorded_by=?',
    [keys[0].observation_id,actor]);
   if(!existing.length)throw Error('Idempotency observation missing');
   await conn.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,replayed:true,
    availableToSell:null,receiptAccepted:false});return;
  }
  const [holds]=await conn.query<RowDataPacket[]>(`SELECT h.id,h.status AS holdStatus,
   h.dispatch_state AS dispatchState,h.snapshot_json AS snapshotJson,
   h.snapshot_sha256 AS snapshotSha256,r.id AS requestId,r.created_by AS ownerId,
   r.site_id AS siteId,r.supplier_id AS supplierId,r.status AS requestStatus,
   d.id AS decisionId,d.decision AS reviewDecision
   FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_review_decisions d ON d.id=h.decision_id
   WHERE h.id=? FOR UPDATE`,[input.holdId]);
  if(!holds.length||holds[0].ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Held PO not found for owner'});return;
  }
  const h=holds[0];
  if(h.holdStatus!=='HELD'||h.dispatchState!=='DISABLED'||
     h.requestStatus!=='APPROVED_INTERNAL'||h.reviewDecision!=='APPROVED_INTERNAL')
   throw new IntakeConflictError('Held PO status or reviewer authorization invalid');
  const snap=holdSnapshot(h.snapshotJson);
  if(reconstructHoldHash(snap)!==h.snapshotSha256||
     snap.requestId!==h.requestId||snap.siteId!==h.siteId||
     snap.supplierId!==h.supplierId||snap.reviewId!==h.decisionId)
   throw new IntakeConflictError('Held PO snapshot signature or ownership mismatch');
  const [reqLines]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
   sku_snapshot AS sku,name_snapshot AS name,quantity,quoted_unit_cost AS quotedUnitCost,
   line_subtotal AS lineSubtotal FROM proc_request_items
   WHERE request_id=? ORDER BY position`,[h.requestId]);
  if(reqLines.length!==input.items.length||reqLines.length!==snap.lines.length)
   throw new IntakeConflictError('Intake must exactly match complete held PO lines');
  for(let i=0;i<reqLines.length;i++){
   const original=reqLines[i],held=snap.lines[i];
   const observed=input.items.find(x=>x.productId===original.productId);
   if(!observed||observed.quantity!==Number(original.quantity)||
      held.productId!==original.productId||held.quantity!==Number(original.quantity)||
      held.sku!==original.sku||held.name!==original.name||
      String(held.quotedUnitCost)!==String(original.quotedUnitCost)||
      String(held.lineSubtotal)!==String(original.lineSubtotal))
    throw new IntakeConflictError('PO line mismatch or partial/overcount intake refused');
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_inbound_observations
   (id,hold_id,request_id,site_id,recorded_by,delivery_evidence_ref,physical_count_ref,payload_sha256)
   VALUES (?,?,?,?,?,?,?,?)`,
   [id,input.holdId,h.requestId,h.siteId,actor,input.deliveryEvidenceRef,
    input.physicalCountRef,hash]);
  for(const line of input.items){
   await conn.execute(`INSERT INTO inv_inbound_lines
     (id,observation_id,product_id,quantity,tracking_mode,lot_code,serials_json)
     VALUES (?,?,?,?,?,?,?)`,
    [randomUUID(),id,line.productId,line.quantity,line.trackingMode,line.lotCode,
     JSON.stringify(line.serialNumbers)]);
  }
  await conn.execute('UPDATE inv_inbound_request_keys SET observation_id=? WHERE actor_id=? AND request_key=?',
   [id,actor,key]);
  await conn.execute(`INSERT INTO inv_inbound_audit
   (id,observation_id,actor_id,event_type,event_hash) VALUES (?,?,?,?,?)`,
   [randomUUID(),id,actor,'OBSERVATION_RECORDED',hash]);
  await conn.commit();
  res.status(201).json({id,status:'AWAITING_WITNESS',replayed:false,payloadSha256:hash,
   availableToSell:null,receiptAccepted:false,stockMovementsEnabled:false,
   message:'Unverified internal inbound observation recorded; no goods receipt, stock availability or warehouse issue created.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/quarantine-summary',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT e.site_id AS siteId,i.code AS siteCode,
   e.product_id AS productId,p.sku,COUNT(*) AS eventCount,SUM(e.quantity) AS attestedQuantity
   FROM inv_quarantine_custody_events e
   JOIN inventory_sites i ON i.id=e.site_id JOIN crm_products p ON p.id=e.product_id
   JOIN inv_inbound_observations o ON o.id=e.observation_id
   WHERE o.status='QUARANTINED_INTERNAL'
   GROUP BY e.site_id,i.code,e.product_id,p.sku ORDER BY i.code,p.sku LIMIT 100`);
  const [checks]=await db.query<RowDataPacket[]>(`SELECT
   (SELECT COUNT(*) FROM inv_quarantine_custody_events e
     JOIN inv_inbound_observations o ON o.id=e.observation_id
     WHERE o.status<>'QUARANTINED_INTERNAL') AS orphanedStatus,
   (SELECT COUNT(*) FROM inv_inbound_lines l
     JOIN inv_inbound_observations o ON o.id=l.observation_id
     LEFT JOIN inv_quarantine_custody_events e ON e.line_id=l.id
     WHERE o.status='QUARANTINED_INTERNAL' AND (e.id IS NULL OR
       e.quantity<>l.quantity OR e.site_id<>o.site_id OR e.product_id<>l.product_id)) AS mismatchedLines,
   (SELECT COALESCE(SUM(l.quantity),0) FROM inv_inbound_lines l
     JOIN inv_inbound_observations o ON o.id=l.observation_id
     WHERE o.status='QUARANTINED_INTERNAL' AND l.tracking_mode='SERIAL') AS expectedSerials,
   (SELECT COUNT(*) FROM inv_quarantine_serials) AS storedSerials`);
  const c=checks[0];
  const inconsistencies=Number(c.orphanedStatus)+Number(c.mismatchedLines)+
    Math.abs(Number(c.expectedSerials)-Number(c.storedSerials));
  res.json({items:rows,internalLedgerConsistent:inconsistencies===0,
   internalDiscrepancies:inconsistencies,availableToSell:null,reservedQuantity:null,
   financialValue:null,externalReceiptVerified:false,goodsIssued:false,
   disclaimer:'Read-only internal quarantine custody evidence; not physical stock certification, available inventory, external goods receipt or financial valuation.'});
 }catch(e){fail(res,e);}
});
export default router;
