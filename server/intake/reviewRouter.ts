import {randomUUID,createHash} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {IntakeInputError,IntakeConflictError,validateInbound,validateWitness,canonicalIntakeHash} from './validation';

const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,error:unknown){
 if(error instanceof IntakeInputError){res.status(400).json({error:error.message});return;}
 if(error instanceof IntakeConflictError||(error&&typeof error==='object'&&'code' in error&&error.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Intake witness conflicts with previously attested custody or immutable observation'});return;
 }
 console.error('Inbound witness failure',error instanceof Error?error.name:'Unknown');
 res.status(503).json({error:'Inbound witness service unavailable'});
}
function serials(value:unknown):string[]{
 if(typeof value==='string'){try{return serials(JSON.parse(value));}catch{throw new IntakeConflictError('Corrupt serial evidence');}}
 if(!Array.isArray(value)||value.some(x=>typeof x!=='string'))
  throw new IntakeConflictError('Corrupt serial evidence');
 return value as string[];
}
async function details(conn:PoolConnection|import('mysql2/promise').Pool,id:string){
 const [lines]=await conn.query<RowDataPacket[]>(`SELECT id,product_id AS productId,quantity,
   tracking_mode AS trackingMode,lot_code AS lotCode,serials_json AS serialNumbers
   FROM inv_inbound_lines WHERE observation_id=? ORDER BY product_id`,[id]);
 return lines.map(l=>({...l,serialNumbers:serials(l.serialNumbers)}));
}
router.get('/observations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT o.id,o.hold_id AS holdId,
   o.request_id AS requestId,o.status,o.recorded_by AS recordedBy,
   o.delivery_evidence_ref AS deliveryEvidenceRef,
   o.physical_count_ref AS physicalCountRef,o.created_at AS createdAt
   FROM inv_inbound_observations o WHERE o.recorded_by<>?
   ORDER BY o.created_at DESC,o.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalReceiptVerified:false,stockAvailable:false});
 }catch(e){fail(res,e);}
});
router.get('/observations/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid observation ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT o.id,o.hold_id AS holdId,
   o.request_id AS requestId,o.recorded_by AS recordedBy,o.status,
   o.delivery_evidence_ref AS deliveryEvidenceRef,
   o.physical_count_ref AS physicalCountRef,o.payload_sha256 AS payloadSha256
   FROM inv_inbound_observations o WHERE o.id=? AND o.recorded_by<>?`,
   [req.params.id,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'Observation unavailable for independent witness'});return;}
  const lines=await details(db,req.params.id);
  res.json({observation:rows[0],items:lines,externalReceiptVerified:false,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/observations/:id/witness',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid observation ID'});return;}
 let decision:ReturnType<typeof validateWitness>;
 try{decision=validateWitness(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT o.id,o.hold_id AS holdId,
   o.site_id AS siteId,o.recorded_by AS recordedBy,o.status,
   o.delivery_evidence_ref AS deliveryEvidenceRef,
   o.physical_count_ref AS physicalCountRef,o.payload_sha256 AS payloadSha256,
   h.status AS holdStatus,h.dispatch_state AS dispatchState,
   r.status AS requestStatus
   FROM inv_inbound_observations o JOIN proc_po_holds h ON h.id=o.hold_id
   JOIN proc_requests r ON r.id=o.request_id
   WHERE o.id=? FOR UPDATE`,[req.params.id]);
  if(!rows.length||rows[0].recordedBy===actor){
   await conn.rollback();res.status(404).json({error:'Observation unavailable for independent witness'});return;
  }
  const record=rows[0];
  if(record.status!=='AWAITING_WITNESS'||record.holdStatus!=='HELD'||
    record.dispatchState!=='DISABLED'||record.requestStatus!=='APPROVED_INTERNAL')
   throw new IntakeConflictError('Observation already decided or held PO authority changed');
  const lines=await details(conn,req.params.id);
  if(!lines.length)throw new IntakeConflictError('Missing observed goods');
  // Recompute canonical evidence hash from immutable DB lines. Browser is not trusted.
  const verified=validateInbound({holdId:record.holdId,
   deliveryEvidenceRef:record.deliveryEvidenceRef,physicalCountRef:record.physicalCountRef,
   items:lines.map(l=>({productId:l.productId,quantity:Number(l.quantity),
    trackingMode:l.trackingMode,lotCode:l.lotCode,serialNumbers:l.serialNumbers}))});
  const sha=canonicalIntakeHash(verified);
  if(sha!==record.payloadSha256)throw new IntakeConflictError('Inbound observation hash mismatch');
  const decisionId=randomUUID(),accepted=decision.outcome==='ACCEPT_QUARANTINE';
  await conn.execute(`INSERT INTO inv_inbound_decisions
   (id,observation_id,reviewer_id,outcome,inspection_evidence_ref,reason)
   VALUES (?,?,?,?,?,?)`,
   [decisionId,req.params.id,actor,decision.outcome,decision.inspectionEvidenceRef,decision.reason]);
  if(accepted){
   for(const line of lines){
    for(const serial of line.serialNumbers){
     await conn.execute(`INSERT INTO inv_quarantine_serials
      (id,observation_id,product_id,site_id,serial_number) VALUES (?,?,?,?,?)`,
      [randomUUID(),req.params.id,line.productId,record.siteId,serial]);
    }
    await conn.execute(`INSERT INTO inv_quarantine_custody_events
     (id,observation_id,line_id,site_id,product_id,quantity,recorded_by)
     VALUES (?,?,?,?,?,?,?)`,
     [randomUUID(),req.params.id,line.id,record.siteId,line.productId,Number(line.quantity),actor]);
   }
  }
  await conn.execute(`UPDATE inv_inbound_observations
   SET status=?,decided_at=UTC_TIMESTAMP(3) WHERE id=? AND status='AWAITING_WITNESS'`,
   [accepted?'QUARANTINED_INTERNAL':'REJECTED_INTERNAL',req.params.id]);
  const eventHash=createHash('sha256').update(JSON.stringify({
   observationId:req.params.id,observationHash:sha,decisionId,
   reviewerId:actor,outcome:decision.outcome,inspectionEvidenceRef:decision.inspectionEvidenceRef,
   reason:decision.reason,physicallyInspected:decision.physicallyInspected})).digest('hex');
  await conn.execute(`INSERT INTO inv_inbound_audit
   (id,observation_id,actor_id,event_type,event_hash) VALUES (?,?,?,?,?)`,
   [randomUUID(),req.params.id,actor,accepted?'QUARANTINE_ATTESTED':'OBSERVATION_REJECTED',eventHash]);
  await conn.commit();
  res.status(201).json({id:decisionId,observationId:req.params.id,
   status:accepted?'QUARANTINED_INTERNAL':'REJECTED_INTERNAL',
   evidenceHash:eventHash,quarantineCustodyEventsRecorded:accepted,
   availableToSell:null,reservedQuantity:null,externalReceiptVerified:false,
   supplierPOIssued:false,saleOrStockIssueAllowed:false,
   message:accepted?'Independent INTERNAL custody observation attested into quarantine. No real external receipt, saleable stock, reservation, issue or financial entry.'
    :'Observation rejected internally. No quarantine custody event or stock movement created.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
