import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ChainInputError,ChainConflictError,releaseInput,releaseSnapshot,
 planInput,planDigest,releaseHoldSnapshot,rejectLiveAllocation} from './validation';
import {readHeldGrnSource,checkReleaseIntent,verifyReleaseHeld,zeroPosition} from './integrity';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Release/stock plan not authorized by verified source or no-negative-stock gate'});return;
 }
 console.error('Stock foundation owner request refused',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Internal stock-planning service unavailable'});
}
async function audit(c:PoolConnection,actor:string,id:string,type:'RELEASE'|'PLAN',
 event:'RELEASE_PREPARED'|'PLAN_HELD',details:object){
 await c.execute(`INSERT INTO inv_stock_foundation_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256) VALUES (?,?,?,?,?,?)`,
  [randomUUID(),actor,type,id,event,sha(JSON.stringify(details))]);
}
router.get('/held-grn',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT h.id AS heldGrnId,
   p.observation_id AS observationId,h.stock_posting_state AS postingState,
   i.status AS observationStatus,r.id AS releaseIntentId,r.status AS releaseStatus
   FROM inv_grn_held_records h JOIN inv_grn_reconciliation_packs p ON p.id=h.pack_id
   JOIN inv_inbound_observations i ON i.id=p.observation_id
   LEFT JOIN inv_stock_release_intents r ON r.held_grn_id=h.id
   WHERE p.prepared_by=? ORDER BY h.created_at DESC,h.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,officialGrnIssued:false,stockPostingEnabled:false,
   verifiedSupplierReceipt:false});
 }catch(e){fail(res,e);}
});
router.get('/release-intents',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT r.id,r.held_grn_id AS heldGrnId,
  r.observation_id AS observationId,r.site_id AS siteId,r.status,
  r.intent_sha256 AS intentSha256,h.id AS holdId,h.posting_state AS postingState,
  r.created_at AS createdAt FROM inv_stock_release_intents r
  LEFT JOIN inv_stock_release_holds h ON h.release_intent_id=r.id
  WHERE r.prepared_by=? ORDER BY r.created_at DESC,r.id DESC LIMIT 100`,
  [res.locals.auth.userId]);
  res.json({items:rows,postedMovements:0,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/release-intents',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof releaseInput>;
 try{input=releaseInput(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const source=await readHeldGrnSource(conn,input.heldGrnId);
  if(source.ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Evidence not available for owner'});return;
  }
  const snapshot=releaseSnapshot(source),digest=sha(JSON.stringify(snapshot));
  const [prior]=await conn.query<RowDataPacket[]>(`SELECT id,status,intent_sha256 AS digest
   FROM inv_stock_release_intents WHERE held_grn_id=? FOR UPDATE`,[input.heldGrnId]);
  if(prior.length){
   const state=await checkReleaseIntent(conn,String(prior[0].id));
   if(state.intentSha256!==digest)throw new ChainConflictError('Release source changed after intent');
   await conn.commit();
   res.status(200).json({id:prior[0].id,status:state.status,replayed:true,
    postingState:'DISABLED',postedStock:0,availableToSell:null});return;
  }
  for(const l of source.lines){
   await conn.execute(`INSERT IGNORE INTO inv_stock_position_gates(site_id,product_id)
    VALUES (?,?)`,[source.siteId,l.productId]);
   await zeroPosition(conn,source.siteId,l.productId);
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_stock_release_intents
   (id,held_grn_id,observation_id,site_id,prepared_by,
    source_sha256,intent_sha256,intent_json) VALUES (?,?,?,?,?,?,?,?)`,
   [id,input.heldGrnId,source.observationId,source.siteId,actor,
    source.heldGrnSha256,digest,JSON.stringify(snapshot)]);
  for(const line of source.lines){
   await conn.execute(`INSERT INTO inv_stock_release_intent_lines
    (id,release_intent_id,product_id,site_id,observed_quantity,tracking_mode,lot_code,serials_json)
    VALUES (?,?,?,?,?,?,?,?)`,
    [randomUUID(),id,line.productId,source.siteId,line.quantity,line.trackingMode,
     line.lotCode,JSON.stringify([...line.serialNumbers].sort())]);
  }
  await audit(conn,actor,id,'RELEASE','RELEASE_PREPARED',{
   heldGrnId:input.heldGrnId,sourceSha256:source.heldGrnSha256,
   intentSha256:digest,skuLines:source.lines.length});
  await conn.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',replayed:false,intentSha256:digest,
   availableToSell:null,postingState:'DISABLED',postedStock:0,
   message:'Non-posting stock release review preparation only, no external verified GRN, stock balance or reservation.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/reservation-plans',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,
   p.release_intent_id AS releaseIntentId,p.product_id AS productId,
   p.site_id AS siteId,p.requested_quantity AS requestedQuantity,p.planning_ref AS planningRef,
   p.state,p.reservation_state AS reservationState,p.intent_sha256 AS intentSha256
   FROM inv_reservation_planning_intents p
   WHERE p.prepared_by=? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,committedReservations:0,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/reservation-plans',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof planInput>;
 try{input=planInput(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const state=await verifyReleaseHeld(conn,input.releaseIntentId);
  if(state.source.ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Held release unavailable to owner'});return;
  }
  const line=state.source.lines.find(x=>x.productId===input.productId);
  if(!line||input.quantity>line.quantity)
   throw new ChainConflictError('Unposted evidence quantity insufficient for hypothetical plan');
  await zeroPosition(conn,state.source.siteId,input.productId);
  const digest=planDigest(input,state.intentSha256,state.source.siteId);
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,intent_sha256 AS digest
   FROM inv_reservation_planning_intents WHERE release_intent_id=? AND product_id=?
   FOR UPDATE`,[input.releaseIntentId,input.productId]);
  if(existing.length){
   if(existing[0].digest!==digest)throw new ChainConflictError('Immutable plan already exists with different quantity');
   await conn.commit();
   res.status(200).json({id:existing[0].id,replayed:true,state:'HELD',
    reservationState:'DISABLED',allocatedQuantity:0,availableToSell:null});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_reservation_planning_intents
   (id,release_intent_id,site_id,product_id,requested_quantity,planning_ref,prepared_by,
    intent_sha256) VALUES (?,?,?,?,?,?,?,?)`,
   [id,input.releaseIntentId,state.source.siteId,input.productId,input.quantity,
    input.planningRef,actor,digest]);
  await audit(conn,actor,id,'PLAN','PLAN_HELD',{
   releaseIntentId:input.releaseIntentId,productId:input.productId,digest});
  await conn.commit();
  res.status(201).json({id,replayed:false,state:'HELD',reservationState:'DISABLED',
   requestedQuantity:input.quantity,allocatedQuantity:0,availableToSell:null,
   message:'Non-allocating demand plan only; no sellable balance or reservation committed.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/positions',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT g.site_id AS siteId,
   g.product_id AS productId,g.available_quantity AS available,
   g.reserved_quantity AS reserved,g.picked_quantity AS picked,g.posted_quantity AS posted
   FROM inv_stock_position_gates g JOIN inventory_sites s ON s.id=g.site_id
   WHERE s.created_by=? ORDER BY g.site_id,g.product_id LIMIT 250`,[res.locals.auth.userId]);
  if(rows.some(r=>[r.available,r.reserved,r.picked,r.posted].some(v=>Number(v)!==0)))
   throw new ChainConflictError('Unsafe stock gate: nonzero balance');
  res.json({items:rows,verifiedSourceReceipts:0,postedStock:0,allocatedQuantity:0,
   availableToSell:null,postingAllowed:false});
 }catch(e){fail(res,e);}
});
router.post('/allocation-attempt',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof planInput>;
 try{input=planInput(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const state=await verifyReleaseHeld(conn,input.releaseIntentId);
  if(state.source.ownerId!==res.locals.auth.userId){
   await conn.rollback();res.status(404).json({error:'No release for owner'});return;
  }
  if(!state.source.lines.some(l=>l.productId===input.productId))
   throw new ChainConflictError('No SKU in held release');
  await zeroPosition(conn,state.source.siteId,input.productId);
  // Always conflicts: no authenticated GRN/stock receipt creates available units.
  rejectLiveAllocation(input.quantity);
  throw new ChainConflictError('Allocation is forbidden while source is not operationally verified');
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
