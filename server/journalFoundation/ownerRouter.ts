import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {verifyReleaseHeld,zeroPosition} from '../stockFoundation/integrity';
import {rejectLiveAllocation} from '../stockFoundation/validation';
import {ChainInputError,ChainConflictError,validateProposal,
 journalManifest,journalDigest,legDigest,balanceJournal} from './validation';
import {checkJournal,checkReviewedJournalHold} from './integrity';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Unposted journal evidence, duplicate serial or no-negative-stock constraint conflict'});return;
 }
 console.error('Unposted journal owner error',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Unposted journal service unavailable'});
}
async function audit(conn:PoolConnection,journalId:string,actor:string,details:object){
 await conn.execute(`INSERT INTO inv_unposted_journal_audit
  (id,journal_id,actor_id,event_type,event_sha256)
  VALUES(?,?,?,'JOURNAL_PROPOSED',?)`,
  [randomUUID(),journalId,actor,sha(JSON.stringify(details))]);
}
router.get('/eligible',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT r.id AS releaseIntentId,
   r.site_id AS siteId,r.status,h.state AS holdState,
   h.posting_state AS postingState,
   j.id AS journalId,j.status AS journalStatus
   FROM inv_stock_release_intents r
   JOIN inv_stock_release_holds h ON h.release_intent_id=r.id
   LEFT JOIN inv_unposted_journal_headers j ON j.release_intent_id=r.id
   WHERE r.prepared_by=? AND r.status='REVIEWED_HELD'
   AND h.state='HELD' AND h.posting_state='DISABLED'
   ORDER BY r.created_at DESC,r.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPoVerified:false,officialGrnVerified:false,
   actualLedgerEnabled:false,stockPostingEnabled:false});
 }catch(e){fail(res,e);}
});
router.get('/journals',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT j.id,j.release_intent_id AS releaseIntentId,
   j.site_id AS siteId,j.manifest_sha256 AS manifestSha256,j.status,
   j.posting_state AS postingState,h.id AS heldId,h.state AS heldState,
   j.created_at AS createdAt
   FROM inv_unposted_journal_headers j
   LEFT JOIN inv_unposted_journal_holds h ON h.journal_id=j.id
   WHERE j.prepared_by=? ORDER BY j.created_at DESC,j.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,postedJournalCount:0,availableToSell:null,serialOwnershipVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/journals',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateProposal>;
 try{input=validateProposal(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const release=await verifyReleaseHeld(conn,input.releaseIntentId);
  if(release.source.ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Held source unavailable to owner'});return;
  }
  const manifest=journalManifest({releaseIntentId:release.id,
   releaseSha256:release.intentSha256,siteId:release.source.siteId,
   lines:release.source.lines});
  const totals=balanceJournal(manifest.legs);
  const digest=journalDigest(manifest);
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,manifest_sha256 AS digest,status
   FROM inv_unposted_journal_headers WHERE release_intent_id=? FOR UPDATE`,
   [input.releaseIntentId]);
  if(existing.length){
   if(existing[0].digest!==digest)throw new ChainConflictError('Immutable journal manifest differs');
   const verified=await checkJournal(conn,String(existing[0].id));
   if(verified.manifestSha256!==digest)throw new ChainConflictError('Journal evidence mismatch');
   await conn.commit();
   res.status(200).json({id:existing[0].id,status:verified.status,replayed:true,
    ...totals,postingState:'DISABLED',availableToSell:null});return;
  }
  for(const line of release.source.lines)await zeroPosition(conn,release.source.siteId,line.productId);
  const journalId=randomUUID();
  await conn.execute(`INSERT INTO inv_unposted_journal_headers
   (id,release_intent_id,site_id,prepared_by,release_sha256,manifest_sha256,manifest_json)
   VALUES(?,?,?,?,?,?,?)`,
   [journalId,release.id,release.source.siteId,actor,release.intentSha256,
    digest,JSON.stringify(manifest)]);
  for(const leg of manifest.legs){
   await conn.execute(`INSERT INTO inv_unposted_journal_legs
    (id,journal_id,product_id,site_id,account_code,entry_side,quantity,
     tracking_mode,lot_code,serials_json,leg_sha256)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
    [randomUUID(),journalId,leg.productId,leg.siteId,leg.accountCode,leg.side,
     leg.quantity,leg.trackingMode,leg.lotCode,JSON.stringify(leg.serialNumbers),
     legDigest(leg)]);
  }
  for(const line of release.source.lines)for(const serial of line.serialNumbers)
   await conn.execute(`INSERT INTO inv_unposted_serial_candidates
    (id,journal_id,product_id,site_id,serial_number)
    VALUES(?,?,?,?,?)`,[randomUUID(),journalId,line.productId,release.source.siteId,serial]);
  await conn.execute('INSERT INTO inv_unposted_source_blockers(journal_id) VALUES(?)',[journalId]);
  await audit(conn,journalId,actor,{releaseIntentId:release.id,manifestSha256:digest,
   evidenceUnits:totals.evidenceUnits,postingState:'DISABLED'});
  await conn.commit();
  res.status(201).json({id:journalId,status:'PENDING_INTERNAL',replayed:false,
   ...totals,officialGrnVerified:false,supplierAuthenticated:false,
   serialOwnershipVerified:false,postingState:'DISABLED',availableToSell:null,
   message:'Balanced UNPOSTED evidence journal; no physical movement, saleable receipt or legal serial ownership.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/authority',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT
   (SELECT COUNT(*) FROM inv_unposted_journal_headers WHERE prepared_by=?) AS proposals,
   (SELECT COUNT(*) FROM inv_unposted_serial_candidates s
    JOIN inv_unposted_journal_headers j ON j.id=s.journal_id
    WHERE j.prepared_by=?) AS serialCandidates,
   (SELECT COUNT(*) FROM inv_unposted_journal_holds h
    JOIN inv_unposted_journal_headers j ON j.id=h.journal_id
    WHERE j.prepared_by=?) AS heldReviews`,
   [res.locals.auth.userId,res.locals.auth.userId,res.locals.auth.userId]);
  res.json({internalEvidence:rows[0],externalPoVerified:false,
   supplierAcknowledgmentAuthenticated:false,officialGrnVerified:false,
   warehouseReleaseAuthorized:false,serialOwnershipEstablished:false,
   operationalDoubleEntryLedgerEnabled:false,stockPostingEnabled:false,
   realReservationEnabled:false,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/debit-attempt',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 const b=req.body as Record<string,unknown>;
 if(!b||typeof b!=='object'||Array.isArray(b)||
  Object.keys(b).sort().join('|')!=='journalId|productId|quantity'||
  !inventoryId(b.journalId)||!inventoryId(b.productId)||
  typeof b.quantity!=='number'||!Number.isSafeInteger(b.quantity)||
  b.quantity<1||b.quantity>1000){
  res.status(400).json({error:'Exact journalId, productId and positive integer quantity required'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const state=await checkReviewedJournalHold(conn,b.journalId);
  if(state.release.source.ownerId!==res.locals.auth.userId){
   await conn.rollback();res.status(404).json({error:'No held journal for owner'});return;
  }
  if(!state.release.source.lines.some(l=>l.productId===b.productId))
   throw new ChainConflictError('Product is absent from internal evidence journal');
  await zeroPosition(conn,state.release.source.siteId,b.productId);
  rejectLiveAllocation(b.quantity);
  throw new ChainConflictError('No authorized stock balance exists for debit');
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
