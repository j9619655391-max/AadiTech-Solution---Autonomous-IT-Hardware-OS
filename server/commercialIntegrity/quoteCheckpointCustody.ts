import {createHash,createPublicKey} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {buildLocalQuoteHistoryCommitment,candidateWitnessReceiptDigest,
 verifyCandidateQuoteWitnessChain,type CandidateWitnessReceipt,
 type CandidatePinnedKey} from './quoteAnchors';
import {inspectInternalQuoteHistory} from './quoteHistory';
import {inspectInternalQuoteScope} from './checks';

// Phase 1BM: local quotation candidate-only ledger. No HTTP writer, no
// provider credentials, private keys, authoritative CRL/OCSP or WORM.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{64}$/;
const ACCEPTED='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({productionReleaseAuthorized:false,
 productionReleaseBlocked:true,releaseDecision:'HOLD' as const,
 independentlyAuthenticatedWitness:false,authenticatedRevocationEvidence:false,
 externallyPublishedCheckpointVerified:false,realWormVerified:false});
export function bmQuoteCheckpointWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BM_QUOTE_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BM quotation checkpoint write denied outside disposable CI/approved isolated TLS staging');
}
function digestPins(keys:CandidatePinnedKey[]){
 if(!Array.isArray(keys)||keys.length<1||keys.length>8)
  throw Error('Phase 1BM requires 1-8 candidate public pins');
 const sorted=keys.map(k=>{
  if(!k||typeof k.keyId!=='string'||!/^[-._:A-Za-z0-9]{1,96}$/.test(k.keyId)||
     !['ACTIVE','REVOKED','UNKNOWN'].includes(k.status))
   throw Error('Phase 1BM invalid candidate pin entry');
  const p=createPublicKey(k.publicKeySpkiPem);
  if(p.asymmetricKeyType!=='ed25519')throw Error('Phase 1BM non-Ed25519 candidate pin');
  return {keyId:k.keyId,publicKeySpkiSha256:createHash('sha256')
   .update(p.export({format:'der',type:'spki'})).digest('hex'),
   validFrom:k.validFrom,validUntil:k.validUntil};
 }).sort((a,b)=>a.keyId.localeCompare(b.keyId));
 if(new Set(sorted.map(k=>k.keyId)).size!==sorted.length)
  throw Error('Phase 1BM duplicate candidate pin');
 return createHash('sha256').update('aaditech/quote/pinset/v1\n'+
  JSON.stringify(sorted)).digest('hex');
}
export async function readCandidateQuoteSourceUnderLock(conn:PoolConnection,quoteId:string){
 const [drafts]=await conn.execute<RowDataPacket[]>(
  'SELECT q.*,c.deleted_at AS customer_deleted_at FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id WHERE q.id=? FOR UPDATE',[quoteId]);
 if(drafts.length!==1)throw Error('Phase 1BM quote source unavailable');
 const [lines]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position LIMIT 42',[quoteId]);
 const [revisions]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number ASC LIMIT 1002',[quoteId]);
 const [decisions]=await conn.execute<RowDataPacket[]>(
  'SELECT d.*,u.role AS reviewer_role FROM sales_quote_review_decisions d LEFT JOIN auth_users u ON u.id=d.owner_user_id WHERE d.quote_id=? ORDER BY d.revision_number ASC LIMIT 1002',[quoteId]);
 const [preparations]=await conn.execute<RowDataPacket[]>(
  `SELECT p.*,o.id AS outbox_id,o.event_type,o.dispatch_state,o.payload_sha256,
   (SELECT COUNT(*) FROM sales_quote_outbox_holds c WHERE c.release_preparation_id=p.id) AS outbox_count
   FROM sales_quote_release_preparations p
   LEFT JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id
   WHERE p.quote_id=? ORDER BY p.revision_number ASC LIMIT 1002`,[quoteId]);
 const {draft}= {draft:drafts[0]};
 const history=inspectInternalQuoteHistory({draft,lines,revisions,
  decisions,preparations,truncated:revisions.length>1000||
   decisions.length>1001||preparations.length>1001});
 const newest=revisions.at(-1)??null,revision=newest?Number(newest.revision_number):0;
 const currentReview=decisions.filter(x=>Number(x.revision_number)===revision);
 const currentPrep=preparations.filter(x=>Number(x.revision_number)===revision);
 const current=inspectInternalQuoteScope({draft,lines,revision:newest,
  decision:currentReview[0]??null,preparation:currentPrep[0]??null});
 const sourceValid=history.historyConsistent&&current.localScopeConsistent&&
  currentReview.length<=1&&currentPrep.length<=1;
 const commitment=buildLocalQuoteHistoryCommitment({draft,lines,revisions,decisions,preparations});
 return {commitment,sourceValid,revision};
}
export async function inspectCandidateQuoteCheckpointOnConnection(
 conn:PoolConnection,quoteId:string,expectedSourceSha256:string|null){
 if(!UUID.test(quoteId))throw Error('Phase 1BM invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bm_candidate_checkpoint_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
 if(!heads.length)return Object.freeze({candidateCheckpointExists:false,
  candidateCheckpointReceiptSha256:null,candidateCheckpointSourceSha256:null,
  candidateCheckpointGovernanceState:'ABSENT',candidateCheckpointSequence:0,
  candidateCheckpointLocallyConsistent:true,candidateCheckpointAnomalyCodes:[],
  ...HOLD});
 const [events]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bm_candidate_checkpoint_attempts WHERE quote_id=? ORDER BY id ASC LIMIT 1002 FOR UPDATE',[quoteId]);
 const errors=new Set<string>(),h=heads[0];
 let sequence=0,receipt:null|string=null,source:null|string=null,
  pinset:null|string=null,revision=0,incident=false,attempted=0;
 if(events.length>1000)errors.add('CHECKPOINT_ATTEMPT_BOUND_EXCEEDED');
 for(const row of events){
  attempted++;
  const seq=Number(row.sequence_number),candidateRevision=Number(row.candidate_revision_number),
   r=String(row.candidate_receipt_sha256),
   s=String(row.candidate_source_sha256),p=String(row.pinset_sha256);
  if(!Number.isSafeInteger(seq)||seq<1||
     !Number.isSafeInteger(candidateRevision)||candidateRevision<0||!SHA.test(r)||!SHA.test(s)||!SHA.test(p)||
     (row.previous_receipt_sha256!==null&&
      !SHA.test(String(row.previous_receipt_sha256)))||
     (row.claimed_publication_head_sha256!==null&&
      !SHA.test(String(row.claimed_publication_head_sha256))))
   errors.add('CHECKPOINT_ATTEMPT_INVALID');
  if(row.outcome===ACCEPTED){
   if(incident||seq!==sequence+1||
      row.previous_receipt_sha256!==receipt||
      (sequence>0&&(p!==pinset||candidateRevision<revision)))
    errors.add('CHECKPOINT_ACCEPTED_CHAIN_BROKEN');
   sequence=seq;receipt=r;source=s;pinset=p;revision=candidateRevision;
  }else incident=true;
 }
 if(Number(h.last_sequence)!==sequence||
    h.last_receipt_sha256!==receipt||h.last_source_sha256!==source||
    h.last_pinset_sha256!==pinset||
    Number(h.last_revision_number)!==revision)
  errors.add('CHECKPOINT_HEAD_HISTORY_DIVERGENCE');
 if((h.governance_state==='QUARANTINED')!==incident)
  errors.add('CHECKPOINT_QUARANTINE_STATE_MISMATCH');
 if(h.independent_publication_verified!=='NO'||
    h.independent_revocation_verified!=='NO'||
    h.external_worm_verified!=='NO'||h.production_release!=='HOLD')
  errors.add('CHECKPOINT_UNAUTHORIZED_TRUST_PROMOTION');
 if(sequence>0&&expectedSourceSha256!==null&&
    expectedSourceSha256!==source)
  errors.add('CHECKPOINT_SOURCE_HEAD_DRIFT');
 return Object.freeze({candidateCheckpointExists:true,
  candidateCheckpointGovernanceState:String(h.governance_state),
  candidateCheckpointSequence:sequence,
  candidateCheckpointReceiptSha256:receipt,
  candidateCheckpointSourceSha256:source,
  candidateCheckpointAttemptCount:attempted,
  candidateCheckpointLocallyConsistent:errors.size===0,
  candidateCheckpointAnomalyCodes:Object.freeze([...errors].sort()),
  ...HOLD});
}
export async function inspectCandidateQuoteCheckpoint(pool:Pool,quoteId:string,
 env:NodeJS.ProcessEnv=process.env){
 bmQuoteCheckpointWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {commitment}=await readCandidateQuoteSourceUnderLock(conn,quoteId);
  const result=await inspectCandidateQuoteCheckpointOnConnection(
   conn,quoteId,commitment.sourceCommitmentSha256);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateQuoteCheckpoint(pool:Pool,args:{
 quoteId:string,receipts:CandidateWitnessReceipt[],pinnedKeys:CandidatePinnedKey[],
 claimedPublicationHeadSha256?:string|null,env?:NodeJS.ProcessEnv
}){
 bmQuoteCheckpointWriteTarget(args.env??process.env);
 const {quoteId,receipts,pinnedKeys}=args;
 if(!UUID.test(quoteId)||!Array.isArray(receipts)||receipts.length<1||
    receipts.length>32)throw Error('Phase 1BM invalid or overlarge candidate receipt chain');
 const candidate=receipts.at(-1);
 if(!candidate||!candidate.body||candidate.body.quoteId!==quoteId)
  throw Error('Phase 1BM unbound witness receipt');
 const last=candidate.body;
 if(!SHA.test(last.sourceCommitmentSha256)||
    !Number.isSafeInteger(last.sequence)||last.sequence<1||
    !Number.isSafeInteger(last.revisionNumber)||last.revisionNumber<0)
  throw Error('Phase 1BM malformed candidate witness head');
 const claimed=args.claimedPublicationHeadSha256??null;
 if(claimed!==null&&!SHA.test(claimed))
  throw Error('Phase 1BM invalid claimed publication head digest');
 const pinset=digestPins(pinnedKeys);
 // To let an internal revocation *claim* freeze the stream, verify the
 // signature against the same candidate public material with ACTIVE status;
 // never treat that material as authenticated authority. Revocation wins.
 const candidateKeys=pinnedKeys.map(k=>({...k,status:'ACTIVE' as const}));
 const verified=verifyCandidateQuoteWitnessChain({quoteId,
  expectedSourceCommitmentSha256:last.sourceCommitmentSha256,
  receipts,pinnedKeys:candidateKeys});
 if(!verified.candidateWitnessChainConsistent)
  throw Error('Phase 1BM candidate signature/sequence/retention invalid: '+
   verified.witnessAnomalyCodes.join(','));
 const receiptDigest=candidateWitnessReceiptDigest(candidate);
 const revoked=pinnedKeys.some(k=>k.status!=='ACTIVE');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {commitment,sourceValid,revision}=await readCandidateQuoteSourceUnderLock(conn,quoteId);
  await conn.execute(
   'INSERT INTO quote_bm_candidate_checkpoint_streams (quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bm_candidate_checkpoint_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
  const h=heads[0],seq=Number(h.last_sequence);
  if(!h||!Number.isSafeInteger(seq)||seq<0||seq>32||
     (seq===0&&(h.last_receipt_sha256!==null||h.last_source_sha256!==null||
      h.last_pinset_sha256!==null)))
   throw Error('Phase 1BM corrupt stored candidate head');
  const historic=await inspectCandidateQuoteCheckpointOnConnection(conn,quoteId,null);
  if(!historic.candidateCheckpointLocallyConsistent)
   throw Error('Phase 1BM cannot append to inconsistent candidate checkpoint ledger');
  const [duplicated]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bm_candidate_checkpoint_attempts WHERE quote_id=? AND candidate_receipt_sha256=? LIMIT 2 FOR UPDATE',
   [quoteId,receiptDigest]);
  const exactReplay=h.governance_state==='HELD_UNVERIFIED'&&
   seq===last.sequence&&h.last_receipt_sha256===receiptDigest&&
   h.last_source_sha256===commitment.sourceCommitmentSha256&&
   h.last_pinset_sha256===pinset&&!revoked&&sourceValid&&
   (claimed===null||claimed===receiptDigest)&&
   duplicated.some(x=>x.outcome===ACCEPTED);
  if(exactReplay){
   await conn.commit();return Object.freeze({outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(duplicated.length){
   await conn.commit();return Object.freeze({outcome:'DUPLICATE_REJECTED',
    governanceState:String(h.governance_state),...HOLD});
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(revoked)outcome='REVOCATION_CLAIM_QUARANTINED';
  else if(claimed!==null&&claimed!==receiptDigest)
   outcome='PUBLICATION_MISMATCH_QUARANTINED';
  else if(!sourceValid||last.sourceCommitmentSha256!==commitment.sourceCommitmentSha256||
     last.revisionNumber>revision)
   outcome='SOURCE_MISMATCH_QUARANTINED';
  else if(seq===0)outcome=last.sequence===1&&last.previousReceiptSha256===null?
   ACCEPTED:'GAP_QUARANTINED';
  else if(last.sequence<=seq)
   outcome=last.sequence===seq?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(last.sequence!==seq+1)outcome='GAP_QUARANTINED';
  else if(last.previousReceiptSha256!==h.last_receipt_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else if(pinset!==h.last_pinset_sha256)
   outcome='PINSET_CHANGE_QUARANTINED';
  else if(last.revisionNumber<Number(h.last_revision_number))
   outcome='ROLLBACK_QUARANTINED';
  else if(last.revisionNumber>revision)
   outcome='SOURCE_MISMATCH_QUARANTINED';
  else outcome=ACCEPTED;
  await conn.execute(
   'INSERT INTO quote_bm_candidate_checkpoint_attempts (quote_id,sequence_number,candidate_revision_number,candidate_receipt_sha256,candidate_source_sha256,previous_receipt_sha256,pinset_sha256,claimed_publication_head_sha256,outcome) VALUES (?,?,?,?,?,?,?,?,?)',
   [quoteId,last.sequence,last.revisionNumber,receiptDigest,last.sourceCommitmentSha256,
    last.previousReceiptSha256,pinset,claimed,outcome]);
  if(outcome===ACCEPTED){
   await conn.execute(
    'UPDATE quote_bm_candidate_checkpoint_streams SET last_sequence=?,last_receipt_sha256=?,last_source_sha256=?,last_revision_number=?,last_pinset_sha256=? WHERE quote_id=?',
    [last.sequence,receiptDigest,last.sourceCommitmentSha256,last.revisionNumber,pinset,quoteId]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED')
   await conn.execute(
    "UPDATE quote_bm_candidate_checkpoint_streams SET governance_state='QUARANTINED' WHERE quote_id=?",[quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===ACCEPTED?'HELD_UNVERIFIED':'QUARANTINED',
   localCandidateOnly:true,independentPublishedProofAccepted:false,...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
