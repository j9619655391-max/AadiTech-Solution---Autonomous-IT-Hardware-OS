import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {PROVIDER_CODE,REQUESTED_SCOPE} from './providerAuthorityPreflight.mjs';
import {assessPhase1AuPolicyDrift} from './phase1AuPolicyDrift.mjs';
import {
  verifyPhase1AvClaimJournal,assessPhase1AvAuthorityLifecycle
} from './phase1AvAuthorityLifecycle.mjs';

// Phase 1AW: offline cryptographic interoperability only, NEVER source of
// independent signer identity, eMudhra/RCAI authority, legal verification,
// release approval, credential enrollment, issuance, GRN, stock or finance.
// Public-key pins MUST originate outside this untrusted checkpoint; even a
// mathematically verified signature is NOT organizational authorization.
export const CHECKPOINT_PURPOSE='AADITECH_EXTERNAL_AUTHORITY_AUDIT_HOLD_V1';
const BODY_KEYS=Object.freeze([
 'schemaVersion','purpose','providerCode','requestedScope','sequence',
 'issuedAt','expiresAt','priorCheckpointSha256','journalEventCount',
 'journalTailSha256','policySnapshotSha256','recoveryClaimSha256','releaseDecision'
]);
const CHECKPOINT_KEYS=Object.freeze([...BODY_KEYS,'signatures']);
const SIG_KEYS=['role','reviewerRef','keyId','signatureBase64'];
const PIN_KEYS=['role','reviewerRef','keyId','publicKeyPem','publicKeySha256'];
const RECOVERY_KEYS=[
 'schemaVersion','incidentRef','recordedAt','isolatedRestoreClaimSha256',
 'mfaRecoveryClaimSha256','networkIsolationClaimSha256',
 'revocationRecheckClaimSha256','reviewers','outboundDispatchHeld',
 'releaseDecision'
];
const RECOVERY_REVIEWER_KEYS=['role','reviewerRef'];
const ROLES=['LEGAL','SECURITY'];
const RECOVERY_ROLES=['SECURITY','OPERATIONS','OWNER'];
const SHA=/^[a-f0-9]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_TTL_MS=24*3600000;
const PREFIX='AADITECH-PHASE-1AW-OFFLINE-CHECKPOINT-V1\0';
const RECEIPT_PREFIX='AADITECH-PHASE-1AW-CHECKPOINT-RECEIPT-V1\0';
const POLICY_PREFIX='AADITECH-PHASE-1AW-POLICY-CLAIMS-V1\0';
const INCIDENT_TYPES=new Set([
 'TRUST_ANCHOR_ROTATION_PROPOSED','TRUST_ANCHOR_COMPROMISE_SUSPECTED',
 'REVOCATION_CONFIRMED_CLAIM','REVOCATION_SOURCE_UNAVAILABLE',
 'PROVIDER_ACCESS_WITHDRAWN_CLAIM','EVIDENCE_REVIEW_EXPIRED'
]);
function exact(value,keys){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype||
    Object.keys(value).length!==keys.length||
    Object.keys(value).some(key=>!keys.includes(key)))
  throw Error('Invalid checkpoint schema, forbidden metadata, or authority switch');
}
function sha(value){
 if(typeof value!=='string'||!SHA.test(value))throw Error('Invalid SHA-256');
}
function ref(value){
 if(typeof value!=='string'||!REF.test(value))throw Error('Invalid opaque non-PII reference');
}
function utc(value){
 if(typeof value!=='string'||!UTC.test(value)||
    !Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)
  throw Error('Invalid canonical UTC timestamp');
 return Date.parse(value);
}
function clock(now){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('Invalid evaluation clock');
 return now.getTime();
}
function body(checkpoint){
 const b=Object.fromEntries(BODY_KEYS.map(key=>[key,checkpoint?.[key]]));
 exact(b,BODY_KEYS);
 if(b.schemaVersion!==1||b.purpose!==CHECKPOINT_PURPOSE||
    b.providerCode!==PROVIDER_CODE||b.requestedScope!==REQUESTED_SCOPE||
    b.releaseDecision!=='HOLD'||!Number.isSafeInteger(b.sequence)||
    b.sequence<1||b.sequence>1_000_000_000||
    !Number.isSafeInteger(b.journalEventCount)||
    b.journalEventCount<0||b.journalEventCount>64)
  throw Error('Invalid checkpoint purpose, release state or sequence');
 const issued=utc(b.issuedAt),expires=utc(b.expiresAt);
 if(expires<=issued||expires-issued>MAX_TTL_MS)
  throw Error('Invalid checkpoint lifetime');
 if(b.sequence===1){
  if(b.priorCheckpointSha256!==null)throw Error('Genesis checkpoint cannot claim a previous receipt');
 }else sha(b.priorCheckpointSha256);
 if(b.journalEventCount===0){
  if(b.journalTailSha256!==null)throw Error('Empty journal must have null tail');
 }else sha(b.journalTailSha256);
 sha(b.policySnapshotSha256);
 if(b.recoveryClaimSha256!==null)sha(b.recoveryClaimSha256);
 return b;
}
// Message deliberately uses fixed field order and context prefix to prevent
// signature replay as an operational instruction or on another service.
export function phase1AwCheckpointSigningBytes(checkpointBody){
 exact(checkpointBody,BODY_KEYS);
 const b=body(checkpointBody);
 return Buffer.from(PREFIX+JSON.stringify(BODY_KEYS.map(key=>b[key])),'utf8');
}
function signatures(value){
 if(!Array.isArray(value)||value.length!==2)throw Error('Exactly two role signatures required');
 for(let i=0;i<value.length;i++){
  const s=value[i];exact(s,SIG_KEYS);
  if(s.role!==ROLES[i])throw Error('Canonical distinct LEGAL and SECURITY signature roles required');
  ref(s.reviewerRef);ref(s.keyId);
  if(typeof s.signatureBase64!=='string'||s.signatureBase64.length!==88||
     !/^[A-Za-z0-9+/]{86}==$/.test(s.signatureBase64)||
     Buffer.from(s.signatureBase64,'base64').length!==64||
     Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
   throw Error('Invalid canonical detached Ed25519 signature encoding');
 }
 if(value[0].reviewerRef===value[1].reviewerRef||
    value[0].keyId===value[1].keyId)
  throw Error('Reviewer/key identity collision');
 return value;
}
// Receipt binds both signed data and detached signatures. It is a hash of
// untrusted bytes, not an externally witnessed/immutable checkpoint.
export function phase1AwCheckpointReceiptSha256(checkpoint){
 exact(checkpoint,CHECKPOINT_KEYS);const s=signatures(checkpoint.signatures);
 const b=phase1AwCheckpointSigningBytes(Object.fromEntries(BODY_KEYS.map(k=>[k,checkpoint[k]])));
 return createHash('sha256').update(RECEIPT_PREFIX)
   .update(b).update(JSON.stringify(s.map(x=>[
     x.role,x.reviewerRef,x.keyId,x.signatureBase64
   ]))).digest('hex');
}
function pinnedKeys(pins){
 if(!Array.isArray(pins)||pins.length!==2)
  throw Error('Two separately supplied public-key pins required');
 const refs=new Set(),keys=new Set(),result=[];
 for(let i=0;i<pins.length;i++){
  const p=pins[i];exact(p,PIN_KEYS);
  if(p.role!==ROLES[i])throw Error('Signer role pinning requires LEGAL and SECURITY');
  ref(p.reviewerRef);ref(p.keyId);sha(p.publicKeySha256);
  if(refs.has(p.reviewerRef)||keys.has(p.keyId))
   throw Error('Signer public-key identity collision');
  refs.add(p.reviewerRef);keys.add(p.keyId);
  if(typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>1024||
     !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(p.publicKeyPem))
   throw Error('Only bounded public SPKI PEM values are allowed');
  const pub=createPublicKey(p.publicKeyPem);
  if(pub.asymmetricKeyType!=='ed25519')
   throw Error('Reviewer pin is not Ed25519');
  const spki=pub.export({format:'der',type:'spki'});
  const hash=createHash('sha256').update(spki).digest('hex');
  if(hash!==p.publicKeySha256)throw Error('Reviewer SPKI pin mismatch');
  result.push({...p,publicKey:pub});
 }
 return result;
}
function sortKeys(value){
 if(Array.isArray(value))return value.map(sortKeys);
 if(value&&typeof value==='object'){
  return Object.fromEntries(Object.keys(value).sort().map(k=>[k,sortKeys(value[k])]));
 }
 return value;
}
export function phase1AwPolicyClaimsSha256(snapshot,now=new Date()){
 clock(now);
 // 1AU checks provider/scope, 16 document SHAs, window schema and policy
 // reference before any local digest is calculated.
 assessPhase1AuPolicyDrift(null,snapshot,now);
 return createHash('sha256').update(POLICY_PREFIX)
  .update(JSON.stringify(sortKeys(snapshot))).digest('hex');
}
function checkOne(checkpoint,pins,journal,policy,now){
 exact(checkpoint,CHECKPOINT_KEYS);
 const b=body(checkpoint),s=signatures(checkpoint.signatures);
 if(utc(b.issuedAt)>now.getTime()+5*60000)
  throw Error('Checkpoint issued too far in the future');
 const keys=pinnedKeys(pins);
 const message=phase1AwCheckpointSigningBytes(b);
 const signaturesValid=s.every((sig,i)=>
   sig.role===keys[i].role&&sig.reviewerRef===keys[i].reviewerRef&&
   sig.keyId===keys[i].keyId&&
   verifySignature(null,message,keys[i].publicKey,Buffer.from(sig.signatureBase64,'base64'))
 );
 const j=verifyPhase1AvClaimJournal(journal,now);
 const journalBound=b.journalEventCount===j.eventCount&&
   b.journalTailSha256===j.tailSha256;
 const policyBound=b.policySnapshotSha256===phase1AwPolicyClaimsSha256(policy,now);
 if(utc(b.issuedAt)<Date.parse(policy.recordedAt)||
    (journal.events.length>0&&utc(b.issuedAt)<utc(journal.events.at(-1).at)))
  throw Error('Signed checkpoint cannot predate its journal or policy evidence');
 return {
  issuedAt:utc(b.issuedAt),expired:utc(b.expiresAt)<=now.getTime(),
  signaturesValid,journalBound,policyBound,
  cryptographicallyConsistent:signaturesValid&&journalBound&&policyBound,
  receiptSha256:phase1AwCheckpointReceiptSha256(checkpoint)
 };
}
export function phase1AwRecoveryClaimSha256(claim){
 exact(claim,RECOVERY_KEYS);
 if(!Array.isArray(claim.reviewers))throw Error('Invalid recovery reviewer inventory');
 const canonical=RECOVERY_KEYS.map(k=>k==='reviewers'?
  claim.reviewers.map(r=>[r.role,r.reviewerRef]):claim[k]);
 return createHash('sha256').update('AADITECH-PHASE-1AW-RECOVERY-CLAIM-V1\\0')
  .update(JSON.stringify(canonical)).digest('hex');
}
function recoveryClaim(claim,journal,now){
 exact(claim,RECOVERY_KEYS);
 if(claim.schemaVersion!==1||claim.releaseDecision!=='HOLD'||
    claim.outboundDispatchHeld!==true)
  throw Error('Recovery claim cannot authorize or enable release');
 ref(claim.incidentRef);
 const date=utc(claim.recordedAt);
 if(date>now.getTime()+5*60000)throw Error('Future-dated recovery review claim');
 for(const k of ['isolatedRestoreClaimSha256','mfaRecoveryClaimSha256',
  'networkIsolationClaimSha256','revocationRecheckClaimSha256'])sha(claim[k]);
 if(!Array.isArray(claim.reviewers)||claim.reviewers.length!==3)
  throw Error('Recovery requires three distinct claimed reviewer roles');
 const refs=new Set();
 for(let i=0;i<claim.reviewers.length;i++){
  const r=claim.reviewers[i];exact(r,RECOVERY_REVIEWER_KEYS);
  if(r.role!==RECOVERY_ROLES[i])throw Error('Invalid recovery reviewer role');
  ref(r.reviewerRef);
  if(refs.has(r.reviewerRef))throw Error('Duplicate recovery reviewer');
  refs.add(r.reviewerRef);
 }
 // An anonymous local claim cannot retroactively invent an incident.
 const events=journal.events;
 const triggered=events.filter(e=>
  e.incidentRef===claim.incidentRef&&INCIDENT_TYPES.has(e.type));
 if(!triggered.length)throw Error('Recovery claim has no prior affected incident');
 if(date<utc(triggered[0].at))throw Error('Recovery claim predates incident');
 if(events.some(e=>refs.has(e.actorRef)))throw Error('Incident operator cannot self-witness recovery');
 return {syntheticRecoveryInventoryChecked:true,claimedReviewerCount:3};
}
function result(){
 return {
  phase:'1AW',reviewBasis:'OFFLINE_SIGNATURE_INTEROPERABILITY_NOT_AUTHORITY',
  currentCheckpointInspected:false,priorCheckpointInspected:false,
  signatureChecksPassed:false,checkpointJournalBound:false,
  checkpointPolicyBound:false,priorCheckpointValid:false,
  checkpointExpired:false,checkpointRollbackOrForkDetected:false,
  recoveryClaimInspected:false,recoveryClaimSchemaComplete:false,
  incidentQuarantineActive:false,incidentResponseRequired:false,
  independentlyAuthenticatedSignerKeys:false,
  independentlyAuthenticatedLegalOrProviderAuthority:false,
  authenticatedExternalTimestamp:false,immutableExternalStorageVerified:false,
  authenticatedLiveCrlOcsp:false,trustAnchorEnrollmentEnabled:false,
  credentialRotationExecuted:false,realRestoreWitnessed:false,
  officialGrnVerified:false,stockPostingEnabled:false,
  supplierDispatchEnabled:false,financePostingEnabled:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 };
}
export function assessPhase1AwCheckpointRecovery({
 priorJournal=null,currentJournal=null,priorPolicy=null,currentPolicy=null,
 priorCheckpoint=null,currentCheckpoint=null,reviewerKeyPins=null,
 recovery=null,now=new Date()
}={}){
 clock(now);
 const base=result(),blockers=new Set(['NO_INDEPENDENT_EXTERNAL_AUTHORITY_OR_APPROVAL']);
 if(currentCheckpoint===null||currentJournal===null||currentPolicy===null||
    reviewerKeyPins===null){
  return Object.freeze({
   ...base,blockerCodes:['MISSING_OFFLINE_CHECKPOINT_OR_PINNED_REVIEWER_KEYS',
    ...blockers].sort()
  });
 }
 const current=checkOne(currentCheckpoint,reviewerKeyPins,currentJournal,currentPolicy,now);
 const prior=priorCheckpoint===null?null:(
  priorJournal!==null&&priorPolicy!==null?
   checkOne(priorCheckpoint,reviewerKeyPins,priorJournal,priorPolicy,now):null
 );
 if(priorCheckpoint!==null&&prior===null)
  throw Error('Previous checkpoint requires its journal and policy');
 const governance=assessPhase1AvAuthorityLifecycle({
  baselineJournal:priorJournal,currentJournal,
  baselinePolicy:priorPolicy,currentPolicy,now
 });
 if(!current.signaturesValid)blockers.add('DETACHED_CHECKPOINT_SIGNATURE_INVALID');
 if(!current.journalBound)blockers.add('CHECKPOINT_JOURNAL_MISMATCH');
 if(!current.policyBound)blockers.add('CHECKPOINT_POLICY_CLAIMS_MISMATCH');
 if(current.expired)blockers.add('CHECKPOINT_EXPIRED');
 if(prior===null)blockers.add('NO_INDEPENDENT_SIGNED_CHECKPOINT_BASELINE');
 let historyProblem=false;
 if(prior){
  if(!prior.cryptographicallyConsistent){
   blockers.add('PREVIOUS_CHECKPOINT_CRYPTO_OR_BINDING_INVALID');
   historyProblem=true;
  }
  const priorBody=body(priorCheckpoint),currentBody=body(currentCheckpoint);
  if(currentBody.sequence!==priorBody.sequence+1||
     currentBody.priorCheckpointSha256!==prior.receiptSha256||
     current.issuedAt<prior.issuedAt){
   blockers.add('CHECKPOINT_ROLLBACK_OR_FORK');
   historyProblem=true;
  }
  if(governance.historyForkOrRollbackDetected){
   blockers.add('JOURNAL_HISTORY_ROLLBACK_OR_FORK');
   historyProblem=true;
  }
 }
 let recoveryChecked=false,recoveryMismatch=false;
 if(recovery!==null){
  recoveryClaim(recovery,currentJournal,now);
  if(utc(recovery.recordedAt)>utc(currentCheckpoint.issuedAt))
   throw Error('Recovery claim must precede the signed checkpoint');
  recoveryChecked=true;
  if(phase1AwRecoveryClaimSha256(recovery)!==currentCheckpoint.recoveryClaimSha256){
   recoveryMismatch=true;
   blockers.add('RECOVERY_CLAIM_NOT_SIGNED_IN_CHECKPOINT');
  }
  blockers.add('RECOVERY_CLAIMS_NOT_EXTERNALLY_WITNESSED');
 }else if(currentCheckpoint.recoveryClaimSha256!==null){
  recoveryMismatch=true;
  blockers.add('SIGNED_RECOVERY_CLAIM_MISSING');
 }
 if(governance.incidentQuarantineActive)blockers.add('EXTERNAL_INCIDENT_QUARANTINE');
 if(governance.policyReviewInspected&&!governance.currentJournalInspected)
  blockers.add('MISSING_INCIDENT_JOURNAL');
 return Object.freeze({
  ...base,currentCheckpointInspected:true,priorCheckpointInspected:prior!==null,
  signatureChecksPassed:current.signaturesValid,
  checkpointJournalBound:current.journalBound,
  checkpointPolicyBound:current.policyBound,
  priorCheckpointValid:prior?.cryptographicallyConsistent??false,
  checkpointExpired:current.expired,
  checkpointRollbackOrForkDetected:historyProblem,
  recoveryClaimInspected:recoveryChecked,
  recoveryClaimSchemaComplete:recoveryChecked,
  incidentQuarantineActive:governance.incidentQuarantineActive||
   historyProblem||current.expired||recoveryMismatch||!current.cryptographicallyConsistent,
  incidentResponseRequired:governance.incidentResponseRequired||
   historyProblem||current.expired||recoveryMismatch||!current.cryptographicallyConsistent,
  blockerCodes:Object.freeze([...blockers].sort())
 });
}
