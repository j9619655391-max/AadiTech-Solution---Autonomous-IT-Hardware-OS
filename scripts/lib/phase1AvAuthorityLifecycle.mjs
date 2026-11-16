import {createHash} from 'node:crypto';
import {PROVIDER_CODE,REQUESTED_SCOPE} from './providerAuthorityPreflight.mjs';
import {assessPhase1AuPolicyDrift} from './phase1AuPolicyDrift.mjs';

// Phase 1AV: SELF-HASHED administrative claims journal, NOT a digital
// signature, trusted timestamp, external CA enrollment, legal authority,
// credential revocation executor, nor a way to turn on stock or production.
export const AUTHORITY_EVENT_TYPES=Object.freeze([
 'TRUST_ANCHOR_ROTATION_PROPOSED',
 'TRUST_ANCHOR_COMPROMISE_SUSPECTED',
 'REVOCATION_CONFIRMED_CLAIM',
 'REVOCATION_SOURCE_UNAVAILABLE',
 'PROVIDER_ACCESS_WITHDRAWN_CLAIM',
 'EVIDENCE_REVIEW_EXPIRED',
 'INCIDENT_ACKNOWLEDGED',
 'INCIDENT_CLOSURE_CLAIMED'
]);
const TYPES=new Set(AUTHORITY_EVENT_TYPES);
const TRIGGERS=new Set(AUTHORITY_EVENT_TYPES.slice(0,6));
const REVIEW_REQUIRED=new Set([
 'TRUST_ANCHOR_ROTATION_PROPOSED','INCIDENT_CLOSURE_CLAIMED'
]);
const ANCHOR_TYPES=new Set([
 'TRUST_ANCHOR_ROTATION_PROPOSED','TRUST_ANCHOR_COMPROMISE_SUSPECTED'
]);
const SHA=/^[a-f0-9]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const JOURNAL_KEYS=['schemaVersion','providerCode','requestedScope','events'];
const EVENT_KEYS=['schemaVersion','sequence','at','type','incidentRef',
 'actorRef','evidenceSha256','anchorSha256','reviewers','prevEventSha256','eventSha256'];
const REVIEWER_KEYS=['role','ref'];
const HOUR=3_600_000;

function exact(value,keys){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype||
    Object.keys(value).length!==keys.length||
    Object.keys(value).some(k=>!keys.includes(k)))
   throw Error('Invalid or unexpected administrative claim fields');
}
function utc(value){
 if(typeof value!=='string'||!UTC.test(value)||
    !Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)
   throw Error('Invalid canonical UTC event timestamp');
 return Date.parse(value);
}
function sha(value){if(typeof value!=='string'||!SHA.test(value))throw Error('Invalid SHA-256 claim');}
function ref(value){if(typeof value!=='string'||!REF.test(value))throw Error('Invalid non-PII reviewer/incident reference');}

function canonicalEventData(e){
 return [
  e.schemaVersion,e.sequence,e.at,e.type,e.incidentRef,e.actorRef,
  e.evidenceSha256,e.anchorSha256,
  e.reviewers.map(r=>[r.role,r.ref]),e.prevEventSha256
 ];
}
// This proves only self-consistency of a locally held journal.
// Whoever controls both the journal and hashes can rewrite both.
export function phase1AvEventSha256(eventWithoutHash){
 return createHash('sha256').update(JSON.stringify(canonicalEventData(eventWithoutHash))).digest('hex');
}
export function verifyPhase1AvClaimJournal(journal,now=new Date()){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('Invalid review clock');
 exact(journal,JOURNAL_KEYS);
 if(journal.schemaVersion!==1||journal.providerCode!==PROVIDER_CODE||
    journal.requestedScope!==REQUESTED_SCOPE||!Array.isArray(journal.events)||
    journal.events.length>64)
   throw Error('Unexpected provider, sandbox scope or journal size');
 const events=journal.events,seenPairs=new Set(),activeIncidentRefs=new Set();
 const proposedAnchors=new Set();
 let prev=null,lastTime=-Infinity,incidentTriggerCount=0,closureClaims=0;
 for(let i=0;i<events.length;i++){
  const e=events[i];exact(e,EVENT_KEYS);
  if(e.schemaVersion!==1||e.sequence!==i+1||!TYPES.has(e.type)||
     e.prevEventSha256!==prev||typeof e.eventSha256!=='string'||
     !SHA.test(e.eventSha256))
   throw Error('Journal sequence, event type, or previous digest invalid');
  const time=utc(e.at);
  if(time<lastTime||time>now.getTime()+5*60_000)
   throw Error('Out-of-order or future administrative incident');
  lastTime=time;
  ref(e.incidentRef);ref(e.actorRef);sha(e.evidenceSha256);
  if(ANCHOR_TYPES.has(e.type))sha(e.anchorSha256);
  else if(e.anchorSha256!==null)throw Error('Unexpected candidate trust-anchor claim');
  if(!Array.isArray(e.reviewers)||e.reviewers.length>2)
   throw Error('Invalid independent reviewer inventory');
  const reviewerRoles=new Set(),reviewerRefs=new Set();
  for(const r of e.reviewers){
   exact(r,REVIEWER_KEYS);
   if(!['SECURITY','LEGAL'].includes(r.role))throw Error('Unknown reviewer role');
   ref(r.ref);
   if(r.ref===e.actorRef||reviewerRefs.has(r.ref)||reviewerRoles.has(r.role))
    throw Error('Self-review or reviewer-role collision');
   reviewerRefs.add(r.ref);reviewerRoles.add(r.role);
  }
  if(REVIEW_REQUIRED.has(e.type)){
   if(e.reviewers.length!==2||!reviewerRoles.has('SECURITY')||
      !reviewerRoles.has('LEGAL'))throw Error('Separate claimed security and legal reviewers required');
  }else if(e.reviewers.length!==0)
   throw Error('Spurious review or approval claim');
  const eventKey=e.incidentRef+'|'+e.type;
  if(seenPairs.has(eventKey))throw Error('Repeated incident transition');
  seenPairs.add(eventKey);
  if(e.type==='INCIDENT_ACKNOWLEDGED'||e.type==='INCIDENT_CLOSURE_CLAIMED'){
   if(!activeIncidentRefs.has(e.incidentRef))
    throw Error('Incident claim without prior risk trigger');
  }else if(TRIGGERS.has(e.type))activeIncidentRefs.add(e.incidentRef);
  if(e.type==='TRUST_ANCHOR_ROTATION_PROPOSED'){
   if(proposedAnchors.has(e.anchorSha256))throw Error('Repeated proposed trust-anchor candidate');
   proposedAnchors.add(e.anchorSha256);
  }
  if(TRIGGERS.has(e.type))incidentTriggerCount++;
  if(e.type==='INCIDENT_CLOSURE_CLAIMED')closureClaims++;
  if(phase1AvEventSha256(e)!==e.eventSha256)
   throw Error('Administrative incident journal digest mismatch');
  prev=e.eventSha256;
 }
 return Object.freeze({
  eventCount:events.length,tailSha256:prev,incidentTriggerCount,
  closureClaimCount:closureClaims,
  selfConsistentDigestChain:true,
  providerSignatureVerified:false,
  independentReviewerIdentityVerified:false,
  productionReleaseAuthorized:false
 });
}
function holdFields(){
 return {
  phase:'1AV',basis:'UNAUTHENTICATED_ADMINISTRATIVE_CLAIMS',
  policyReviewInspected:false,priorJournalInspected:false,currentJournalInspected:false,
  journalEventCount:0,newEventCount:0,incidentTriggerCount:0,
  closureClaimCount:0,historyForkOrRollbackDetected:false,
  incidentQuarantineActive:false,incidentResponseRequired:false,
  selfConsistentDigestChain:false,independentSignedCheckpointVerified:false,
  providerSignatureVerified:false,independentReviewerIdentityVerified:false,
  trustAnchorChangeAuthorized:false,trustAnchorEnrollmentEnabled:false,
  authorizedCredentialsBound:false,authenticatedLiveRevocation:false,
  legallyVerifiedMcaAndSignatory:false,officialGrnVerified:false,
  stockPostingEnabled:false,supplierDispatchEnabled:false,
  financePostingEnabled:false,productionReleaseAuthorized:false,
  releaseDecision:'HOLD'
 };
}
/** Deliberately NO positive authorization path. Even a self-consistent,
 * 'reviewed', allegedly closed incident remains blocked pending genuine
 * separately authenticated provider, legal, security, and operations proof. */
export function assessPhase1AvAuthorityLifecycle({
 baselineJournal=null,currentJournal=null,baselinePolicy=null,
 currentPolicy=null,now=new Date()
}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('Invalid review clock');
 const initial=holdFields(),reasons=new Set(['EXTERNAL_PROVIDER_AND_SIGNER_AUTHORITY_MISSING']);
 const drift=assessPhase1AuPolicyDrift(baselinePolicy,currentPolicy,now);
 const elevate=drift.policyDriftDetected===true||
  drift.currentCpsReferenceMismatch||drift.incidentInventoryChanged||
  drift.evidenceReviewRollbackDetected||drift.expiredEvidenceCount>0||
  drift.revokedEvidenceCount>0||drift.unknownRevocationCount>0;
 if(elevate)reasons.add('POLICY_DRIFT_OR_EVIDENCE_REVIEW_INCIDENT');
 if(currentPolicy===null)reasons.add('NO_CURRENT_AUTHORITY_CLAIMS');
 if(baselinePolicy===null)reasons.add('NO_INDEPENDENT_POLICY_CHECKPOINT');
 const previous=baselineJournal===null?null:verifyPhase1AvClaimJournal(baselineJournal,now);
 const current=currentJournal===null?null:verifyPhase1AvClaimJournal(currentJournal,now);
 if(previous===null)reasons.add('NO_INDEPENDENT_JOURNAL_CHECKPOINT');
 if(current===null)reasons.add('NO_CURRENT_INCIDENT_JOURNAL');
 let fork=false,newEvents=0;
 if(previous&&current){
  if(current.eventCount<previous.eventCount){
   fork=true;reasons.add('INCIDENT_JOURNAL_HISTORY_ROLLBACK');
  }else{
   for(let i=0;i<previous.eventCount;i++){
    if(baselineJournal.events[i].eventSha256!==currentJournal.events[i].eventSha256){
     fork=true;reasons.add('INCIDENT_JOURNAL_FORK');
     break;
    }
   }
   if(!fork)newEvents=current.eventCount-previous.eventCount;
  }
 }else if(current)newEvents=current.eventCount;
 const incident=current?.incidentTriggerCount>0||previous?.incidentTriggerCount>0||false;
 if(incident)reasons.add('INCIDENT_QUARANTINE_REQUIRES_INDEPENDENT_RESPONSE');
 if(current?.closureClaimCount>0)
  reasons.add('INCIDENT_CLOSURE_CLAIM_IS_NOT_AUTHENTICATED_CLEARANCE');
 if(current?.eventCount>0&&!incident)reasons.add('JOURNAL_UNSUPPORTED_TRANSITION');
 const quarantined=!!(incident||fork||elevate);
 return Object.freeze({
  ...initial,policyReviewInspected:currentPolicy!==null,
  priorJournalInspected:previous!==null,currentJournalInspected:current!==null,
  journalEventCount:current?.eventCount??0,newEventCount:newEvents,
  incidentTriggerCount:current?.incidentTriggerCount??0,
  closureClaimCount:current?.closureClaimCount??0,
  historyForkOrRollbackDetected:fork,
  incidentQuarantineActive:quarantined,
  incidentResponseRequired:quarantined,
  selfConsistentDigestChain:current?.selfConsistentDigestChain??false,
  // Hash chaining can never establish a signed checkpoint.
  independentSignedCheckpointVerified:false,
  blockerCodes:Object.freeze([...reasons].sort()),
  responseRequirements:Object.freeze(quarantined?[
   'Keep supplier, warehouse, stock and financial actions disabled',
   'Out-of-band confirm affected provider, issuer and certificate scope',
   'Use approved vault/operator channels for independent credential suspension',
   'Reverify provider-issued signed CRL/OCSP and legal authority',
   'Capture an externally authenticated immutable checkpoint and incident approvals',
   'Require independent security, legal, operations and owner release reviews'
  ]:[])
 });
}
