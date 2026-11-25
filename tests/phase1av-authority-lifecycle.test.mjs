import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
 AUTHORITY_EVENT_TYPES,phase1AvEventSha256,verifyPhase1AvClaimJournal,
 assessPhase1AvAuthorityLifecycle
} from '../scripts/lib/phase1AvAuthorityLifecycle.mjs';
import {PROVIDER_CODE,REQUESTED_SCOPE,AUTHORITY_DIGEST_FIELDS,
 INDEPENDENT_REVIEW_DIGEST_FIELDS} from '../scripts/lib/providerAuthorityPreflight.mjs';
import {localIncidentInventorySha256,CCA_CPS_PUBLIC_REFERENCE,
 CCA_DISCLOSURE_URL,CCA_TRUST_DOMAIN
} from '../scripts/lib/phase1AuPolicyDrift.mjs';

const clock=new Date('2026-11-16T13:00:00.000Z');
const stamp=(n=0)=>new Date(clock.getTime()-3600000+n*60000).toISOString();
const digest=(n)=>n.toString(16).padStart(64,'0');
const reviewers=()=>[
 {role:'SECURITY',ref:'security-reviewer-001'},
 {role:'LEGAL',ref:'legal-reviewer-002'}
];
const journal=()=>({
 schemaVersion:1,providerCode:PROVIDER_CODE,requestedScope:REQUESTED_SCOPE,events:[]
});
function append(j,type,incidentRef='incident-2026-001',{
 actorRef='change-operator-001',anchorSha256=null,reviewers:refs=[],at=null,evidenceSha256=null
}={}){
 const last=j.events.at(-1);
 const entry={
  schemaVersion:1,sequence:j.events.length+1,at:at??stamp(j.events.length),
  type,incidentRef,actorRef,
  evidenceSha256:evidenceSha256??digest(400+j.events.length),
  anchorSha256,reviewers:refs,prevEventSha256:last?.eventSha256??null
 };
 j.events.push({...entry,eventSha256:phase1AvEventSha256(entry)});
 return j;
}
const assess=(base,current,extra={})=>assessPhase1AvAuthorityLifecycle({
 baselineJournal:base,currentJournal:current,now:clock,...extra
});
const assertHeld=(r)=>{
 for(const field of ['providerSignatureVerified','independentReviewerIdentityVerified',
 'independentSignedCheckpointVerified','trustAnchorChangeAuthorized',
 'trustAnchorEnrollmentEnabled','authenticatedLiveRevocation',
 'stockPostingEnabled','supplierDispatchEnabled','financePostingEnabled',
 'productionReleaseAuthorized','authorizedCredentialsBound']){
  assert.equal(r[field],false,field);
 }
 assert.equal(r.releaseDecision,'HOLD');
};

test('Phase 1AV no-input and empty self-hashed logs NEVER authorize release',()=>{
 const empty=assessPhase1AvAuthorityLifecycle({now:clock});
 assertHeld(empty);
 assert.equal(empty.currentJournalInspected,false);
 assert.ok(empty.blockerCodes.includes('NO_INDEPENDENT_JOURNAL_CHECKPOINT'));
 const log=journal(),check=verifyPhase1AvClaimJournal(log,clock);
 assert.equal(check.selfConsistentDigestChain,true);
 assert.equal(check.eventCount,0);
 assert.equal(check.providerSignatureVerified,false);
 const result=assess(log,log);
 assertHeld(result);
 assert.equal(result.incidentQuarantineActive,false);
 assert.equal(result.currentJournalInspected,true);
 assert.equal(result.selfConsistentDigestChain,true);
 assert.equal(result.independentSignedCheckpointVerified,false);
});

test('independently claimed review of a new trust anchor is NOT external PKIX enrollment',()=>{
 const j=append(journal(),'TRUST_ANCHOR_ROTATION_PROPOSED','incident-2026-001',{
  anchorSha256:digest(22),reviewers:reviewers()
 });
 const r=assess(null,j);
 assertHeld(r);
 assert.equal(r.incidentQuarantineActive,true);
 assert.equal(r.incidentResponseRequired,true);
 assert.equal(r.incidentTriggerCount,1);
 assert.equal(r.newEventCount,1);
 assert.ok(r.blockerCodes.includes('INCIDENT_QUARANTINE_REQUIRES_INDEPENDENT_RESPONSE'));
 assert.equal(r.responseRequirements.length,6);
 const second=append(structuredClone(j),'INCIDENT_CLOSURE_CLAIMED','incident-2026-001',{
  reviewers:reviewers()
 });
 const closed=assess(j,second);
 assertHeld(closed);
 assert.equal(closed.closureClaimCount,1);
 assert.equal(closed.incidentQuarantineActive,true);
 assert.equal(closed.historyForkOrRollbackDetected,false);
 assert.equal(closed.newEventCount,1);
 assert.ok(closed.blockerCodes.includes('INCIDENT_CLOSURE_CLAIM_IS_NOT_AUTHENTICATED_CLEARANCE'));
});

test('revocation, responder outage, provider withdrawal and key compromise are quarantine triggers',()=>{
 for(const type of [
  'TRUST_ANCHOR_COMPROMISE_SUSPECTED','REVOCATION_CONFIRMED_CLAIM',
  'REVOCATION_SOURCE_UNAVAILABLE','PROVIDER_ACCESS_WITHDRAWN_CLAIM',
  'EVIDENCE_REVIEW_EXPIRED'
 ]){
  const extra=type==='TRUST_ANCHOR_COMPROMISE_SUSPECTED'?
   {anchorSha256:digest(55)}:{};
  const log=append(journal(),type,'incident-2026-002',extra);
  const result=assess(journal(),log);
  assertHeld(result);
  assert.equal(result.incidentQuarantineActive,true);
  assert.equal(result.incidentResponseRequired,true);
  assert.equal(result.incidentTriggerCount,1);
 }
});

test('replay, rollback and fork are flagged even when both self-hash chains are valid',()=>{
 const base=append(journal(),'REVOCATION_SOURCE_UNAVAILABLE','incident-2026-001');
 const newer=append(structuredClone(base),'INCIDENT_ACKNOWLEDGED','incident-2026-001');
 const good=assess(base,newer);
 assert.equal(good.historyForkOrRollbackDetected,false);
 assert.equal(good.newEventCount,1);
 const rollback=assess(newer,base);
 assertHeld(rollback);
 assert.equal(rollback.historyForkOrRollbackDetected,true);
 assert.ok(rollback.blockerCodes.includes('INCIDENT_JOURNAL_HISTORY_ROLLBACK'));
 const changed=append(journal(),'PROVIDER_ACCESS_WITHDRAWN_CLAIM','incident-2026-001');
 const fork=assess(base,changed);
 assertHeld(fork);
 assert.equal(fork.historyForkOrRollbackDetected,true);
 assert.equal(fork.incidentQuarantineActive,true);
 assert.ok(fork.blockerCodes.includes('INCIDENT_JOURNAL_FORK'));
});

test('in-place modification, reordered events and invalid previous digest do not verify',()=>{
 const j=append(journal(),'REVOCATION_SOURCE_UNAVAILABLE','incident-2026-001');
 append(j,'INCIDENT_ACKNOWLEDGED','incident-2026-001');
 const edited=structuredClone(j);edited.events[0].evidenceSha256=digest(88);
 assert.throws(()=>verifyPhase1AvClaimJournal(edited,clock));
 const corrupt=structuredClone(j);corrupt.events[1].prevEventSha256=digest(44);
 assert.throws(()=>verifyPhase1AvClaimJournal(corrupt,clock));
 const reorder=structuredClone(j);reorder.events.reverse();
 assert.throws(()=>verifyPhase1AvClaimJournal(reorder,clock));
 const gap=structuredClone(j);gap.events[1].sequence=3;
 assert.throws(()=>verifyPhase1AvClaimJournal(gap,clock));
});

test('reviewer role collisions, single approval and forged clearance fields fail closed',()=>{
 const mistakes=[
  e=>{e.reviewers=[];},
  e=>{e.reviewers=[reviewers()[0]];},
  e=>{e.reviewers[1].role='SECURITY';},
  e=>{e.reviewers[1].ref=e.reviewers[0].ref;},
  e=>{e.actorRef=e.reviewers[0].ref;},
  e=>{e.providerApproved=true;},
  e=>{e.evidenceSha256='not-a-sha';},
  e=>{e.anchorSha256=null;},
  e=>{e.at='2026-11-16T25:00:00.000Z';},
  e=>{e.at='2026-11-16T16:00:00.000Z';},
  e=>{e.type='TRUST_ANCHOR_ACTIVATED';},
  e=>{e.sequence=0;}
 ];
 for(const mutate of mistakes){
  const j=append(journal(),'TRUST_ANCHOR_ROTATION_PROPOSED','incident-2026-001',{
   anchorSha256:digest(123),reviewers:reviewers()
  });
  mutate(j.events[0]);
  assert.throws(()=>verifyPhase1AvClaimJournal(j,clock));
 }
 const incorrect=append(journal(),'INCIDENT_ACKNOWLEDGED','incident-2026-001');
 assert.throws(()=>verifyPhase1AvClaimJournal(incorrect,clock));
 const bareClosure=append(journal(),'INCIDENT_CLOSURE_CLAIMED','incident-2026-001',{
  reviewers:reviewers()
 });
 assert.throws(()=>verifyPhase1AvClaimJournal(bareClosure,clock));
});

test('duplicate incident transitions, repeated proposed anchor, wrong provider/scope and oversized logs fail',()=>{
 const repeated=append(journal(),'REVOCATION_SOURCE_UNAVAILABLE','incident-2026-001');
 append(repeated,'REVOCATION_SOURCE_UNAVAILABLE','incident-2026-001');
 assert.throws(()=>verifyPhase1AvClaimJournal(repeated,clock));
 const roots=append(journal(),'TRUST_ANCHOR_ROTATION_PROPOSED','incident-2026-001',{
  anchorSha256:digest(23),reviewers:reviewers()
 });
 append(roots,'TRUST_ANCHOR_ROTATION_PROPOSED','incident-2026-002',{
  anchorSha256:digest(23),reviewers:reviewers()
 });
 assert.throws(()=>verifyPhase1AvClaimJournal(roots,clock));
 for(const mutate of [
  j=>{j.requestedScope='PRODUCTION_STOCK';},
  j=>{j.providerCode='UNKNOWN_CA';},
  j=>{j.apiToken='SECRET';},
  j=>{j.schemaVersion=2;},
  j=>{j.events='invalid';},
  j=>{j.events=new Array(65).fill(null);}
 ]){
  const j=journal();mutate(j);
  assert.throws(()=>verifyPhase1AvClaimJournal(j,clock));
 }
});

function claims(nowMs){
 let i=1;const next=()=>digest(i++);
 const artifactDigests=Object.fromEntries(AUTHORITY_DIGEST_FIELDS.map(k=>[k,next()]));
 const reviewDigests=Object.fromEntries(INDEPENDENT_REVIEW_DIGEST_FIELDS.map(k=>[k,next()]));
 const recordedAt=new Date(nowMs-20*60_000).toISOString();
 const windows=Object.fromEntries([...AUTHORITY_DIGEST_FIELDS,
  ...INDEPENDENT_REVIEW_DIGEST_FIELDS].map(kind=>[
  kind,{
   capturedAt:new Date(nowMs-25*60_000).toISOString(),
   refreshBy:new Date(nowMs+(kind==='authenticatedOcspSnapshotSha256'?20:600)*60_000).toISOString(),
   revocationState:'CLAIMED_NOT_REVOKED',revokedAt:null
  }
 ]));
 return {
  schemaVersion:1,providerCode:PROVIDER_CODE,requestedScope:REQUESTED_SCOPE,
  sequence:2,recordedAt,
  policy:{
   ccaCpsVersion:CCA_CPS_PUBLIC_REFERENCE,ccaDisclosureUrl:CCA_DISCLOSURE_URL,
   trustDomain:CCA_TRUST_DOMAIN,incidentDenylistSha256:localIncidentInventorySha256()
  },artifactDigests,reviewDigests,windows
 };
}
test('independent Phase 1AU policy drift and claimed CRL/OCSP expiry trigger incident governance',()=>{
 const now=clock.getTime(),original=claims(now),changed=structuredClone(original);
 changed.sequence=3;
 changed.policy.ccaCpsVersion='4.2.0';
 changed.windows.authenticatedOcspSnapshotSha256.refreshBy=new Date(now-60_000).toISOString();
 const r=assess(journal(),journal(),{
  baselinePolicy:original,currentPolicy:changed
 });
 assertHeld(r);
 assert.equal(r.incidentQuarantineActive,true);
 assert.equal(r.incidentResponseRequired,true);
 assert.ok(r.blockerCodes.includes('POLICY_DRIFT_OR_EVIDENCE_REVIEW_INCIDENT'));
 // Consistent synthetic policy data still cannot satisfy authority.
 const clean=claims(now);clean.sequence=3;
 const quiet=assess(journal(),journal(),{
  baselinePolicy:original,currentPolicy:clean
 });
 assertHeld(quiet);
});

test('CI CLI is no-network, accepts only --ci-hold and never enables production',()=>{
 const root=fileURLToPath(new URL('../',import.meta.url));
 const cli=fileURLToPath(new URL('../scripts/phase1av-incident-preflight.mjs',import.meta.url));
 const run=(args)=>spawnSync(process.execPath,[cli,...args],{
  cwd:root,env:{...process.env,CI:'true',GITHUB_ACTIONS:'true',NODE_ENV:'production'},
  encoding:'utf8',timeout:8000,maxBuffer:32_768
 });
 const valid=run(['--ci-hold']);
 assert.equal(valid.status,0,valid.stderr);
 const status=JSON.parse(valid.stdout);
 assertHeld(status);
 assert.equal(status.currentJournalInspected,false);
 for(const args of [[],['--approve'],['--offline-journal','/tmp/proof'],
  ['--ci-hold','--approve']]){
  const denied=run(args);
  assert.equal(denied.status,2);
  assert.equal(denied.stdout,'');
  assert.match(denied.stderr,/HOLD/);
  assert.ok(!denied.stderr.includes('/tmp/proof'));
 }
 assert.equal(AUTHORITY_EVENT_TYPES.length,8);
});
