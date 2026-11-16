import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
 CHECKPOINT_PURPOSE,phase1AwCheckpointSigningBytes,
 phase1AwCheckpointReceiptSha256,phase1AwPolicyClaimsSha256,
 phase1AwRecoveryClaimSha256,
 assessPhase1AwCheckpointRecovery
} from '../scripts/lib/phase1AwSignedCheckpoint.mjs';
import {
 phase1AvEventSha256,verifyPhase1AvClaimJournal
} from '../scripts/lib/phase1AvAuthorityLifecycle.mjs';
import {
 PROVIDER_CODE,REQUESTED_SCOPE,AUTHORITY_DIGEST_FIELDS,
 INDEPENDENT_REVIEW_DIGEST_FIELDS
} from '../scripts/lib/providerAuthorityPreflight.mjs';
import {
 CCA_DISCLOSURE_URL,CCA_CPS_PUBLIC_REFERENCE,CCA_TRUST_DOMAIN,
 localIncidentInventorySha256
} from '../scripts/lib/phase1AuPolicyDrift.mjs';

const now=new Date('2026-11-16T14:00:00.000Z');
const T=now.getTime();
const at=(minutes)=>new Date(T+minutes*60000).toISOString();
const sha=(i)=>i.toString(16).padStart(64,'0');
function makeKeys(){
 const signers=[
  {role:'LEGAL',reviewerRef:'legal-reviewer-001',keyId:'legal-key-001'},
  {role:'SECURITY',reviewerRef:'security-reviewer-002',keyId:'security-key-002'}
 ];
 const privateKeys=[],pins=[];
 for(const s of signers){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const spki=publicKey.export({format:'der',type:'spki'});
  pins.push({...s,
   publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
   publicKeySha256:createHash('sha256').update(spki).digest('hex')
  });
  privateKeys.push(privateKey);
 }
 return {signers,privateKeys,pins};
}
function policy(sequence=1){
 let i=1;
 const artifactDigests=Object.fromEntries(AUTHORITY_DIGEST_FIELDS.map(k=>[k,sha(i++)]));
 const reviewDigests=Object.fromEntries(INDEPENDENT_REVIEW_DIGEST_FIELDS.map(k=>[k,sha(i++)]));
 const windows=Object.fromEntries([...AUTHORITY_DIGEST_FIELDS,
  ...INDEPENDENT_REVIEW_DIGEST_FIELDS].map(kind=>{
  const refresh=kind==='authenticatedOcspSnapshotSha256'?20:
   kind==='authenticatedCrlSnapshotSha256'?45:360;
  return [kind,{capturedAt:at(-40),refreshBy:at(refresh),
   revokedAt:null,revocationState:'CLAIMED_NOT_REVOKED'}];
 }));
 return {
  schemaVersion:1,providerCode:PROVIDER_CODE,requestedScope:REQUESTED_SCOPE,
  sequence,recordedAt:at(-30),
  policy:{ccaCpsVersion:CCA_CPS_PUBLIC_REFERENCE,
   ccaDisclosureUrl:CCA_DISCLOSURE_URL,trustDomain:CCA_TRUST_DOMAIN,
   incidentDenylistSha256:localIncidentInventorySha256()},
  artifactDigests,reviewDigests,windows
 };
}
function journal(){
 return {schemaVersion:1,providerCode:PROVIDER_CODE,
  requestedScope:REQUESTED_SCOPE,events:[]};
}
function append(j,type,incident='incident-2026-001',minute=-50){
 const last=j.events.at(-1);
 const e={
  schemaVersion:1,sequence:j.events.length+1,at:at(minute),type,
  incidentRef:incident,actorRef:'incident-operator-001',
  evidenceSha256:sha(100+j.events.length),anchorSha256:null,reviewers:[],
  prevEventSha256:last?.eventSha256??null
 };
 j.events.push({...e,eventSha256:phase1AvEventSha256(e)});
 return j;
}
function checkpoint({sequence=1,issued=-20,expires=20,prior=null,
 journalValue=journal(),policyValue=policy(),keys,recoveryClaimSha256=null}){
 const summary=verifyPhase1AvClaimJournal(journalValue,now);
 const body={
  schemaVersion:1,purpose:CHECKPOINT_PURPOSE,providerCode:PROVIDER_CODE,
  requestedScope:REQUESTED_SCOPE,sequence,issuedAt:at(issued),
  expiresAt:at(expires),priorCheckpointSha256:prior,
  journalEventCount:summary.eventCount,journalTailSha256:summary.tailSha256,
  policySnapshotSha256:phase1AwPolicyClaimsSha256(policyValue,now),
  recoveryClaimSha256,releaseDecision:'HOLD'
 };
 const message=phase1AwCheckpointSigningBytes(body);
 const signatures=keys.signers.map((s,i)=>({
  ...s,signatureBase64:sign(null,message,keys.privateKeys[i]).toString('base64')
 }));
 return {...body,signatures};
}
function fixture(){
 const keys=makeKeys();
 const firstJournal=append(journal(),'REVOCATION_SOURCE_UNAVAILABLE');
 const secondJournal=structuredClone(firstJournal);
 append(secondJournal,'INCIDENT_ACKNOWLEDGED','incident-2026-001',-45);
 const firstPolicy=policy(1),secondPolicy=policy(2);
 const first=checkpoint({sequence:1,journalValue:firstJournal,
  policyValue:firstPolicy,keys});
 const second=checkpoint({sequence:2,issued:-10,expires:30,
  prior:phase1AwCheckpointReceiptSha256(first),
  journalValue:secondJournal,policyValue:secondPolicy,keys});
 return {
  keys,firstJournal,secondJournal,firstPolicy,secondPolicy,first,second
 };
}
function inspect(f,overrides={}){
 return assessPhase1AwCheckpointRecovery({
  priorJournal:f.firstJournal,currentJournal:f.secondJournal,
  priorPolicy:f.firstPolicy,currentPolicy:f.secondPolicy,
  priorCheckpoint:f.first,currentCheckpoint:f.second,
  reviewerKeyPins:f.keys.pins,now,...overrides
 });
}
function held(r){
 for(const field of [
  'independentlyAuthenticatedSignerKeys',
  'independentlyAuthenticatedLegalOrProviderAuthority',
  'authenticatedExternalTimestamp','immutableExternalStorageVerified',
  'authenticatedLiveCrlOcsp','trustAnchorEnrollmentEnabled',
  'credentialRotationExecuted','realRestoreWitnessed',
  'officialGrnVerified','stockPostingEnabled','supplierDispatchEnabled',
  'financePostingEnabled','productionReleaseAuthorized'
 ])assert.equal(r[field],false,field);
 assert.equal(r.releaseDecision,'HOLD');
}
function resigned(check,keys){
 const {signatures:ignored,...b}=check;
 const msg=phase1AwCheckpointSigningBytes(b);
 return {...b,signatures:keys.signers.map((s,i)=>({
  ...s,signatureBase64:sign(null,msg,keys.privateKeys[i]).toString('base64')
 }))};
}
test('Phase 1AW no-input preflight cannot inspect signatures or enable release',()=>{
 const r=assessPhase1AwCheckpointRecovery({now});
 held(r);
 assert.equal(r.currentCheckpointInspected,false);
 assert.equal(r.signatureChecksPassed,false);
 assert.ok(r.blockerCodes.includes('MISSING_OFFLINE_CHECKPOINT_OR_PINNED_REVIEWER_KEYS'));
});
test('valid synthetic Ed25519 LEGAL+SECURITY signatures bind journal and policy but NEVER authorize release',()=>{
 const f=fixture(),r=inspect(f);
 held(r);
 assert.equal(r.currentCheckpointInspected,true);
 assert.equal(r.priorCheckpointInspected,true);
 assert.equal(r.signatureChecksPassed,true);
 assert.equal(r.checkpointJournalBound,true);
 assert.equal(r.checkpointPolicyBound,true);
 assert.equal(r.priorCheckpointValid,true);
 assert.equal(r.checkpointExpired,false);
 assert.equal(r.checkpointRollbackOrForkDetected,false);
 assert.equal(r.incidentQuarantineActive,true);
 assert.equal(r.incidentResponseRequired,true);
 assert.equal(r.selfConsistentDigestChain,undefined);
 assert.equal(r.recoveryClaimInspected,false);
 assert.ok(r.blockerCodes.includes('EXTERNAL_INCIDENT_QUARANTINE'));
});
test('signature corruption, public-key substitution and signature replay cannot pass cryptography',()=>{
 const f=fixture();
 const bad=structuredClone(f.second);
 const bytes=Buffer.from(bad.signatures[0].signatureBase64,'base64');
 bytes[10]^=1;
 bad.signatures[0].signatureBase64=bytes.toString('base64');
 const result=inspect(f,{currentCheckpoint:bad});
 held(result);
 assert.equal(result.signatureChecksPassed,false);
 assert.equal(result.incidentResponseRequired,true);
 assert.ok(result.blockerCodes.includes('DETACHED_CHECKPOINT_SIGNATURE_INVALID'));
 const keySwap=makeKeys();
 const wrong=inspect(f,{reviewerKeyPins:keySwap.pins});
 assert.equal(wrong.signatureChecksPassed,false);
 held(wrong);
 const duplicated=structuredClone(f.second);
 duplicated.signatures[1].signatureBase64=duplicated.signatures[0].signatureBase64;
 const invalid=inspect(f,{currentCheckpoint:duplicated});
 assert.equal(invalid.signatureChecksPassed,false);
 held(invalid);
});
test('changed snapshot/journal without new valid signatures cannot pass binding',()=>{
 const f=fixture();
 const changedPolicy=structuredClone(f.secondPolicy);
 changedPolicy.policy.ccaCpsVersion='4.2.0';
 const p=inspect(f,{currentPolicy:changedPolicy});
 held(p);
 assert.equal(p.checkpointPolicyBound,false);
 assert.ok(p.blockerCodes.includes('CHECKPOINT_POLICY_CLAIMS_MISMATCH'));
 const changedJournal=append(structuredClone(f.secondJournal),
  'REVOCATION_CONFIRMED_CLAIM','incident-2026-002',-40);
 const j=inspect(f,{currentJournal:changedJournal});
 held(j);
 assert.equal(j.checkpointJournalBound,false);
 assert.ok(j.blockerCodes.includes('CHECKPOINT_JOURNAL_MISMATCH'));
});
test('re-signed forged predecessor hash, sequence rollback and chronology violations flag fork',()=>{
 const f=fixture();
 const wrongRef=resigned({...f.second,priorCheckpointSha256:sha(123456)},f.keys);
 let r=inspect(f,{currentCheckpoint:wrongRef});
 held(r);assert.equal(r.signatureChecksPassed,true);
 assert.equal(r.checkpointRollbackOrForkDetected,true);
 assert.ok(r.blockerCodes.includes('CHECKPOINT_ROLLBACK_OR_FORK'));
 const replay=resigned({...f.second,sequence:1,priorCheckpointSha256:null},f.keys);
 r=inspect(f,{currentCheckpoint:replay});
 assert.equal(r.checkpointRollbackOrForkDetected,true);
 held(r);
 const oldTime=resigned({...f.second,issuedAt:at(-25),expiresAt:at(5)},f.keys);
 r=inspect(f,{currentCheckpoint:oldTime});
 assert.equal(r.checkpointRollbackOrForkDetected,true);
 held(r);
});
test('missing predecessor and validly re-signed checkpoint freshness gaps always quarantine',()=>{
 const f=fixture();
 const missing=inspect(f,{priorCheckpoint:null});
 held(missing);
 assert.equal(missing.checkpointRollbackOrForkDetected,true);
 assert.ok(missing.blockerCodes.includes('MISSING_EXPECTED_SIGNED_PREDECESSOR'));
 const oldReceipt=resigned({...f.first,expiresAt:at(-15)},f.keys);
 const resumed=resigned({
  ...f.second,priorCheckpointSha256:phase1AwCheckpointReceiptSha256(oldReceipt)
 },f.keys);
 const broken=inspect(f,{
  priorCheckpoint:oldReceipt,currentCheckpoint:resumed
 });
 held(broken);
 assert.equal(broken.signatureChecksPassed,true);
 assert.equal(broken.priorCheckpointValid,true);
 assert.equal(broken.checkpointRollbackOrForkDetected,true);
 assert.ok(broken.blockerCodes.includes('SIGNED_CHECKPOINT_CONTINUITY_GAP'));
 assert.equal(broken.incidentResponseRequired,true);
});
test('expired mathematically valid checkpoint is quarantined and never a release',()=>{
 const f=fixture();
 const expired=resigned({...f.second,issuedAt:at(-10),expiresAt:at(0)},f.keys);
 const r=inspect(f,{currentCheckpoint:expired});
 assert.equal(r.signatureChecksPassed,true);
 assert.equal(r.checkpointExpired,true);
 assert.equal(r.incidentResponseRequired,true);
 assert.ok(r.blockerCodes.includes('CHECKPOINT_EXPIRED'));
 held(r);
});
test('reject mismatched key pins, RSA/private key material and untrusted signer metadata',()=>{
 const f=fixture();
 const corrupt=structuredClone(f.keys.pins);
 corrupt[0].publicKeySha256=sha(33);
 assert.throws(()=>inspect(f,{reviewerKeyPins:corrupt}));
 const {privateKey}=generateKeyPairSync('ed25519');
 const keyLeak=structuredClone(f.keys.pins);
 keyLeak[0].publicKeyPem=privateKey.export({format:'pem',type:'pkcs8'});
 assert.throws(()=>inspect(f,{reviewerKeyPins:keyLeak}));
 const rsa=generateKeyPairSync('rsa',{modulusLength:2048}).publicKey;
 const replaced=structuredClone(f.keys.pins);
 replaced[0].publicKeyPem=rsa.export({format:'pem',type:'spki'});
 replaced[0].publicKeySha256=createHash('sha256')
  .update(rsa.export({format:'der',type:'spki'})).digest('hex');
 assert.throws(()=>inspect(f,{reviewerKeyPins:replaced}));
 const inflated=structuredClone(f.second);
 inflated.signatures[0].providerApproved=true;
 assert.throws(()=>inspect(f,{currentCheckpoint:inflated}));
 const selfReview=structuredClone(f.second);
 selfReview.signatures[1].reviewerRef=selfReview.signatures[0].reviewerRef;
 assert.throws(()=>inspect(f,{currentCheckpoint:selfReview}));
});
test('strict schema rejects unapproved release flags, missing journals, corrupt times and invalid signatures',()=>{
 const f=fixture();
 for(const mutate of [
  s=>{s.releaseDecision='GO';},
  s=>{s.productionReleaseAuthorized=true;},
  s=>{s.purpose='PROVIDER_SIGNING_AUTHORITY';},
  s=>{s.requestedScope='REAL_STOCK_POSTING';},
  s=>{s.signatures[0].signatureBase64='invalid';},
  s=>{s.journalTailSha256='invalid';},
  s=>{s.expiresAt=s.issuedAt;},
  s=>{s.expiresAt=at(30*60);},
  s=>{s.issuedAt='2026-11-16T25:00:00.000Z';},
  s=>{s.priorCheckpointSha256=null;}
 ]){
  const copy=structuredClone(f.second);
  mutate(copy);
  assert.throws(()=>inspect(f,{currentCheckpoint:copy}));
 }
 assert.throws(()=>inspect(f,{priorJournal:null}));
 assert.throws(()=>inspect(f,{priorPolicy:null}));
 const beforePolicy=resigned({...f.second,issuedAt:at(-35),expiresAt:at(5)},f.keys);
 assert.throws(()=>inspect(f,{currentCheckpoint:beforePolicy}));
 assert.throws(()=>assessPhase1AwCheckpointRecovery({now:null}));
});
test('even complete synthetic incident recovery claims remain held and cannot verify real restore',()=>{
 const f=fixture();
 const recovery={
  schemaVersion:1,incidentRef:'incident-2026-001',recordedAt:at(-15),
  isolatedRestoreClaimSha256:sha(321),
  mfaRecoveryClaimSha256:sha(322),
  networkIsolationClaimSha256:sha(323),
  revocationRecheckClaimSha256:sha(324),
  reviewers:[
   {role:'SECURITY',reviewerRef:'security-recovery-003'},
   {role:'OPERATIONS',reviewerRef:'operations-recovery-004'},
   {role:'OWNER',reviewerRef:'owner-recovery-005'}
  ],outboundDispatchHeld:true,releaseDecision:'HOLD'
 };
 const signed=resigned({...f.second,recoveryClaimSha256:phase1AwRecoveryClaimSha256(recovery)},f.keys);
 const report=inspect(f,{recovery,currentCheckpoint:signed});
 assert.equal(report.recoveryClaimInspected,true);
 assert.equal(report.recoveryClaimSchemaComplete,true);
 assert.equal(report.realRestoreWitnessed,false);
 assert.equal(report.incidentQuarantineActive,true);
 assert.ok(report.blockerCodes.includes('RECOVERY_CLAIMS_NOT_EXTERNALLY_WITNESSED'));
 assert.ok(!report.blockerCodes.includes('RECOVERY_CLAIM_NOT_SIGNED_IN_CHECKPOINT'));
 held(report);
 const detached=inspect(f,{recovery});
 assert.ok(detached.blockerCodes.includes('RECOVERY_CLAIM_NOT_SIGNED_IN_CHECKPOINT'));
 assert.equal(detached.incidentQuarantineActive,true);
 held(detached);
 const withheld=inspect(f,{currentCheckpoint:signed});
 assert.ok(withheld.blockerCodes.includes('SIGNED_RECOVERY_CLAIM_MISSING'));
 held(withheld);
 const swapped=structuredClone(recovery);
 swapped.isolatedRestoreClaimSha256=sha(999);
 const swappedReport=inspect(f,{currentCheckpoint:signed,recovery:swapped});
 assert.ok(swappedReport.blockerCodes.includes('RECOVERY_CLAIM_NOT_SIGNED_IN_CHECKPOINT'));
 held(swappedReport);
 for(const change of [
  r=>{r.reviewers[1].reviewerRef=r.reviewers[0].reviewerRef;},
  r=>{r.reviewers[0].role='LEGAL';},
  r=>{r.reviewers[2].reviewerRef='incident-operator-001';},
  r=>{r.incidentRef='incident-unrelated-002';},
  r=>{r.outboundDispatchHeld=false;},
  r=>{r.releaseDecision='GO';},
  r=>{r.vaultToken='SECRET';},
  r=>{r.recordedAt=at(-55);}
 ]){
  const modified=structuredClone(recovery);change(modified);
  assert.throws(()=>inspect(f,{recovery:modified,currentCheckpoint:signed}));
 }
});
test('public policy key sorting is stable, but never an external signed policy',()=>{
 const snapshot=policy();
 const swapped=Object.fromEntries(Object.entries(snapshot).reverse());
 const a=phase1AwPolicyClaimsSha256(snapshot,now);
 const b=phase1AwPolicyClaimsSha256(swapped,now);
 assert.equal(a,b);
 assert.match(a,/^[a-f0-9]{64}$/);
});
test('Phase 1AW CI CLI refuses all modes except zero-input HOLD',()=>{
 const path=fileURLToPath(new URL('../scripts/phase1aw-checkpoint-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[path,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{...process.env,CI:'true',GITHUB_ACTIONS:'true',NODE_ENV:'production'},
  encoding:'utf8',timeout:8000,maxBuffer:32_768
 });
 const good=run(['--ci-hold']);
 assert.equal(good.status,0,good.stderr);
 held(JSON.parse(good.stdout));
 for(const args of [[],['--approve'],['--file','/tmp/private'],
  ['--ci-hold','--trust']]){
  const bad=run(args);
  assert.equal(bad.status,2);
  assert.equal(bad.stdout,'');
  assert.match(bad.stderr,/HOLD/);
  assert.ok(!bad.stderr.includes('/tmp/private'));
 }
});
