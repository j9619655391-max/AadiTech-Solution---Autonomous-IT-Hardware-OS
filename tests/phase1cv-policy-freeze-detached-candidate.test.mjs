import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 DOMAIN,ROLES,canonical,candidateSigningBytes,
 assessGovernanceFingerprint,assessDetachedCandidate,
 verifyLiveDetachedCandidate
} from '../scripts/phase1cv-policy-freeze-detached-candidate.mjs';
import {REPO} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40);
const NOW='2026-11-19T12:00:00.000Z';
const sha256=s=>createHash('sha256').update(s).digest('hex');
function fileRecord(content='* @security-operator @business-operator\n'){
 const bytes=Buffer.from(content,'utf8');
 const sha=createHash('sha1').update(
  Buffer.concat([Buffer.from('blob '+bytes.length+'\0'),bytes])).digest('hex');
 return {status:'read',data:{
  path:'.github/CODEOWNERS',type:'file',encoding:'base64',
  content:bytes.toString('base64'),size:bytes.length,sha
 }};
}
function source(){
 const details={id:77,name:'AadiTech main protected two-person review - PROPOSED NOT INSTALLED',
  target:'branch',enforcement:'active',bypass_actors:[],
  conditions:{ref_name:{include:['refs/heads/main'],exclude:[]}},
  rules:[
   {type:'deletion'},{type:'non_fast_forward'},
   {type:'pull_request',parameters:{
    required_approving_review_count:2,require_code_owner_review:true,
    dismiss_stale_reviews_on_push:true,require_last_push_approval:true
   }},
   {type:'required_status_checks',parameters:{
    required_status_checks:[{context:'baseline',integration_id:15368}]
   }}
  ]};
 return {
  handoff:{
   phase:'1CU',
   kind:'OPERATOR_ONLY_CROSS_SOURCE_REVIEWER_MAIN_PROTECTION_HANDOFF_HOLD',
   technicalGovernanceHandoffPreconditionsObserved:true,
   actualMainBaseStableAcrossAllSources:true,
   exactHeadPushAndPrTechnicalCiReceiptsMatched:true,
   distinctNominatedLatestHeadTechnicalGithubApprovalsMatched:true,
   exactActiveMainRulesAndNoBypassFieldsObservable:true,
   installedMainCodeownersExactNominatedBytesMatched:true,
   currentDevHeadSha:HEAD,verifiedMainBaseSha:BASE,
   pushRunId:123456,prRunId:123457,
   localUnsignedObservationSha256:'c'.repeat(64),
   productionReleaseAuthorized:false,productionReleaseBlocked:true,
   releaseDecision:'HOLD'
  },
  rulesets:{
   listStatus:'read',listingComplete:true,
   listed:[{id:77,name:details.name,target:'branch',enforcement:'active'}],
   details:{'77':details},detailStatus:{'77':'read'}
  },codeowners:fileRecord()
 };
}
function packet(){
 const snapshot=assessGovernanceFingerprint(source());
 const keys={};const signatures=[];
 const statement={
  schemaVersion:1,kind:'CANDIDATE_OFFREPO_POLICY_FREEZE',
  repository:REPO,sourceHeadSha:HEAD,mainBaseSha:BASE,
  pushRunId:123456,prRunId:123457,
  policyFingerprintSha256:snapshot.policyFingerprintSha256,
  nonce:'d'.repeat(64),epoch:43,previousDigest:'e'.repeat(64),
  issuedAt:'2026-11-19T11:58:00.000Z',
  expiresAt:'2026-11-19T12:05:00.000Z',
  releaseDecision:'HOLD'
 };
 for(const role of ROLES){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'}).toString();
  const spkiSha256=sha256(publicKey.export({type:'spki',format:'der'}));
  const keyId=role==='SECURITY_WITNESS'?'security-witness-v1':'business-witness-v1';
  keys[role]={keyId,publicKeyPem,spkiSha256,
   validFrom:'2026-11-18T00:00:00.000Z',
   validUntil:'2026-11-20T00:00:00.000Z',revoked:false};
  signatures.push({role,keyId,algorithm:'Ed25519',
   signature:sign(null,candidateSigningBytes(statement),privateKey).toString('base64')});
 }
 return {
  before:snapshot,after:assessGovernanceFingerprint(structuredClone(source())),
  statement,signatures,registry:keys,
  checkpoint:{epoch:42,lastDigest:'e'.repeat(64),
   observedAt:'2026-11-19T11:50:00.000Z'},now:NOW
 };
}
const check=f=>assessDetachedCandidate(f);
function denied(edit,code){
 const f=packet();edit(f);
 const r=check(f);
 assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes(code),
  'wanted '+code+', got '+r.anomalyCodes.join('|'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('CV: two locally valid Ed25519 detached role signatures yield mathematical candidate only',()=>{
 const r=check(packet());
 assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.verifiedCandidateSignatureCount,2);
 assert.match(r.policyFingerprintSha256,/^[a-f0-9]{64}$/);
 assert.match(r.detachedCandidateSha256,/^[a-f0-9]{64}$/);
 for(const k of [
  'callerSuppliedKeyEnrollmentIndependentlyAuthenticated',
  'legalSecurityBusinessRolesIndependentlyAuthenticated',
  'externallyDurableHighWatermarkAndAtomicCASVerified',
  'independentCrossRunAntiEquivocationWitnessVerified',
  'remotelyRetrievedOffrepoBytesAndTrustedTlsIdentityVerified',
  'githubOidcSlsaAttestationOrWormObjectLockVerified',
  'liveProviderMcaAndExternalStagingAcceptanceVerified',
  'productionReleaseAuthorized'
 ])assert.equal(r[k],false,k);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CV: canonical signed payload is stable across property insertion order and domain-separated',()=>{
 assert.equal(canonical({z:3,a:[true,null,'hi']}),
  '{"a":[true,null,"hi"],"z":3}');
 assert.equal(candidateSigningBytes({z:3,a:1}).toString(),
  DOMAIN+'{"a":1,"z":3}');
 assert.throws(()=>canonical({x:NaN}),/CV_UNSUPPORTED_CANONICAL/);
 assert.throws(()=>canonical({x:2.1}),/CV_UNSUPPORTED_CANONICAL/);
 assert.throws(()=>candidateSigningBytes({x:'x'.repeat(9000)}),
  /CV_UNTRUSTED_OR_OVERSIZE/);
});
test('CV: read-only exact main policy fingerprints accept separate identical observations',()=>{
 const a=assessGovernanceFingerprint(source()),b=assessGovernanceFingerprint(source());
 assert.equal(a.technicalSnapshotConsistent,true);
 assert.equal(a.policyFingerprintSha256,b.policyFingerprintSha256);
 assert.equal(a.productionReleaseAuthorized,false);
 assert.equal(a.currentHeadSha,HEAD);
 assert.equal(a.mainBaseSha,BASE);
});
test('CV: changed source SHA, main base or exact CI run IDs is a TOCTOU HOLD',()=>{
 for(const edit of [
  f=>{f.after.currentHeadSha='f'.repeat(40)},
  f=>{f.after.mainBaseSha='f'.repeat(40)},
  f=>{f.after.pushRunId++},
  f=>{f.after.prRunId++},
  f=>{f.after.policyFingerprintSha256='f'.repeat(64)}
 ])denied(edit,'CV_TOCTOU_RULESET_CODEOWNERS_REVIEW_OR_SOURCE_DRIFT');
});
test('CV: actual ruleset ID swap or parameter changes alter frozen digest',()=>{
 for(const edit of [
  s=>{s.rulesets.details['77'].rules[2].parameters.required_approving_review_count=1},
  s=>{s.rulesets.details['77'].rules[3].parameters.required_status_checks[0].integration_id=0},
  s=>{s.rulesets.details['77'].name='drift';s.rulesets.listed[0].name='drift'},
  s=>{s.rulesets.details['77'].id=78;s.rulesets.listed[0].id=78;
   s.rulesets.details['78']=s.rulesets.details['77'];delete s.rulesets.details['77'];
   s.rulesets.detailStatus['78']='read';delete s.rulesets.detailStatus['77'];}
 ]){
  const s=source(),pre=assessGovernanceFingerprint(s);
  edit(s);
  const post=assessGovernanceFingerprint(s);
  assert.notEqual(pre.policyFingerprintSha256,post.policyFingerprintSha256);
 }
});
test('CV: modified main CODEOWNERS content while same source SHA causes digest mismatch',()=>{
 const s=source(),pre=assessGovernanceFingerprint(s);
 s.codeowners=fileRecord('* @other-person\n');
 const post=assessGovernanceFingerprint(s);
 assert.equal(post.technicalSnapshotConsistent,true);
 assert.notEqual(pre.policyFingerprintSha256,post.policyFingerprintSha256);
});
test('CV: hidden bypass actors, unauthorized bypass and incomplete rule inventory deny snapshot',()=>{
 for(const edit of [
  s=>{delete s.rulesets.details['77'].bypass_actors},
  s=>{s.rulesets.details['77'].bypass_actors=[{actor_id:3}]},
  s=>{s.rulesets.listStatus='access_denied'},
  s=>{s.rulesets.listingComplete=false},
  s=>{s.rulesets.detailStatus['77']='access_denied'},
  s=>{s.rulesets.details['77'].id=999},
  s=>{s.rulesets.listed.push(s.rulesets.listed[0])}
 ]){
  const s=source();edit(s);
  assert.equal(assessGovernanceFingerprint(s).technicalSnapshotConsistent,false);
 }
});
test('CV: fake CODEOWNERS bytes, wrong Git blob hash and missing base file deny snapshot',()=>{
 for(const edit of [
  s=>{s.codeowners.status='not_found_or_hidden'},
  s=>{s.codeowners.data.sha='f'.repeat(40)},
  s=>{s.codeowners.data.size+=2},
  s=>{s.codeowners.data.content='YQ=='},
  s=>{s.codeowners.data.path='CODEOWNERS'},
  s=>{s.codeowners.data.type='symlink'}
 ]){
  const s=source();edit(s);
  const r=assessGovernanceFingerprint(s);
  assert.equal(r.technicalSnapshotConsistent,false);
  assert.equal(r.policyFingerprintSha256,null);
 }
});
test('CV: fake or missing prior 1CU technical approvals never accepted as policy',()=>{
 for(const edit of [
  s=>{s.handoff.technicalGovernanceHandoffPreconditionsObserved=false},
  s=>{s.handoff.exactActiveMainRulesAndNoBypassFieldsObservable=false},
  s=>{s.handoff.installedMainCodeownersExactNominatedBytesMatched=false},
  s=>{s.handoff.distinctNominatedLatestHeadTechnicalGithubApprovalsMatched=false},
  s=>{s.handoff.verifiedMainBaseSha=null},
  s=>{s.handoff.productionReleaseAuthorized=true},
  s=>{s.handoff.releaseDecision='GO'}
 ]){
  const s=source();edit(s);
  assert.equal(assessGovernanceFingerprint(s).technicalSnapshotConsistent,false);
 }
});
test('CV: detached statement source, base, run, policy and nonce substitutions denied',()=>{
 for(const edit of [
  f=>{f.statement.sourceHeadSha='f'.repeat(40)},
  f=>{f.statement.mainBaseSha='f'.repeat(40)},
  f=>{f.statement.pushRunId++},
  f=>{f.statement.prRunId++},
  f=>{f.statement.policyFingerprintSha256='f'.repeat(64)},
  f=>{f.statement.nonce='0'.repeat(64)}
 ]){
  const r=check((()=>{const f=packet();edit(f);return f})());
  assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CV: replayed, rolled-back and skipped prior monotonic epoch rejected',()=>{
 for(const edit of [
  f=>{f.statement.epoch=42},
  f=>{f.statement.epoch=44},
  f=>{f.statement.previousDigest='f'.repeat(64)},
  f=>{f.checkpoint.epoch=43},
  f=>{f.checkpoint.lastDigest='0'.repeat(64)}
 ])denied(edit,'CV_REPLAY_ROLLBACK_GAP_OR_UNANCHORED_EPOCH');
});
test('CV: expired, future, noncanonical and backwards-clock signatures denied',()=>{
 for(const edit of [
  f=>{f.now='2026-11-19T12:06:00.000Z'},
  f=>{f.statement.expiresAt='2026-11-19T13:00:00.000Z'},
  f=>{f.statement.issuedAt='2026-11-19T13:00:00.000Z'},
  f=>{f.checkpoint.observedAt='2026-11-19T11:59:00.000Z'},
  f=>{f.statement.issuedAt='not-a-time'}
 ])denied(edit,'CV_EXPIRED_FUTURE_OR_NONMONOTONIC_CANDIDATE_TIME');
});
test('CV: altered signature, claimed algorithm, key ID and malformed Ed25519 signature fail',()=>{
 for(const edit of [
  f=>{f.signatures[0].signature=f.signatures[1].signature},
  f=>{f.signatures[0].signature='a'.repeat(88)},
  f=>{f.signatures[0].algorithm='RSA-PSS'},
  f=>{f.signatures[0].keyId='fake-key-id'},
  f=>{f.registry.SECURITY_WITNESS.spkiSha256='a'.repeat(64)}
 ]){
  const r=check((()=>{const f=packet();edit(f);return f})());
  assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 }
});
test('CV: role duplication, missing second role and forged extra signer rejected',()=>{
 for(const edit of [
  f=>{f.signatures.pop()},
  f=>{f.signatures[1].role='SECURITY_WITNESS'},
  f=>{f.signatures.push(f.signatures[0])},
  f=>{delete f.registry.BUSINESS_WITNESS}
 ]){
  const r=check((()=>{const f=packet();edit(f);return f})());
  assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 }
});
test('CV: revoked, expired or not-yet-valid public keys cannot claim accepted signer',()=>{
 for(const edit of [
  f=>{f.registry.SECURITY_WITNESS.revoked=true},
  f=>{f.registry.SECURITY_WITNESS.validFrom='2026-11-20T00:00:00.000Z'},
  f=>{f.registry.SECURITY_WITNESS.validUntil='2026-11-19T11:59:00.000Z'},
  f=>{f.registry.SECURITY_WITNESS.keyId='fake'}
 ]){
  const r=check((()=>{const f=packet();edit(f);return f})());
  assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 }
});
test('CV: reuse of one SPKI across claimed security and business roles is rejected',()=>{
 const f=packet();
 f.registry.BUSINESS_WITNESS={...f.registry.SECURITY_WITNESS};
 f.signatures[1]={...f.signatures[0],role:'BUSINESS_WITNESS'};
 const r=check(f);
 assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes('CV_SIGNER_KEY_REUSE_OR_ROLE_COLLUSION'));
});
test('CV: malformed claim fields, unknown decision or unsigned omitted fields denied',()=>{
 for(const edit of [
  f=>{f.statement.releaseDecision='GO'},
  f=>{f.statement.kind='PRODUCTION_APPROVED'},
  f=>{f.statement.repository='forged/other'},
  f=>{delete f.statement.expiresAt},
  f=>{f.statement.extra='approve'},
  f=>{f.checkpoint.observedAt='not-a-date'}
 ]){
  const r=check((()=>{const f=packet();edit(f);return f})());
  assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('CV: no real nominees/token never contacts remote URLs or grants production',async()=>{
 let requested=0,loaded=0;
 const r=await verifyLiveDetachedCandidate({
  pushId:111,prId:222,securityLogin:'security-operator',
  businessLogin:'business-operator',token:'',
  proposal:{},now:NOW,
  loadCandidate:async()=>{loaded++;return packet();},
  fetchImpl:async()=>{requested++;throw Error('must not request');}
 });
 assert.equal(requested,0);
 assert.equal(loaded,1);
 assert.equal(r.twoSnapshotsAndDetachedCandidateMathematicallyConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CV: invalid nominators, same run IDs and missing packet loader abort before any GET',async()=>{
 const opts={
  pushId:111,prId:222,
  securityLogin:'security-operator',businessLogin:'business-operator',
  token:'test',proposal:{},fetchImpl:async()=>{throw Error('unexpected GET');},
  loadCandidate:async()=>packet()
 };
 for(const change of [
  o=>{o.securityLogin='j9619655391-max'},
  o=>{o.businessLogin=o.securityLogin},
  o=>{o.prId=o.pushId},
  o=>{o.pushId=0},
  o=>{o.loadCandidate=undefined}
 ]){
  const o={...opts};change(o);
  await assert.rejects(()=>verifyLiveDetachedCandidate(o),/CV_/);
 }
});
