import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {assessCrossWitnessRetrieval,witnessSigningBytes}
 from '../scripts/phase1ce-cross-witness-retrieval-preflight.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const NOW='2026-11-18T13:30:00.000Z';
const hash=x=>createHash('sha256').update(x).digest('hex');
const node=(a,b)=>createHash('sha256').update(Buffer.from([1])).update(a).update(b).digest();
const leaf=x=>createHash('sha256').update(Buffer.from([0])).update(Buffer.from(x)).digest();
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(obj(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('unsupported test fixture');
}
function makeEnvelope(){
 const body={schemaVersion:1,phase:'1CC',kind:'UNSIGNED_SOURCE_BOUND_CI_RECEIPT',
  repository:REPO,sourceHeadSha:'c'.repeat(40),checkedOutSha:'d'.repeat(40),
  githubEventName:'pull_request',githubRef:'refs/pull/1/merge',
  selectedInputBundleSha256:'e'.repeat(64),
  sourceAndReceiptAnomalyCodes:[],unsignedGithubArtifactOnly:true,
  globalZeroCriticalHighAuditPassed:false,releaseDecision:'HOLD',
  productionReleaseAuthorized:false};
 const envelopeSha256=hash('aaditech/phase1cc/unsigned-ci-source-receipt-envelope/v1\n'+canonical(body));
 return {body,envelopeSha256,localSourceAndArtifactsConsistent:true,
  independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,
  independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'};
}
function fixture(){
 const envelope=makeEnvelope();
 const context={ciJobId:'build-input-provenance',ciRunId:44309414646,
  runAttempt:1,challengeNonce:'f'.repeat(64),retrievalNonce:'9'.repeat(64),
  logRef:'log_source_auditor'};
 const payload=Buffer.from(JSON.stringify(envelope));
 const retrieval={schemaVersion:1,objectPath:'custody/run-44309414646.json',
  objectVersionId:'version_000001',repository:REPO,
  sourceHeadSha:envelope.body.sourceHeadSha,
  checkedOutSha:envelope.body.checkedOutSha,
  retrievalNonce:context.retrievalNonce,
  retrievedAt:'2026-11-18T13:29:30.000Z',
  contentLength:payload.length,contentSha256:hash(payload),
  bodyBase64:payload.toString('base64')};
 const left=leaf('old-checkpoint'),right=leaf('new-appended-archive');
 const oldRootSha256=left.toString('hex'),rootSha256=node(left,right).toString('hex');
 const authorities={},anchors={},witnesses=[],privateKeys={};
 for(const [i,witnessRef] of ['witness_alpha','witness_beta'].entries()){
  const org=i===0?'external_org_alpha':'external_org_beta';
  const admin=i===0?'external_admin_alpha':'external_admin_beta';
  const keyId=i===0?'witness_key_alpha':'witness_key_beta';
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  privateKeys[witnessRef]=privateKey;
  authorities[witnessRef]={
   witnessRef,keyId,organizationRef:org,administratorRef:admin,
   publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
   spkiSha256:hash(publicKey.export({type:'spki',format:'der'})),
   enrolledAt:'2026-11-17T00:00:00.000Z',
   expiresAt:'2026-12-17T00:00:00.000Z',revoked:false};
  anchors[witnessRef]={sequence:20,lastDigest:(i?'b':'a').repeat(64),
   treeSize:1,rootSha256:oldRootSha256};
  const statement={
   schemaVersion:1,purpose:'AUDITED_APPEND_ONLY_HEAD',
   witnessRef,keyId,organizationRef:org,administratorRef:admin,
   repository:REPO,sourceHeadSha:envelope.body.sourceHeadSha,
   checkedOutSha:envelope.body.checkedOutSha,
   envelopeSha256:envelope.envelopeSha256,ciRunId:context.ciRunId,
   runAttempt:context.runAttempt,challengeNonce:context.challengeNonce,
   logRef:context.logRef,previousSequence:20,sequence:21,
   previousDigest:anchors[witnessRef].lastDigest,
   oldTreeSize:1,oldRootSha256,treeSize:2,rootSha256,
   artifactVersionId:retrieval.objectVersionId,
   artifactSha256:retrieval.contentSha256,retrievalNonce:context.retrievalNonce,
   observedAt:'2026-11-18T13:29:00.000Z',
   expiresAt:'2026-11-18T13:35:00.000Z'};
  witnesses.push({statement,signatureBase64:
   sign(null,witnessSigningBytes(statement),privateKey).toString('base64')});
 }
 return {envelope,context,witnesses,authorities,anchors,
  consistencyProofSha256:[right.toString('hex')],retrieval,now:NOW,privateKeys};
}
function reSign(x,index){
 const {statement}=x.witnesses[index];
 x.witnesses[index].signatureBase64=sign(null,witnessSigningBytes(statement),
  x.privateKeys[statement.witnessRef]).toString('base64');
}
const assess=x=>assessCrossWitnessRetrieval(x);
test('1CE: two distinct test witness keys, RFC6962 growth and byte-exact retrieval agree but cannot authenticate outsiders',()=>{
 const r=assess(fixture());
 assert.equal(r.candidateSignedHeadsMathematicallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.verifiedSuppliedSignatureCount,2);
 assert.equal(r.receivedCandidateWitnessCount,2);
 assert.equal(r.observedVersionId,'version_000001');
 for(const flag of ['outOfBandWitnessEnrollmentsAuthenticated',
  'independentLogPublisherIdentityVerified',
  'authenticatedWitnessHighWatermarksTrusted',
  'externallyWitnessedAntiEquivocationOrMonotonicity',
  'officialWormObjectVersionApiResponseVerified',
  'retrievalTlsPeerAndStorageProviderVerified',
  'objectLockDeniedDeletionAndRetentionVerified',
  'independentlyRecoveredDrBytesVerified',
  'independentSourceCIWorkloadIdentityVerified',
  'globalZeroCriticalHighAuditPassed','productionReleaseAuthorized'])
  assert.equal(r[flag],false,flag);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionReleaseBlocked,true);
});
test('1CE: zero witnesses, no retrieved evidence and no trust anchors remain a non-waivable HOLD',()=>{
 const r=assess({envelope:makeEnvelope()});
 assert.equal(r.candidateSignedHeadsMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes('CE_INDEPENDENT_WITNESS_QUORUM_UNAVAILABLE'));
 assert.ok(r.anomalyCodes.includes('CE_RETRIEVAL_METADATA_UNBOUNDED_OR_MALFORMED'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CE: same size tree with same root is permitted only with empty proof',()=>{
 const x=fixture();const old=x.witnesses[0].statement.oldRootSha256;
 for(let i=0;i<2;i++){x.witnesses[i].statement.treeSize=1;
  x.witnesses[i].statement.rootSha256=old;reSign(x,i);}
 x.consistencyProofSha256=[];
 assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,true);
 x.consistencyProofSha256=['f'.repeat(64)];
 assert.ok(assess(x).anomalyCodes.includes('CE_RFC6962_APPEND_ONLY_PROOF_REJECTED'));
});
test('1CE: signed cross-witness different current log roots are rejected',()=>{
 const x=fixture();x.witnesses[1].statement.rootSha256='e'.repeat(64);reSign(x,1);
 const r=assess(x);
 assert.ok(r.anomalyCodes.includes('CE_CROSS_WITNESS_CURRENT_HEAD_EQUIVOCATION'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CE: disagreeing previous roots or historical sizes are detected as fork',()=>{
 for(const [k,v] of [['oldRootSha256','0'.repeat(64)],['oldTreeSize',2]]){
  const x=fixture();x.witnesses[1].statement[k]=v;reSign(x,1);
  assert.ok(assess(x).anomalyCodes.includes('CE_CROSS_WITNESS_PREVIOUS_HEAD_EQUIVOCATION'),k);
 }
});
test('1CE: wrong RFC6962 proof, omitted proof, invalid hex and impossible tree shrink cannot pass',()=>{
 for(const modify of [
  x=>x.consistencyProofSha256=[],
  x=>x.consistencyProofSha256=['a'.repeat(64)],
  x=>x.consistencyProofSha256=['not-hex'],
  x=>{x.witnesses[0].statement.treeSize=0;reSign(x,0);},
  x=>{x.witnesses[0].statement.treeSize=1000000001;reSign(x,0);}
 ]){
  const x=fixture();modify(x);
  assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,false);
 }
});
test('1CE: one replay, anchor rollback, skipped sequence or missing predecessor is rejected',()=>{
 for(const [k,v] of [['sequence',20],['sequence',22],
  ['previousSequence',19],['previousDigest','0'.repeat(64)]]){
  const x=fixture();x.witnesses[0].statement[k]=v;reSign(x,0);
  assert.ok(assess(x).anomalyCodes.includes('CE_REPLAY_FORK_OR_ROLLBACK_VS_SUPPLIED_ANCHOR'),k);
 }
 const x=fixture();x.anchors.witness_alpha.treeSize=3;
 assert.ok(assess(x).anomalyCodes.includes('CE_REPLAY_FORK_OR_ROLLBACK_VS_SUPPLIED_ANCHOR'));
});
test('1CE: mutable witness enrollment, duplicate organization and reused key/admin rejected',()=>{
 for(const modify of [
  x=>x.authorities.witness_alpha.revoked=true,
  x=>x.authorities.witness_alpha.spkiSha256='1'.repeat(64),
  x=>x.authorities.witness_alpha.enrolledAt='2026-11-19T00:00:00.000Z',
  x=>x.authorities.witness_beta.publicKeyPem=x.authorities.witness_alpha.publicKeyPem,
  x=>{x.witnesses[1].statement.organizationRef='external_org_alpha';
   x.authorities.witness_beta.organizationRef='external_org_alpha';reSign(x,1);},
  x=>{x.witnesses[1].statement.administratorRef='external_admin_alpha';
   x.authorities.witness_beta.administratorRef='external_admin_alpha';reSign(x,1);}
 ]){
  const x=fixture();modify(x);
  assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,false);
 }
});
test('1CE: forged signed source SHA, CI run, envelope digest or nonce is denied',()=>{
 for(const [k,v] of [
  ['sourceHeadSha','0'.repeat(40)],['checkedOutSha','0'.repeat(40)],
  ['envelopeSha256','0'.repeat(64)],['ciRunId',13],
  ['runAttempt',2],['challengeNonce','0'.repeat(64)],
  ['retrievalNonce','1'.repeat(64)],['artifactVersionId','other_ver'],
  ['artifactSha256','0'.repeat(64)],['logRef','attacker_log']]){
  const x=fixture();x.witnesses[1].statement[k]=v;reSign(x,1);
  assert.ok(assess(x).anomalyCodes.includes('CE_SIGNED_HEAD_CONTEXT_SOURCE_OR_FRESHNESS_DRIFT'),k);
 }
});
test('1CE: swapped signatures, noncanonical base64 and replaced witness roles fail',()=>{
 const x=fixture();x.witnesses[0].signatureBase64=x.witnesses[1].signatureBase64;
 assert.ok(assess(x).anomalyCodes.includes('CE_DETACHED_SIGNATURE_OR_PINNED_SPKI_INVALID'));
 const y=fixture();y.witnesses[1].signatureBase64='A'.repeat(86)+'==';
 assert.ok(assess(y).anomalyCodes.includes('CE_DETACHED_SIGNATURE_OR_PINNED_SPKI_INVALID'));
 const z=fixture();z.witnesses[1].statement.witnessRef='witness_alpha';
 assert.equal(assess(z).candidateSignedHeadsMathematicallyConsistent,false);
});
test('1CE: retrieved bytes are bounded, decoded, sha256-hashed and parsed as exact local envelope',()=>{
 for(const modify of [
  x=>x.retrieval.bodyBase64=Buffer.from('{"forged":true}').toString('base64'),
  x=>x.retrieval.contentSha256='a'.repeat(64),
  x=>x.retrieval.contentLength+=1,
  x=>x.retrieval.bodyBase64='!not-base64',
  x=>x.retrieval.bodyBase64='A'.repeat(400000),
  x=>x.retrieval.contentLength=300000,
  x=>x.retrieval.bodyBase64=Buffer.from('not-json').toString('base64')
 ]){
  const x=fixture();modify(x);
  assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,false);
  assert.equal(assess(x).productionReleaseAuthorized,false);
 }
});
test('1CE: object version, retrieval nonce, location path or stale receipt refuses',()=>{
 for(const [k,v] of [
  ['objectVersionId','other_version'],
  ['retrievalNonce','1'.repeat(64)],
  ['objectPath','../../private/secret'],
  ['retrievedAt','2026-11-17T00:00:00.000Z'],
  ['sourceHeadSha','0'.repeat(40)],['repository','attacker/repo']]){
  const x=fixture();x.retrieval[k]=v;
  assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,false,k);
 }
});
test('1CE: time windows, signature freshness, invalid schema and unknown fields fail',()=>{
 for(const [k,v] of [
  ['observedAt','2026-11-17T00:00:00.000Z'],
  ['observedAt','2026-11-18T14:00:00.000Z'],
  ['expiresAt','2026-11-18T13:20:00.000Z'],
  ['expiresAt','2026-11-19T13:30:00.000Z'],
  ['purpose','UNTRUSTED_RELEASE_PROOF'],
  ['schemaVersion',2]]){
  const x=fixture();x.witnesses[0].statement[k]=v;reSign(x,0);
  assert.equal(assess(x).candidateSignedHeadsMathematicallyConsistent,false,k);
 }
 const x=fixture();x.witnesses[0].statement.releaseDecision='GO';reSign(x,0);
 assert.ok(assess(x).anomalyCodes.includes('CE_UNRECOGNIZED_OR_MALFORMED_SIGNED_HEAD'));
});
test('1CE: one-party pseudo quorum, forged baseline green and mutated digest never grant release',()=>{
 const x=fixture();x.witnesses=[x.witnesses[0],x.witnesses[0]];
 assert.ok(assess(x).anomalyCodes.includes('CE_WITNESS_OR_ORGANIZATION_ADMIN_KEY_REUSED'));
 for(const mutate of [
  x=>x.envelope.body.globalZeroCriticalHighAuditPassed=true,
  x=>x.envelope.productionReleaseAuthorized=true,
  x=>x.envelope.body.sourceHeadSha='f'.repeat(40),
  x=>x.envelope.envelopeSha256='b'.repeat(64)]){
  const f=fixture();mutate(f);
  assert.ok(assess(f).anomalyCodes.includes('CE_LOCAL_CI_ENVELOPE_TAMPER_OR_RELEASE_CLAIM'));
  assert.equal(assess(f).productionReleaseAuthorized,false);
 }
});
