import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {ROLES,signingPayload,assessIndependentCustody}
 from '../scripts/phase1cd-external-custody-preflight.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const now='2026-11-18T12:00:00.000Z',issued='2026-11-18T11:59:00.000Z';
const expires='2026-11-18T12:05:00.000Z';
const digest=x=>createHash('sha256').update(x).digest('hex');
const clone=x=>structuredClone(x);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(obj(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('invalid fixture');
}
function envelope(){
 const body={phase:'1CC',kind:'UNSIGNED_SOURCE_BOUND_CI_RECEIPT',
  repository:REPO,sourceHeadSha:'c'.repeat(40),checkedOutSha:'d'.repeat(40),
  githubEventName:'pull_request',selectedInputBundleSha256:'e'.repeat(64),
  sourceAndReceiptAnomalyCodes:[],unsignedGithubArtifactOnly:true,
  globalZeroCriticalHighAuditPassed:false,productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 return {body,envelopeSha256:digest('aaditech/phase1cc/unsigned-ci-source-receipt-envelope/v1\n'+canonical(body)),
  localSourceAndArtifactsConsistent:true,independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'};
}
function fixture(){
 const e=envelope(),context={ciRunId:44305859172,ciJobId:'build-input-provenance',
  runAttempt:1,challengeNonce:'f'.repeat(64),issuerIds:{
   CI_ATTESTOR:'ci-attestor-org',WORM_AUDITOR:'worm-admin-org',DR_AUDITOR:'restore-auditor-org'}};
 const enrollments={},checkpoints={},privateKeys={};
 for(const [i,role] of ROLES.entries()){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');privateKeys[role]=privateKey;
  enrollments[role]={role,issuerId:context.issuerIds[role],
   organization:['independent-ci-issuer','independent-worm-auditor','independent-dr-operator'][i],
   publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
   spkiSha256:digest(publicKey.export({type:'spki',format:'der'})),
   validFrom:'2026-11-17T00:00:00.000Z',validUntil:'2026-12-17T00:00:00.000Z',
   revoked:false};
  checkpoints[role]={sequence:40,lastDigest:String(i+1).repeat(64)};
 }
 const common=role=>({schemaVersion:1,type:role,issuerId:context.issuerIds[role],
  repository:REPO,sourceHeadSha:e.body.sourceHeadSha,checkedOutSha:e.body.checkedOutSha,
  envelopeSha256:e.envelopeSha256,ciRunId:context.ciRunId,ciJobId:context.ciJobId,
  runAttempt:context.runAttempt,challengeNonce:context.challengeNonce,
  sequence:41,previousDigest:checkpoints[role].lastDigest,issuedAt:issued,expiresAt:expires});
 const make=(role,extra)=>{
  const statement={...common(role),...extra};
  return {statement,algorithm:'Ed25519',
   signature:sign(null,signingPayload(statement),privateKeys[role]).toString('base64')};
 };
 const ci=make('CI_ATTESTOR',{githubWorkflowPath:'.github/workflows/ci.yml',
  oidcIssuer:'https://token.actions.githubusercontent.com',
  oidcSubject:'repo:'+REPO+':pull_request',subjectDigest:e.envelopeSha256});
 const worm=make('WORM_AUDITOR',{attestorClaimDigest:digest(signingPayload(ci.statement)),
  bucketArn:'arn:aws:s3:::auditor-evidence-store',
  objectKey:'custody/ci-run-44305859172.json',objectVersionId:'immutable.version-0001',
  objectLockMode:'COMPLIANCE',retentionUntil:'2027-11-18T12:00:00.000Z',
  storedEnvelopeDigest:e.envelopeSha256,primaryRegion:'ap-south-1',deleteDeniedObserved:true});
 const dr=make('DR_AUDITOR',{wormClaimDigest:digest(signingPayload(worm.statement)),
  restoredVersionId:worm.statement.objectVersionId,
  restoredEnvelopeDigest:e.envelopeSha256,restoreCheckedAt:now,recoveryRegion:'eu-west-1'});
 return {envelope:e,context,enrollments,checkpoints,proofs:[ci,worm,dr],privateKeys,now};
}
function resign(x,role){
 const p=x.proofs.find(v=>v?.statement?.type===role);
 p.signature=sign(null,signingPayload(p.statement),x.privateKeys[role]).toString('base64');
}
const assess=x=>assessIndependentCustody(x);
test('1CD: three mutually linked synthetic Ed25519 claims remain NEVER external authenticated',()=>{
 const r=assess(fixture());
 assert.equal(r.candidateSignaturesAndClaimChainsLocallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.acceptedSuppliedClaimCount,3);
 for(const k of ['outOfBandAuthorityEnrollmentAuthenticated','monotonicCheckpointExternallyWitnessed',
  'antiEquivocationExternalJournalVerified','githubOidcJwtIssuerSignatureAndSubjectVerified',
  'ciWorkloadBinaryIndependentlyAttested','realS3ObjectLockVersionRetentionIndependentlyVerified',
  'offsiteDrRestorationIndependentlyVerified','independentSecurityAndBusinessApprovalsVerified',
  'productionReleaseAuthorized'])assert.equal(r[k],false,k);
 assert.equal(r.productionReleaseBlocked,true);assert.equal(r.releaseDecision,'HOLD');
});
test('1CD: zero external inputs remains HARD HOLD',()=>{
 const x=fixture(),r=assess({envelope:x.envelope,context:{...x.context,challengeNonce:'0'.repeat(64)}});
 assert.equal(r.submittedExternalClaimCount,0);
 assert.ok(r.anomalyCodes.includes('CD_UNTRUSTED_RUN_CONTEXT_CHALLENGE_OR_ROLE_ASSIGNMENT'));
 assert.ok(r.anomalyCodes.includes('CD_CUSTODY_SIGNER_QUORUM_INCOMPLETE'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CD: duplicate witnesses and replay/rollback/sequence-gap are denied',()=>{
 for(const change of [{sequence:39},{sequence:40},{sequence:42},
  {previousDigest:'0'.repeat(64)}]){
  const x=fixture();Object.assign(x.proofs[0].statement,change);resign(x,'CI_ATTESTOR');
  assert.ok(assess(x).anomalyCodes.includes('CD_REPLAY_ROLLBACK_OR_GAP_CI_ATTESTOR'));
 }
 const x=fixture();x.proofs.push(clone(x.proofs[0]));
 assert.equal(assess(x).candidateSignaturesAndClaimChainsLocallyConsistent,false);
});
test('1CD: forged OIDC workload identity, CI source, challenge or target is rejected',()=>{
 for(const [k,v] of [['oidcSubject','repo:attacker/fork:pull_request'],
  ['oidcIssuer','https://attacker.invalid'],['githubWorkflowPath','release.yml'],
  ['subjectDigest','0'.repeat(64)],['checkedOutSha','0'.repeat(40)],
  ['sourceHeadSha','0'.repeat(40)],['challengeNonce','0'.repeat(64)]]){
  const x=fixture();x.proofs[0].statement[k]=v;resign(x,'CI_ATTESTOR');
  assert.equal(assess(x).candidateSignaturesAndClaimChainsLocallyConsistent,false,k);
 }
});
test('1CD: incorrect Ed25519 signature or substituted enrolled SPKI is denied',()=>{
 const x=fixture();x.proofs[0].signature='A'.repeat(86)+'==';
 assert.ok(assess(x).anomalyCodes.includes('CD_SIGNATURE_OR_OUT_OF_BAND_KEY_MISMATCH_CI_ATTESTOR'));
 const y=fixture();y.enrollments.CI_ATTESTOR.publicKeyPem=y.enrollments.DR_AUDITOR.publicKeyPem;
 assert.ok(assess(y).anomalyCodes.includes('CD_SIGNATURE_OR_OUT_OF_BAND_KEY_MISMATCH_CI_ATTESTOR'));
});
test('1CD: revoked, wrong-role, reused-organization, invalid enrollment timeline denied',()=>{
 for(const mutation of [
  x=>x.enrollments.CI_ATTESTOR.role='DR_AUDITOR',
  x=>x.enrollments.WORM_AUDITOR.organization=x.enrollments.CI_ATTESTOR.organization,
  x=>x.enrollments.CI_ATTESTOR.revoked=true,
  x=>x.enrollments.CI_ATTESTOR.spkiSha256='0'.repeat(64),
  x=>x.enrollments.CI_ATTESTOR.validFrom='2026-11-19T00:00:00.000Z',
  x=>x.enrollments.CI_ATTESTOR.validUntil='2026-11-18T11:59:00.000Z']){
  const x=fixture();mutation(x);
  assert.equal(assess(x).candidateSignaturesAndClaimChainsLocallyConsistent,false);
 }
});
test('1CD: unsigned, short-retention, nonexistent-version and WORM audit spoof fail',()=>{
 for(const [k,v] of [
  ['objectLockMode','GOVERNANCE'],['objectVersionId',''],
  ['bucketArn','arn:aws:s3:::'],['objectKey','../../secrets'],
  ['retentionUntil','2026-11-19T12:00:00.000Z'],
  ['storedEnvelopeDigest','0'.repeat(64)],['deleteDeniedObserved',false],
  ['attestorClaimDigest','0'.repeat(64)]]){
  const x=fixture();x.proofs[1].statement[k]=v;resign(x,'WORM_AUDITOR');
  assert.ok(assess(x).anomalyCodes.includes('CD_WORM_VERSION_LOCK_RETENTION_OR_CI_LINK_INVALID'),k);
 }
});
test('1CD: forged upstream CI statement changes invalidate WORM crosslink',()=>{
 const x=fixture();x.proofs[0].statement.sequence=42;resign(x,'CI_ATTESTOR');
 const a=assess(x);assert.ok(a.anomalyCodes.includes('CD_REPLAY_ROLLBACK_OR_GAP_CI_ATTESTOR'));
 assert.ok(a.anomalyCodes.includes('CD_WORM_VERSION_LOCK_RETENTION_OR_CI_LINK_INVALID'));
});
test('1CD: DR archive restore must bind exact WORM version, digest and different region',()=>{
 for(const [k,v] of [['wormClaimDigest','0'.repeat(64)],
  ['restoredVersionId','other-version'],['restoredEnvelopeDigest','0'.repeat(64)],
  ['restoreCheckedAt','2026-11-18T11:58:00.000Z'],['recoveryRegion','ap-south-1']]){
  const x=fixture();x.proofs[2].statement[k]=v;resign(x,'DR_AUDITOR');
  assert.ok(assess(x).anomalyCodes.includes('CD_DR_RETRIEVAL_VERSION_OR_WITNESS_INVALID'),k);
 }
});
test('1CD: tampered source checksum, fake global green or self-authorized go fail',()=>{
 for(const mutate of [
  x=>x.envelope.body.sourceHeadSha='f'.repeat(40),
  x=>x.envelope.envelopeSha256='f'.repeat(64),
  x=>x.envelope.body.globalZeroCriticalHighAuditPassed=true,
  x=>x.envelope.productionReleaseAuthorized=true,
  x=>x.envelope.localSourceAndArtifactsConsistent=false]){
  const x=fixture();mutate(x);
  assert.ok(assess(x).anomalyCodes.includes('CD_CI_SOURCE_ENVELOPE_UNTRUSTED_OR_TAMPERED'));
  assert.equal(assess(x).productionReleaseAuthorized,false);
 }
});
test('1CD: unexpected release-authorizing fields and non-roles are refused',()=>{
 const x=fixture();x.proofs[0].statement.productionReleaseAuthorized=true;resign(x,'CI_ATTESTOR');
 assert.ok(assess(x).anomalyCodes.includes('CD_CLAIM_CONTEXT_OR_SCHEMA_CI_ATTESTOR'));
 const y=fixture();y.proofs[2].statement.type='OWNER_APPROVER';
 assert.ok(assess(y).anomalyCodes.includes('CD_MISSING_OUT_OF_BAND_WITNESS_DR_AUDITOR'));
});
test('1CD: future, expired and excessive validity windows rejected',()=>{
 for(const [k,v] of [['issuedAt','2026-11-18T12:15:00.000Z'],
  ['issuedAt','2026-11-18T11:00:00.000Z'],
  ['expiresAt','2026-11-18T11:59:59.000Z'],
  ['expiresAt','2026-11-19T12:00:00.000Z']]){
  const x=fixture();x.proofs[0].statement[k]=v;resign(x,'CI_ATTESTOR');
  assert.ok(assess(x).anomalyCodes.includes('CD_CLAIM_EXPIRED_OR_FUTURE_CI_ATTESTOR'),k);
 }
});
test('1CD: malformed proof, absent signature and zero-input cannot ever permit release',()=>{
 for(const malformed of [null,{},'bad']){
  const x=fixture();x.proofs[0]=malformed;
  const r=assess(x);assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.candidateSignaturesAndClaimChainsLocallyConsistent,false);
 }
 const x=fixture();x.proofs[0].signature='ab==';
 assert.ok(assess(x).anomalyCodes.includes('CD_INVALID_DETACHED_SIGNATURE_FORMAT_CI_ATTESTOR'));
 const r=assess({envelope:envelope()});
 assert.equal(r.submittedExternalClaimCount,0);
 assert.equal(r.releaseDecision,'HOLD');
});
