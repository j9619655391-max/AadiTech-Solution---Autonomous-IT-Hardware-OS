import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {SOURCE_ROLES,publicationBytes,assessExternalSourceReconciliation}
 from '../scripts/phase1cg-external-source-reconciliation-preflight.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const NOW='2026-11-18T14:30:00.000Z';
const hash=x=>createHash('sha256').update(x).digest('hex');
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(obj(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('unhandled fixture');
}
function makeEnvelope(){
 const body={phase:'1CC',kind:'UNSIGNED_SOURCE_BOUND_CI_RECEIPT',
  repository:REPO,sourceHeadSha:'c'.repeat(40),checkedOutSha:'d'.repeat(40),
  githubEventName:'pull_request',githubRef:'refs/pull/1/merge',
  selectedInputBundleSha256:'e'.repeat(64),
  sourceAndReceiptAnomalyCodes:[],globalZeroCriticalHighAuditPassed:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 return {body,envelopeSha256:hash('aaditech/phase1cc/unsigned-ci-source-receipt-envelope/v1\n'+canonical(body)),
  localSourceAndArtifactsConsistent:true,independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'};
}
function fixture(){
 const envelope=makeEnvelope();
 const context={runId:44319953120,runAttempt:1,challengeNonce:'1'.repeat(64),
  archiveObjectVersion:'archive_v001',archivedEnvelopeSha256:envelope.envelopeSha256,
  lastPushAt:'2026-11-18T14:15:00.000Z'};
 const anchor={storeId:'external_appendonly_source',version:40,epoch:40,
  publicationSha256:'a'.repeat(64),treeSize:10,treeRootSha256:'b'.repeat(64),
  observedAt:'2026-11-18T14:20:00.000Z'};
 const publication={schemaVersion:1,storeId:anchor.storeId,
  previousVersion:40,nextVersion:41,epoch:41,
  previousPublicationSha256:anchor.publicationSha256,
  treeSize:11,treeRootSha256:'f'.repeat(64),repository:REPO,prNumber:1,
  sourceHeadSha:envelope.body.sourceHeadSha,checkoutSha:envelope.body.checkedOutSha,
  envelopeSha256:envelope.envelopeSha256,runId:context.runId,
  runAttempt:context.runAttempt,challengeNonce:context.challengeNonce,
  archiveObjectVersion:context.archiveObjectVersion,
  archivedEnvelopeSha256:context.archivedEnvelopeSha256,
  issuedAt:'2026-11-18T14:28:00.000Z',expiresAt:'2026-11-18T14:33:00.000Z'};
 const publicationSha256=hash(publicationBytes(publication));
 const sourceKeys={},privateKeys={},sourceRecords=[];
 for(const [i,role] of SOURCE_ROLES.entries()){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  privateKeys[role]=privateKey;
  const key={role,issuerId:i?'witness_issuer_b':'publisher_issuer_a',
   organization:i?'external_org_beta':'external_org_alpha',
   administrator:i?'external_admin_beta':'external_admin_alpha',
   login:i?'witness_operator_beta':'publisher_operator_alpha',
   publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
   spkiSha256:hash(publicKey.export({type:'spki',format:'der'})),
   enrolledAt:'2026-11-17T00:00:00.000Z',
   expiresAt:'2026-12-01T00:00:00.000Z',revoked:false};
  sourceKeys[role]=key;
  const statement={schemaVersion:1,role,issuerId:key.issuerId,
   organization:key.organization,administrator:key.administrator,
   endpointHost:i?'witness.example.net':'publisher.example.org',
   tlsPeerSpkiSha256:(i?'d':'c').repeat(64),
   httpStatus:200,redirectCount:0,
   retrievedPublicationSha256:publicationSha256,
   observedAnchorVersion:anchor.version,
   observedAnchorDigest:anchor.publicationSha256,
   previousVersion:publication.previousVersion,nextVersion:publication.nextVersion,
   epoch:publication.epoch,publicationSha256,repository:REPO,
   sourceHeadSha:envelope.body.sourceHeadSha,
   challengeNonce:context.challengeNonce,
   observedAt:'2026-11-18T14:29:00.000Z',
   expiresAt:'2026-11-18T14:33:00.000Z'};
  sourceRecords.push({statement,algorithm:'Ed25519',
   signature:sign(null,publicationBytes(statement),privateKey).toString('base64')});
 }
 const reviewerAssignments={SECURITY_REVIEWER:'security_external',
  BUSINESS_OWNER:'business_external'};
 const reviewRecords=[
  {id:10,login:'security_external',state:'APPROVED',commitSha:envelope.body.sourceHeadSha,
   submittedAt:'2026-11-18T14:29:00.000Z'},
  {id:12,login:'business_external',state:'APPROVED',commitSha:envelope.body.sourceHeadSha,
   submittedAt:'2026-11-18T14:29:30.000Z'}];
 const githubObservation={phase:'1BY',kind:'READ_ONLY_GITHUB_GOVERNANCE_OBSERVATION',
  githubRepoContextMatched:true,observedPrDraftAndUnmerged:true,
  eventSourceHeadAndBaseMatch:true,ciMergeMatchesPrApi:true,
  observedDevHeadSha:envelope.body.sourceHeadSha,
  observedPrMergeSha:envelope.body.checkedOutSha,
  observableRequiredBranchRulesPresent:true,
  independentReviewerSecurityAndBusinessRolesVerified:false,
  effectiveProtectedBranchPolicyIndependentlyAuthenticated:false,
  reviews:{observedApproverLogins:['business_external','security_external']},
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 return {envelope,context,anchor,publication,sourceRecords,sourceKeys,
  githubObservation,reviewRecords,reviewerAssignments,forkReports:[],
  now:NOW,privateKeys};
}
function reSign(x,index){
 const role=SOURCE_ROLES[index],row=x.sourceRecords[index];
 row.signature=sign(null,publicationBytes(row.statement),
  x.privateKeys[role]).toString('base64');
}
const assess=x=>assessExternalSourceReconciliation(x);
test('CG: valid synthetic dual-source CAS and two candidate GitHub reviewers never authorize production',()=>{
 const r=assess(fixture());
 assert.equal(r.candidateSourceAndReviewerObservationsConsistent,true,r.anomalyCodes.join(','));
 for(const key of ['independentlyEnrolledSourceAndReviewerKeysVerified',
  'genuineTlsPublisherServerAndTransportAuthenticated',
  'remoteSourcePayloadIndependentlyRetrieved',
  'durableCheckpointCompareAndSwapExternallyEnforced',
  'crossRunForkGossipAndHighWatermarkExternallyVerified',
  'remoteWormObjectLockRetentionAndDeleteDenialAuthenticated',
  'actualGithubReviewerIdentityAndMembershipVerified',
  'independentlyAuthenticatedGithubRulesetOrCodeowners',
  'sourceBoundIndependentCIWorkloadSignatureVerified',
  'externalProviderAndCorporateAuthorityVerified',
  'globalZeroCriticalHighAuditPassed','productionReleaseAuthorized'])
  assert.equal(r[key],false,key);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CG: missing external sources, CAS and GitHub reviewer evidence are HARD HOLD',()=>{
 const r=assess({envelope:makeEnvelope()});
 assert.ok(r.anomalyCodes.includes('CG_EXTERNALLY_PERSISTED_ANCHOR_NOT_PROVEN'));
 assert.ok(r.anomalyCodes.includes('CG_TWO_INDEPENDENT_SOURCE_SIGNERS_REQUIRED'));
 assert.ok(r.anomalyCodes.includes('CG_READONLY_GITHUB_REVIEW_OR_RULE_SOURCE_NOT_CORRELATED'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CG: repeated, skipped, rolled-back and forged CAS checkpoint sequences rejected',()=>{
 for(const [k,v] of [
  ['previousVersion',39],['nextVersion',40],['nextVersion',43],
  ['epoch',40],['epoch',45],
  ['previousPublicationSha256','0'.repeat(64)],
  ['treeSize',9],['treeSize',10],['treeRootSha256','b'.repeat(64)]]){
  const x=fixture();x.publication[k]=v;
  assert.ok(assess(x).anomalyCodes.includes('CG_CHECKPOINT_CAS_REPLAY_ROLLBACK_OR_FORK'),k);
 }
});
test('CG: anchor cannot silently change version, digest or tree state',()=>{
 for(const [k,v] of [['version',41],['epoch',41],
  ['publicationSha256','0'.repeat(64)],['treeSize',12],
  ['treeRootSha256','e'.repeat(64)]]){
  const x=fixture();x.anchor[k]=v;
  assert.ok(assess(x).anomalyCodes.includes('CG_CHECKPOINT_CAS_REPLAY_ROLLBACK_OR_FORK'),k);
 }
});
test('CG: source data must bind actual commit, test merge, run, archive object and nonce',()=>{
 for(const [k,v] of [
  ['sourceHeadSha','0'.repeat(40)],['checkoutSha','0'.repeat(40)],
  ['envelopeSha256','0'.repeat(64)],['runId',1],['runAttempt',2],
  ['challengeNonce','0'.repeat(64)],['archiveObjectVersion','other_v001'],
  ['archivedEnvelopeSha256','0'.repeat(64)],['prNumber',2]]){
  const x=fixture();x.publication[k]=v;
  assert.ok(assess(x).anomalyCodes.includes('CG_PUBLICATION_REPO_RUN_HEAD_ARCHIVE_MISMATCH'),k);
 }
});
test('CG: signed sources must match publication digest and supplied high-watermark',()=>{
 for(const [k,v] of [
  ['publicationSha256','0'.repeat(64)],
  ['retrievedPublicationSha256','0'.repeat(64)],
  ['observedAnchorDigest','0'.repeat(64)],
  ['observedAnchorVersion',38],['previousVersion',38],
  ['nextVersion',45],['epoch',39],['challengeNonce','0'.repeat(64)]]){
  const x=fixture();x.sourceRecords[0].statement[k]=v;reSign(x,0);
  assert.ok(assess(x).anomalyCodes.includes('CG_UNVERIFIED_SIGNATURE_TLS_OR_SOURCE_SCOPE_PUBLISHER_OBSERVER'),k);
 }
});
test('CG: spoofed TLS peer, HTTP status, redirects and unreviewed endpoint disallowed',()=>{
 for(const [k,v] of [
  ['tlsPeerSpkiSha256','invalid'],
  ['httpStatus',302],['redirectCount',1],
  ['endpointHost','evil.attacker.invalid'],
  ['observedAt','2026-11-17T14:29:00.000Z'],
  ['expiresAt','2026-11-18T14:25:00.000Z']]){
  const x=fixture();x.sourceRecords[1].statement[k]=v;reSign(x,1);
  assert.ok(assess(x).anomalyCodes.includes('CG_UNVERIFIED_SIGNATURE_TLS_OR_SOURCE_SCOPE_INDEPENDENT_WITNESS_OBSERVER'),k);
 }
});
test('CG: mathematically signed records with revoked/swapped key, replayed signature denied',()=>{
 const x=fixture();x.sourceRecords[1].signature=x.sourceRecords[0].signature;
 assert.ok(assess(x).anomalyCodes.includes('CG_UNVERIFIED_SIGNATURE_TLS_OR_SOURCE_SCOPE_INDEPENDENT_WITNESS_OBSERVER'));
 for(const change of [
  x=>x.sourceKeys[SOURCE_ROLES[0]].revoked=true,
  x=>x.sourceKeys[SOURCE_ROLES[0]].publicKeyPem=x.sourceKeys[SOURCE_ROLES[1]].publicKeyPem,
  x=>x.sourceKeys[SOURCE_ROLES[0]].enrolledAt='2026-11-19T00:00:00.000Z',
  x=>x.sourceKeys[SOURCE_ROLES[0]].expiresAt='2026-11-18T14:10:00.000Z']){
  const y=fixture();change(y);
  assert.equal(assess(y).candidateSourceAndReviewerObservationsConsistent,false);
 }
});
test('CG: two observations from same organization, admin, key or login are not independent',()=>{
 for(const k of ['organization','administrator','login','spkiSha256']){
  const x=fixture();
  x.sourceKeys[SOURCE_ROLES[1]][k]=x.sourceKeys[SOURCE_ROLES[0]][k];
  x.sourceRecords[1].statement[k]=x.sourceRecords[0].statement[k]??x.sourceRecords[1].statement[k];
  reSign(x,1);
  assert.equal(assess(x).candidateSourceAndReviewerObservationsConsistent,false,k);
 }
 const x=fixture();x.sourceRecords[1]=x.sourceRecords[0];
 assert.ok(assess(x).anomalyCodes.includes('CG_MISSING_OR_DUPLICATE_SOURCE_PUBLISHER_OBSERVER'));
});
test('CG: fork gossip detects same epoch alternate digest and newer unseen watermark',()=>{
 const cases=[
  {epoch:40,publicationSha256:'0'.repeat(64),sourceId:'source_a'},
  {epoch:41,publicationSha256:'0'.repeat(64),sourceId:'source_b'},
  {epoch:42,publicationSha256:'f'.repeat(64),sourceId:'source_c'}
 ];
 for(const report of cases){
  const x=fixture();x.forkReports=[report];
  assert.ok(assess(x).anomalyCodes.includes('CG_EXTERNALLY_REPORTED_FORK_OR_ADVANCED_HIGH_WATERMARK'));
 }
 const x=fixture();x.forkReports=[{epoch:'bad',publicationSha256:'x',sourceId:'a'}];
 assert.ok(assess(x).anomalyCodes.includes('CG_FORK_GOSSIP_PACKET_MALFORMED'));
});
test('CG: observed official GitHub API source and required branch policy cannot be assumed',()=>{
 for(const [k,v] of [
  ['githubRepoContextMatched',false],
  ['observedPrDraftAndUnmerged',false],
  ['eventSourceHeadAndBaseMatch',false],
  ['ciMergeMatchesPrApi',false],
  ['observableRequiredBranchRulesPresent',false],
  ['observedDevHeadSha','0'.repeat(40)],
  ['observedPrMergeSha','0'.repeat(40)],
  ['productionReleaseAuthorized',true],
  ['independentReviewerSecurityAndBusinessRolesVerified',true]]){
  const x=fixture();x.githubObservation[k]=v;
  assert.ok(assess(x).anomalyCodes.includes('CG_READONLY_GITHUB_REVIEW_OR_RULE_SOURCE_NOT_CORRELATED'),k);
 }
});
test('CG: last review wins; dismissed, rejected, old head and pre-push approvals refused',()=>{
 for(const [k,v] of [
  ['state','DISMISSED'],['state','CHANGES_REQUESTED'],
  ['commitSha','0'.repeat(40)],
  ['submittedAt','2026-11-18T14:14:00.000Z']]){
  const x=fixture();x.reviewRecords[0][k]=v;
  assert.ok(assess(x).anomalyCodes.includes('CG_LATEST_NONAUTHOR_GITHUB_REVIEW_MISSING_OR_STALE_SECURITY_REVIEWER'),k);
 }
 const x=fixture();x.reviewRecords.push({
  id:30,login:'security_external',state:'DISMISSED',
  commitSha:x.envelope.body.sourceHeadSha,
  submittedAt:'2026-11-18T14:29:50.000Z'});
 assert.ok(assess(x).anomalyCodes.includes('CG_LATEST_NONAUTHOR_GITHUB_REVIEW_MISSING_OR_STALE_SECURITY_REVIEWER'));
});
test('CG: two distinct nonauthor reviewer logins must agree with source-approved list',()=>{
 const x=fixture();x.reviewerAssignments.BUSINESS_OWNER='security_external';
 assert.ok(assess(x).anomalyCodes.includes('CG_REVIEWER_ROLE_ASSIGNMENT_OR_QUORUM_MISSING'));
 const y=fixture();y.githubObservation.reviews.observedApproverLogins=['security_external'];
 assert.ok(assess(y).anomalyCodes.includes('CG_LATEST_NONAUTHOR_GITHUB_REVIEW_MISSING_OR_STALE_BUSINESS_OWNER'));
 const z=fixture();z.reviewRecords.pop();
 assert.ok(assess(z).anomalyCodes.includes('CG_LATEST_NONAUTHOR_GITHUB_REVIEW_MISSING_OR_STALE_BUSINESS_OWNER'));
});
test('CG: malformed, oversized and injected GO fields fail closed, no real external release',()=>{
 const x=fixture();x.publication.productionReleaseAuthorized=true;
 assert.ok(assess(x).anomalyCodes.includes('CG_PUBLICATION_MALFORMED_OR_UNBOUNDED'));
 const y=fixture();y.envelope.productionReleaseAuthorized=true;
 assert.ok(assess(y).anomalyCodes.includes('CG_SOURCE_ENVELOPE_MALFORMED_OR_FALSE_GO'));
 const z=fixture();z.reviewRecords[0].productionReleaseAuthorized=true;
 assert.ok(assess(z).anomalyCodes.includes('CG_MALFORMED_GITHUB_REVIEW_EVENT'));
 const w=fixture();w.context.challengeNonce='0'.repeat(64);
 assert.ok(assess(w).anomalyCodes.includes('CG_RUN_ARCHIVE_NONCE_OR_LAST_PUSH_INVALID'));
});
