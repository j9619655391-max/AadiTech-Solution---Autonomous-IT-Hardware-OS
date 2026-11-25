import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {WITNESSES,REVIEWERS,historySigningBytes,assessCheckpointPublicationHistory}
 from '../scripts/phase1cf-checkpoint-publication-review-preflight.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const NOW='2026-11-18T13:45:00.000Z';
const hash=v=>createHash('sha256').update(v).digest('hex');
const leaf=v=>createHash('sha256').update(Buffer.from([0])).update(Buffer.from(v)).digest();
const node=(l,r)=>createHash('sha256').update(Buffer.from([1])).update(l).update(r).digest();
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
function canonical(v){
 if(v===null||typeof v==='string'||typeof v==='boolean')return JSON.stringify(v);
 if(typeof v==='number'&&Number.isSafeInteger(v))return JSON.stringify(v);
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(obj(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
 throw Error('bad fixture type');
}
function envelope(){
 const body={phase:'1CC',kind:'UNSIGNED_SOURCE_BOUND_CI_RECEIPT',
  repository:REPO,sourceHeadSha:'c'.repeat(40),checkedOutSha:'d'.repeat(40),
  githubEventName:'pull_request',selectedInputBundleSha256:'e'.repeat(64),
  sourceAndReceiptAnomalyCodes:[],globalZeroCriticalHighAuditPassed:false,
  releaseDecision:'HOLD',productionReleaseAuthorized:false};
 return {body,envelopeSha256:hash('aaditech/phase1cc/unsigned-ci-source-receipt-envelope/v1\n'+canonical(body)),
  localSourceAndArtifactsConsistent:true,
  independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'};
}
function fixture(){
 const e=envelope(),t='2026-11-18T13:44:00.000Z',t2='2026-11-18T13:44:30.000Z';
 const context={runId:44315685105,runAttempt:1,logRef:'publisher_log_alpha',
  challengeNonce:'a'.repeat(64),archiveObjectVersion:'archived_version_01',
  retrievedEnvelopeSha256:e.envelopeSha256};
 const roots=[leaf('prior-leaf'),leaf('append-two'),leaf('append-three')];
 const oldRoot=roots[0].toString('hex');
 const secondRoot=node(roots[0],roots[1]).toString('hex');
 const thirdRoot=node(node(roots[0],roots[1]),roots[2]).toString('hex');
 const initialAnchor={epoch:10,epochDigest:'0'.repeat(64),treeSize:1,rootSha256:oldRoot};
 const privateKeys={},witnessKeys={},reviewerKeys={};
 for(const [i,role] of [...WITNESSES,...REVIEWERS].entries()){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');privateKeys[role]=privateKey;
  const key={role,issuerId:'issuer_'+role.toLowerCase(),
   organization:'organization_'+i+'_separate',
   login:'reviewer_'+i+'_external',
   publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
   spkiSha256:hash(publicKey.export({type:'spki',format:'der'})),
   enrolledAt:'2026-11-17T00:00:00.000Z',
   expiresAt:'2026-11-20T00:00:00.000Z',revoked:false};
  if(WITNESSES.includes(role))witnessKeys[role]=key;
  else reviewerKeys[role]=key;
 }
 const signIt=(s,role)=>({statement:s,algorithm:'Ed25519',
  signature:sign(null,historySigningBytes(s),privateKeys[role]).toString('base64')});
 const epochs=[];
 for(const [index,spec] of [
  {epoch:11,oldTreeSize:1,oldRootSha256:oldRoot,treeSize:2,
   rootSha256:secondRoot,previousEpochDigest:initialAnchor.epochDigest,
   observedAt:t,consistencyProofSha256:[roots[1].toString('hex')]},
  {epoch:12,oldTreeSize:2,oldRootSha256:secondRoot,treeSize:3,
   rootSha256:thirdRoot,previousEpochDigest:null,
   observedAt:t2,consistencyProofSha256:[roots[2].toString('hex')]}
 ].entries()){
  const checkpoint={schemaVersion:1,repository:REPO,prNumber:1,
   sourceHeadSha:e.body.sourceHeadSha,checkoutSha:e.body.checkedOutSha,
   envelopeSha256:e.envelopeSha256,runId:context.runId,
   runAttempt:context.runAttempt,logRef:context.logRef,
   challengeNonce:context.challengeNonce,epoch:spec.epoch,
   previousEpochDigest:spec.previousEpochDigest??epochs[0]?.digest,
   oldTreeSize:spec.oldTreeSize,oldRootSha256:spec.oldRootSha256,
   treeSize:spec.treeSize,rootSha256:spec.rootSha256,
   archiveObjectVersion:context.archiveObjectVersion,
   archiveEnvelopeSha256:context.retrievedEnvelopeSha256,
   observedAt:spec.observedAt};
  const epochDigest=hash(historySigningBytes(checkpoint));
  const witnessReceipts=WITNESSES.map(role=>signIt({
   role,issuerId:witnessKeys[role].issuerId,epochDigest,observedAt:spec.observedAt,
   retrievalChannel:role===WITNESSES[0]?'AUDITOR_CHANNEL_A':'AUDITOR_CHANNEL_B',
   retrievalContentSha256:context.retrievedEnvelopeSha256,
   archiveObjectVersion:context.archiveObjectVersion
  },role));
  epochs.push({checkpoint,consistencyProofSha256:spec.consistencyProofSha256,
   witnessReceipts,digest:epochDigest});
 }
 for(const e of epochs)delete e.digest;
 const latestDigest=hash(historySigningBytes(epochs[1].checkpoint));
 const reviews=REVIEWERS.map(role=>signIt({
  schemaVersion:1,role,issuerId:reviewerKeys[role].issuerId,
  reviewerLogin:reviewerKeys[role].login,repository:REPO,prNumber:1,
  sourceHeadSha:e.body.sourceHeadSha,checkoutSha:e.body.checkedOutSha,
  runId:context.runId,runAttempt:context.runAttempt,latestEpochDigest:latestDigest,
  challengeNonce:context.challengeNonce,issuedAt:t2,
  expiresAt:'2026-11-18T13:50:00.000Z',
  decision:'CANDIDATE_REVIEW_ONLY'
 },role));
 return {envelope:e,context,initialAnchor,epochs,witnessKeys,reviewerKeys,
  reviews,now:NOW,privateKeys};
}
const signAgain=(f,kind,index,role)=>{
 const item=kind==='epoch'?f.epochs[index].witnessReceipts[role===WITNESSES[0]?0:1]:
  f.reviews[index];
 item.signature=sign(null,historySigningBytes(item.statement),f.privateKeys[role]).toString('base64');
};
const verify=f=>assessCheckpointPublicationHistory(f);
test('CF: mathematical two-epoch, dual-witness and dual-reviewer chain is never real independent authority',()=>{
 const result=verify(fixture());
 assert.equal(result.localSignedChainMathematicallyConsistent,true,result.anomalyCodes.join(','));
 for(const key of ['externalPublisherTrustAuthenticated','independentWitnessKeyEnrollmentVerified',
  'independentPublisherRetrievalAndTlsIdentityVerified','externallyPersistentCheckpointHighWatermarkVerified',
  'crossRunAntiEquivocationExternallyCorroborated','wormObjectVersionRetentionAndDeniedDeleteVerified',
  'independentReviewerIdentityAndGithubApprovalVerified','realLatestHeadGithubRulesetAndCodeownersVerified',
  'signedCIWorkloadProvenanceVerified','externalStorageDrRestoreAuthenticated',
  'globalZeroCriticalHighAuditPassed','productionReleaseAuthorized'])
  assert.equal(result[key],false,key);
 assert.equal(result.releaseDecision,'HOLD');
 assert.equal(result.productionReleaseBlocked,true);
});
test('CF: zero-input CI correctly denies external signature, witness and reviewer quorum',()=>{
 const r=verify({envelope:envelope()});
 assert.equal(r.localSignedChainMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes('CF_REQUIRES_TWO_EPOCHS_WITNESSES_AND_REVIEWERS'));
 assert.ok(r.anomalyCodes.includes('CF_MISSING_EXTERNAL_PERSISTENT_ANCHOR'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CF: previous epoch fork, rollback, gap and sequence substitution cannot pass',()=>{
 for(const [k,v] of [
  ['epoch',11],['epoch',13],['previousEpochDigest','f'.repeat(64)],
  ['oldTreeSize',1],['oldRootSha256','a'.repeat(64)]]){
  const f=fixture();f.epochs[1].checkpoint[k]=v;
  assert.ok(verify(f).anomalyCodes.includes('CF_EPOCH_REPLAY_ROLLBACK_OR_HISTORY_FORK'),k);
 }
});
test('CF: independently supplied initial anchor cannot be silently replaced',()=>{
 for(const [k,v] of [
  ['epoch',11],['epochDigest','f'.repeat(64)],
  ['treeSize',2],['rootSha256','0'.repeat(64)]]){
  const f=fixture();f.initialAnchor[k]=v;
  assert.ok(verify(f).anomalyCodes.includes('CF_EPOCH_REPLAY_ROLLBACK_OR_HISTORY_FORK'),k);
 }
});
test('CF: invalid RFC6962 path, shortened tree and substituted head rejected',()=>{
 for(const alter of [
  f=>f.epochs[1].consistencyProofSha256=[],
  f=>f.epochs[0].consistencyProofSha256=['f'.repeat(64)],
  f=>f.epochs[1].consistencyProofSha256=['nothex'],
  f=>f.epochs[1].checkpoint.treeSize=1,
  f=>f.epochs[1].checkpoint.rootSha256='a'.repeat(64)
 ]){
  const f=fixture();alter(f);
  assert.equal(verify(f).localSignedChainMathematicallyConsistent,false);
 }
});
test('CF: witness channel mismatch, source divergence, archive version or nonce spoof denied',()=>{
 for(const [k,v] of [['retrievalChannel','AUDITOR_CHANNEL_B'],
  ['epochDigest','0'.repeat(64)],['retrievalContentSha256','f'.repeat(64)],
  ['archiveObjectVersion','forged_object'],
  ['observedAt','2026-11-17T13:00:00.000Z']]){
  const f=fixture();f.epochs[0].witnessReceipts[0].statement[k]=v;
  signAgain(f,'epoch',0,WITNESSES[0]);
  assert.ok(verify(f).anomalyCodes.includes('CF_WITNESS_PUBLICATION_RETRIEVAL_BINDING_MISMATCH'),k);
 }
});
test('CF: witness signatures cannot be swapped or authenticated with supplied wrong public key',()=>{
 const f=fixture();
 f.epochs[1].witnessReceipts[0].signature=f.epochs[1].witnessReceipts[1].signature;
 assert.ok(verify(f).anomalyCodes.includes('CF_WITNESS_KEY_OR_SIGNATURE_NOT_VERIFIABLE'));
 const g=fixture();
 g.witnessKeys[WITNESSES[0]].publicKeyPem=g.witnessKeys[WITNESSES[1]].publicKeyPem;
 assert.ok(verify(g).anomalyCodes.includes('CF_WITNESS_KEY_OR_SIGNATURE_NOT_VERIFIABLE'));
});
test('CF: duplicate witness receipts and missing signer cannot fake quorum',()=>{
 const f=fixture();f.epochs[0].witnessReceipts[1]=f.epochs[0].witnessReceipts[0];
 assert.ok(verify(f).anomalyCodes.includes('CF_DUPLICATE_OR_UNRECOGNIZED_WITNESS'));
 const g=fixture();g.epochs[0].witnessReceipts=[];
 assert.ok(verify(g).anomalyCodes.includes('CF_UNRECOGNIZED_EPOCH_OR_WITNESS_PACKET'));
});
test('CF: reviewer must be signed for latest current HEAD, run, role and epoch digest',()=>{
 for(const [k,v] of [['sourceHeadSha','f'.repeat(40)],
  ['latestEpochDigest','e'.repeat(64)],['reviewerLogin','attacker'],
  ['decision','APPROVED'],['runId',44],['challengeNonce','0'.repeat(64)]]){
  const f=fixture();f.reviews[0].statement[k]=v;
  signAgain(f,'review',0,REVIEWERS[0]);
  assert.ok(verify(f).anomalyCodes.includes('CF_STALE_SELF_OR_WRONG_SOURCE_REVIEWER_CLAIM'),k);
 }
});
test('CF: self-review and shared organization, identity or key authority never count',()=>{
 for(const modify of [
  f=>f.reviewerKeys[REVIEWERS[0]].login='j9619655391-max',
  f=>f.reviewerKeys[REVIEWERS[0]].organization=f.witnessKeys[WITNESSES[0]].organization,
  f=>f.reviewerKeys[REVIEWERS[0]].spkiSha256=f.witnessKeys[WITNESSES[0]].spkiSha256,
  f=>f.reviewerKeys[REVIEWERS[0]].revoked=true]){
  const f=fixture();modify(f);
  assert.equal(verify(f).localSignedChainMathematicallyConsistent,false);
 }
});
test('CF: revoked, expired or future enrollment and invalid detached signature rejected',()=>{
 for(const modify of [
  f=>f.witnessKeys[WITNESSES[1]].revoked=true,
  f=>f.witnessKeys[WITNESSES[1]].enrolledAt='2026-11-19T00:00:00.000Z',
  f=>f.reviewerKeys[REVIEWERS[1]].expiresAt='2026-11-18T13:30:00.000Z',
  f=>f.reviews[1].signature='A'.repeat(86)+'==']){
  const f=fixture();modify(f);
  assert.equal(verify(f).localSignedChainMathematicallyConsistent,false);
 }
});
test('CF: stale or reordered history and expired reviewer approval rejected',()=>{
 const x=fixture();x.epochs[1].checkpoint.observedAt=x.epochs[0].checkpoint.observedAt;
 assert.ok(verify(x).anomalyCodes.includes('CF_HISTORICAL_TIME_REORDERED'));
 for(const [k,v] of [['issuedAt','2026-11-17T12:00:00.000Z'],
   ['expiresAt','2026-11-18T13:44:00.000Z'],
   ['expiresAt','2026-11-19T13:45:00.000Z']]){
  const f=fixture();f.reviews[1].statement[k]=v;
  signAgain(f,'review',1,REVIEWERS[1]);
  assert.ok(verify(f).anomalyCodes.includes('CF_STALE_SELF_OR_WRONG_SOURCE_REVIEWER_CLAIM'),k);
 }
});
test('CF: forged expected CI source, changed run nonce, missing archive source fail closed',()=>{
 for(const modify of [
  f=>f.envelope.body.sourceHeadSha='f'.repeat(40),
  f=>f.envelope.envelopeSha256='f'.repeat(64),
  f=>f.context.challengeNonce='0'.repeat(64),
  f=>f.context.retrievedEnvelopeSha256='0'.repeat(64),
  f=>f.epochs[0].checkpoint.archiveEnvelopeSha256='0'.repeat(64)
 ]){
  const f=fixture();modify(f);
  assert.equal(verify(f).localSignedChainMathematicallyConsistent,false);
  assert.equal(verify(f).productionReleaseAuthorized,false);
 }
});
test('CF: duplicate reviewer, unexpected signed GO and excess epoch input fail closed',()=>{
 const f=fixture();f.reviews[1]=f.reviews[0];
 assert.ok(verify(f).anomalyCodes.includes('CF_DUPLICATE_OR_UNKNOWN_REVIEWER_ROLE'));
 const g=fixture();g.reviews[0].statement.productionReleaseAuthorized=true;
 assert.ok(verify(g).anomalyCodes.includes('CF_DUPLICATE_OR_UNKNOWN_REVIEWER_ROLE'));
 const h=fixture();h.epochs.push(h.epochs[1]);
 assert.ok(verify(h).anomalyCodes.includes('CF_REQUIRES_TWO_EPOCHS_WITNESSES_AND_REVIEWERS'));
});
