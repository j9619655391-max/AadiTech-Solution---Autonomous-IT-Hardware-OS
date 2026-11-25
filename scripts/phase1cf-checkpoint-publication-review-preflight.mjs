import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyUnsignedEnvelopeDigest} from './phase1cc-ci-evidence-envelope.mjs';
import {phase1BbVerifyConsistencyProof} from './lib/phase1BbWitnessConsistency.mjs';

// CF: bounded multi-epoch OFFLINE candidate history and latest-head reviewer
// cryptography. All keys, high-watermarks, receipts and reviewer identity
// are supplied by the applicant. This is never authenticated external trust.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const WITNESSES=Object.freeze(['CHECKPOINT_WITNESS_A','CHECKPOINT_WITNESS_B']);
export const REVIEWERS=Object.freeze(['SECURITY_REVIEWER','BUSINESS_OWNER']);
export const DOMAIN='aaditech/phase1cf/independent-history-candidate/v1\n';
const SHA=/^[0-9a-f]{40}$/;
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[a-z][a-z0-9_-]{5,63}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const exact=(v,fields)=>obj(v)&&Object.keys(v).length===fields.length&&fields.every(k=>Object.hasOwn(v,k));
const digest=v=>createHash('sha256').update(v).digest('hex');
const stamp=v=>{
 if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v))return NaN;
 const n=Date.parse(v);
 return Number.isFinite(n)&&new Date(n).toISOString()===v?n:NaN;
};
function canonical(v){
 if(v===null||typeof v==='string'||typeof v==='boolean')return JSON.stringify(v);
 if(typeof v==='number'&&Number.isSafeInteger(v))return JSON.stringify(v);
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(obj(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
 throw Error('CF unsupported canonical evidence type');
}
export function historySigningBytes(v){
 if(!obj(v)||JSON.stringify(v).length>8192)throw Error('CF invalid or oversized statement');
 return Buffer.from(DOMAIN+canonical(v),'utf8');
}
const KEY=Object.freeze(['role','issuerId','organization','login','publicKeyPem',
 'spkiSha256','enrolledAt','expiresAt','revoked']);
const HEAD=Object.freeze(['schemaVersion','repository','prNumber','sourceHeadSha',
 'checkoutSha','envelopeSha256','runId','runAttempt','logRef','challengeNonce',
 'epoch','previousEpochDigest','oldTreeSize','oldRootSha256','treeSize',
 'rootSha256','archiveObjectVersion','archiveEnvelopeSha256','observedAt']);
const WITNESS=Object.freeze(['role','issuerId','epochDigest','observedAt',
 'retrievalChannel','retrievalContentSha256','archiveObjectVersion']);
const REVIEW=Object.freeze(['schemaVersion','role','issuerId','reviewerLogin',
 'repository','prNumber','sourceHeadSha','checkoutSha','runId','runAttempt',
 'latestEpochDigest','challengeNonce','issuedAt','expiresAt','decision']);
function signatureValid(statement,record,key){
 if(!obj(record)||!exact(key,KEY)||record.algorithm!=='Ed25519'||
    typeof record.signature!=='string'||!SIG.test(record.signature)||
    typeof key.publicKeyPem!=='string'||key.publicKeyPem.length>4096||
    !HEX.test(key.spkiSha256??''))return false;
 try{
  const sig=Buffer.from(record.signature,'base64');
  if(sig.length!==64||sig.toString('base64')!==record.signature)return false;
  const pub=createPublicKey(key.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   digest(pub.export({type:'spki',format:'der'}))===key.spkiSha256&&
   verify(null,historySigningBytes(statement),pub,sig);
 }catch{return false;}
}
function validKey(key,role,issuerId,issued,now){
 return exact(key,KEY)&&key.role===role&&key.issuerId===issuerId&&
  ID.test(key.issuerId??'')&&ID.test(key.organization??'')&&
  typeof key.login==='string'&&/^[A-Za-z0-9_-]{4,63}$/.test(key.login)&&
  key.login!=='j9619655391-max'&&
  key.revoked===false&&Number.isFinite(stamp(key.enrolledAt))&&
  Number.isFinite(stamp(key.expiresAt))&&
  stamp(key.enrolledAt)<=issued&&stamp(key.expiresAt)>now&&
  stamp(key.expiresAt)>=issued;
}
const deny=errors=>Object.freeze({
 phase:'1CF',schemaVersion:1,kind:'CANDIDATE_MULTI_EPOCH_REVIEW_QUORUM_HOLD',
 localSignedChainMathematicallyConsistent:errors.size===0,
 anomalyCodes:Object.freeze([...errors].sort()),
 externalPublisherTrustAuthenticated:false,
 independentWitnessKeyEnrollmentVerified:false,
 independentPublisherRetrievalAndTlsIdentityVerified:false,
 externallyPersistentCheckpointHighWatermarkVerified:false,
 crossRunAntiEquivocationExternallyCorroborated:false,
 wormObjectVersionRetentionAndDeniedDeleteVerified:false,
 independentReviewerIdentityAndGithubApprovalVerified:false,
 realLatestHeadGithubRulesetAndCodeownersVerified:false,
 signedCIWorkloadProvenanceVerified:false,
 externalStorageDrRestoreAuthenticated:false,
 globalZeroCriticalHighAuditPassed:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});
export function assessCheckpointPublicationHistory({
 envelope,context={},initialAnchor=null,epochs=[],witnessKeys={},
 reviewerKeys={},reviews=[],now='2026-11-18T13:45:00.000Z'
}={}){
 const errors=new Set();
 const t=stamp(now);
 if(!Number.isFinite(t))errors.add('CF_INVALID_VERIFICATION_CLOCK');
 if(!obj(envelope)||!verifyUnsignedEnvelopeDigest(envelope)||
   envelope.localSourceAndArtifactsConsistent!==true||
   envelope.body?.kind!=='UNSIGNED_SOURCE_BOUND_CI_RECEIPT'||
   envelope.body?.repository!==REPO||
   envelope.body?.sourceAndReceiptAnomalyCodes?.length!==0||
   !SHA.test(envelope.body?.sourceHeadSha??'')||
   !SHA.test(envelope.body?.checkedOutSha??'')||
   envelope.body?.globalZeroCriticalHighAuditPassed!==false)
  errors.add('CF_UNTRUSTED_LOCAL_SOURCE_OR_ENVELOPE');
 if(!obj(context)||!Number.isSafeInteger(context.runId)||context.runId<1||
   !Number.isSafeInteger(context.runAttempt)||context.runAttempt<1||
   !ID.test(context.logRef??'')||
   !HEX.test(context.challengeNonce??'')||
   context.challengeNonce==='0'.repeat(64)||
   !ID.test(context.archiveObjectVersion??'')||
   !HEX.test(context.retrievedEnvelopeSha256??''))
  errors.add('CF_RUN_RETRIEVAL_OR_CHALLENGE_INVALID');
 if(!obj(initialAnchor)||!Number.isSafeInteger(initialAnchor.epoch)||
   initialAnchor.epoch<0||initialAnchor.epoch>1_000_000_000||
   !HEX.test(initialAnchor.epochDigest??'')||
   !Number.isSafeInteger(initialAnchor.treeSize)||initialAnchor.treeSize<1||
   !HEX.test(initialAnchor.rootSha256??''))
  errors.add('CF_MISSING_EXTERNAL_PERSISTENT_ANCHOR');
 if(!Array.isArray(epochs)||epochs.length!==2||!Array.isArray(reviews)||
   reviews.length!==2||!obj(witnessKeys)||!obj(reviewerKeys)||
   Object.keys(witnessKeys).length!==2||Object.keys(reviewerKeys).length!==2)
  errors.add('CF_REQUIRES_TWO_EPOCHS_WITNESSES_AND_REVIEWERS');
 let previous=initialAnchor,latestDigest=null;
 const allIdentities=new Set(),allOrganizations=new Set(),allKeys=new Set();
 const enrolled=[...WITNESSES,...REVIEWERS].map(role=>
  WITNESSES.includes(role)?witnessKeys?.[role]:reviewerKeys?.[role]);
 for(const key of enrolled){
  if(!obj(key))continue;
  if(allIdentities.has(key.login)||allOrganizations.has(key.organization)||
    allKeys.has(key.spkiSha256))
   errors.add('CF_WITNESS_REVIEWER_IDENTITY_KEY_OR_ADMIN_REUSED');
  allIdentities.add(key.login);
  allOrganizations.add(key.organization);
  allKeys.add(key.spkiSha256);
 }
 for(const [index,item] of (Array.isArray(epochs)?epochs.slice(0,2):[]).entries()){
  const head=item?.checkpoint;
  if(!obj(item)||!exact(head,HEAD)||!Array.isArray(item.consistencyProofSha256)||
    item.consistencyProofSha256.length>64||
    !Array.isArray(item.witnessReceipts)||item.witnessReceipts.length!==2){
   errors.add('CF_UNRECOGNIZED_EPOCH_OR_WITNESS_PACKET');continue;
  }
  const issued=stamp(head.observedAt);
  if(head.schemaVersion!==1||head.repository!==REPO||head.prNumber!==1||
    head.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    head.checkoutSha!==envelope?.body?.checkedOutSha||
    head.envelopeSha256!==envelope?.envelopeSha256||
    head.runId!==context?.runId||head.runAttempt!==context?.runAttempt||
    head.logRef!==context?.logRef||
    head.challengeNonce!==context?.challengeNonce||
    head.archiveObjectVersion!==context?.archiveObjectVersion||
    head.archiveEnvelopeSha256!==context?.retrievedEnvelopeSha256||
    !HEX.test(head.rootSha256??'')||!HEX.test(head.oldRootSha256??'')||
    !Number.isSafeInteger(issued)||issued>t+300000||issued<t-900000)
   errors.add('CF_EPOCH_SOURCE_RUN_OR_ARCHIVE_BINDING_INVALID');
  if(!previous||!Number.isSafeInteger(head.epoch)||
    head.epoch!==previous.epoch+1||
    head.previousEpochDigest!==previous.epochDigest||
    head.oldTreeSize!==previous.treeSize||
    head.oldRootSha256!==previous.rootSha256)
   errors.add('CF_EPOCH_REPLAY_ROLLBACK_OR_HISTORY_FORK');
  if(index>0&&Number.isFinite(stamp(epochs[index-1]?.checkpoint?.observedAt))&&
    issued<=stamp(epochs[index-1].checkpoint.observedAt))
   errors.add('CF_HISTORICAL_TIME_REORDERED');
  if(!Array.isArray(item.consistencyProofSha256)||
    item.consistencyProofSha256.some(x=>!HEX.test(x))){
   errors.add('CF_INVALID_RFC6962_PATH');
  }else try{
   if(!phase1BbVerifyConsistencyProof({
    oldSize:head.oldTreeSize,newSize:head.treeSize,
    oldRootSha256:head.oldRootSha256,newRootSha256:head.rootSha256,
    proofSha256:item.consistencyProofSha256
   }))errors.add('CF_INVALID_RFC6962_PATH');
  }catch{errors.add('CF_INVALID_RFC6962_PATH');}
  let currentDigest=null;
  try{currentDigest=digest(historySigningBytes(head));}
  catch{errors.add('CF_MALFORMED_CANONICAL_EPOCH');}
  const seen=new Set();
  for(const observation of item.witnessReceipts){
   const s=observation?.statement,role=s?.role;
   if(!WITNESSES.includes(role)||seen.has(role)||!exact(s,WITNESS)){
    errors.add('CF_DUPLICATE_OR_UNRECOGNIZED_WITNESS');continue;
   }
   seen.add(role);
   const key=witnessKeys?.[role];
   if(s.issuerId!==key?.issuerId||s.epochDigest!==currentDigest||
     s.archiveObjectVersion!==context?.archiveObjectVersion||
     s.retrievalContentSha256!==context?.retrievedEnvelopeSha256||
     s.observedAt!==head.observedAt||
     s.retrievalChannel!==(role==='CHECKPOINT_WITNESS_A'?
       'AUDITOR_CHANNEL_A':'AUDITOR_CHANNEL_B'))
    errors.add('CF_WITNESS_PUBLICATION_RETRIEVAL_BINDING_MISMATCH');
   if(!validKey(key,role,s.issuerId,issued,t)||
     !signatureValid(s,observation,key))
    errors.add('CF_WITNESS_KEY_OR_SIGNATURE_NOT_VERIFIABLE');
  }
  if(seen.size!==2)errors.add('CF_INDEPENDENT_WITNESS_QUORUM_INCOMPLETE');
  previous={epoch:head.epoch,epochDigest:currentDigest,
   treeSize:head.treeSize,rootSha256:head.rootSha256};
  latestDigest=currentDigest;
 }
 const reviewSeen=new Set();
 for(const entry of (Array.isArray(reviews)?reviews.slice(0,2):[])){
  const s=entry?.statement,role=s?.role;
  if(!REVIEWERS.includes(role)||reviewSeen.has(role)||!exact(s,REVIEW)){
   errors.add('CF_DUPLICATE_OR_UNKNOWN_REVIEWER_ROLE');continue;
  }
  reviewSeen.add(role);
  const key=reviewerKeys?.[role],issued=stamp(s.issuedAt),expires=stamp(s.expiresAt);
  if(s.schemaVersion!==1||s.issuerId!==key?.issuerId||
    s.reviewerLogin!==key?.login||s.repository!==REPO||
    s.prNumber!==1||s.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    s.checkoutSha!==envelope?.body?.checkedOutSha||
    s.runId!==context?.runId||s.runAttempt!==context?.runAttempt||
    s.latestEpochDigest!==latestDigest||
    s.challengeNonce!==context?.challengeNonce||
    s.decision!=='CANDIDATE_REVIEW_ONLY'||!Number.isFinite(issued)||
    !Number.isFinite(expires)||issued>t+300000||issued<t-900000||
    expires<=t||expires<=issued||expires-issued>900000)
   errors.add('CF_STALE_SELF_OR_WRONG_SOURCE_REVIEWER_CLAIM');
  if(!validKey(key,role,s.issuerId,issued,t)||
    !signatureValid(s,entry,key))
   errors.add('CF_REVIEWER_SIGNED_CLAIM_UNVERIFIABLE');
 }
 if(reviewSeen.size!==2)errors.add('CF_INDEPENDENT_REVIEWER_QUORUM_MISSING');
 return deny(errors);
}
function readLocal(path){
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>262144)
  throw Error('CF missing/unsafe local source receipt');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CF only accepts zero-input --ci-hold');
 const envelope=readLocal('phase1cc-unsigned-source-receipt-hold.json');
 const cd=readLocal('phase1cd-zero-input-external-custody-hold.json');
 const ce=readLocal('phase1ce-zero-input-cross-witness-hold.json');
 const env=process.env;
 if(!verifyUnsignedEnvelopeDigest(envelope)||
    envelope.localSourceAndArtifactsConsistent!==true||
    env.CI!=='true'||env.GITHUB_ACTIONS!=='true'||
    env.GITHUB_REPOSITORY!==REPO||
    env.GITHUB_JOB!=='build-input-provenance'||
    env.GITHUB_SHA!==envelope.body?.checkedOutSha||
    env.GITHUB_EVENT_NAME!==envelope.body?.githubEventName||
    cd.phase!=='1CD'||cd.submittedExternalClaimCount!==0||
    cd.productionReleaseAuthorized!==false||cd.releaseDecision!=='HOLD'||
    ce.phase!=='1CE'||ce.receivedCandidateWitnessCount!==0||
    ce.productionReleaseAuthorized!==false||ce.releaseDecision!=='HOLD')
  throw Error('CF upstream local CI guard or zero-input provenance invalid');
 const report=assessCheckpointPublicationHistory({envelope});
 writeFileSync('phase1cf-zero-input-review-history-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(report.localSignedChainMathematicallyConsistent||
   report.productionReleaseAuthorized||report.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('CF external checkpoint/reviewer history HOLD failed:',
   e instanceof Error?e.message:'Unknown');process.exitCode=1;
 }
}
