import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyUnsignedEnvelopeDigest} from './phase1cc-ci-evidence-envelope.mjs';

// 1CG: candidate-only cross-source publication, durable checkpoint CAS and
// read-only GitHub latest-head reviewer corroboration. Caller-provided SPKI,
// TLS/HTTP claims, anchors, GitHub observations and roles are NOT independently
// authenticated. CI deliberately has zero external inputs or write privileges.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const SOURCE_ROLES=Object.freeze(['PUBLISHER_OBSERVER','INDEPENDENT_WITNESS_OBSERVER']);
export const REVIEW_ROLES=Object.freeze(['SECURITY_REVIEWER','BUSINESS_OWNER']);
export const DOMAIN='aaditech/phase1cg/publication-corroboration/v1\n';
const HASH=/^[0-9a-f]{64}$/;
const SHA=/^[0-9a-f]{40}$/;
const ID=/^[a-z][a-z0-9_-]{5,63}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const AUTHOR='j9619655391-max';
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const sha256=x=>createHash('sha256').update(x).digest('hex');
const stamp=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const n=Date.parse(x);
 return Number.isFinite(n)&&new Date(n).toISOString()===x?n:NaN;
};
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(own(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('CG unsupported canonical source claim');
}
export function publicationBytes(x){
 if(!own(x)||JSON.stringify(x).length>8192)throw Error('CG bounded publication required');
 return Buffer.from(DOMAIN+canonical(x),'utf8');
}
const ANCHOR=['storeId','version','epoch','publicationSha256','treeSize','treeRootSha256','observedAt'];
const PUB=['schemaVersion','storeId','previousVersion','nextVersion','epoch',
 'previousPublicationSha256','treeSize','treeRootSha256','repository',
 'prNumber','sourceHeadSha','checkoutSha','envelopeSha256','runId',
 'runAttempt','challengeNonce','archiveObjectVersion','archivedEnvelopeSha256',
 'issuedAt','expiresAt'];
const KEY=['role','issuerId','organization','administrator','login','publicKeyPem',
 'spkiSha256','enrolledAt','expiresAt','revoked'];
const OBS=['schemaVersion','role','issuerId','organization','administrator',
 'endpointHost','tlsPeerSpkiSha256','httpStatus','redirectCount',
 'retrievedPublicationSha256','observedAnchorVersion',
 'observedAnchorDigest','previousVersion','nextVersion','epoch',
 'publicationSha256','repository','sourceHeadSha','challengeNonce',
 'observedAt','expiresAt'];
const REVIEW=['id','login','state','commitSha','submittedAt'];
function signatureOk(s,record,key){
 if(!own(record)||record.algorithm!=='Ed25519'||!own(key)||
    typeof record.signature!=='string'||!SIG.test(record.signature)||
    typeof key.publicKeyPem!=='string'||key.publicKeyPem.length>4096||
    !HASH.test(key.spkiSha256??''))return false;
 try{
  const sig=Buffer.from(record.signature,'base64');
  if(sig.length!==64||sig.toString('base64')!==record.signature)return false;
  const pub=createPublicKey(key.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   sha256(pub.export({type:'spki',format:'der'}))===key.spkiSha256&&
   verify(null,publicationBytes(s),pub,sig);
 }catch{return false;}
}
const result=errors=>Object.freeze({
 phase:'1CG',schemaVersion:1,kind:'UNTRUSTED_CROSS_SOURCE_CAS_REVIEW_PREFLIGHT',
 candidateSourceAndReviewerObservationsConsistent:errors.size===0,
 anomalyCodes:Object.freeze([...errors].sort()),
 independentlyEnrolledSourceAndReviewerKeysVerified:false,
 genuineTlsPublisherServerAndTransportAuthenticated:false,
 remoteSourcePayloadIndependentlyRetrieved:false,
 durableCheckpointCompareAndSwapExternallyEnforced:false,
 crossRunForkGossipAndHighWatermarkExternallyVerified:false,
 remoteWormObjectLockRetentionAndDeleteDenialAuthenticated:false,
 actualGithubReviewerIdentityAndMembershipVerified:false,
 independentlyAuthenticatedGithubRulesetOrCodeowners:false,
 sourceBoundIndependentCIWorkloadSignatureVerified:false,
 externalProviderAndCorporateAuthorityVerified:false,
 globalZeroCriticalHighAuditPassed:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});
export function assessExternalSourceReconciliation({
 envelope,context={},anchor=null,publication=null,sourceRecords=[],
 sourceKeys={},githubObservation=null,reviewRecords=[],
 reviewerAssignments={},forkReports=[],now='2026-11-18T14:30:00.000Z'
}={}){
 const errors=new Set(),time=stamp(now);
 if(!Number.isFinite(time))errors.add('CG_INVALID_VERIFICATION_CLOCK');
 if(!own(envelope)||!verifyUnsignedEnvelopeDigest(envelope)||
    envelope.localSourceAndArtifactsConsistent!==true||
    envelope.body?.phase!=='1CC'||
    envelope.body?.kind!=='UNSIGNED_SOURCE_BOUND_CI_RECEIPT'||
    envelope.body?.repository!==REPO||
    envelope.body?.sourceAndReceiptAnomalyCodes?.length!==0||
    !SHA.test(envelope.body?.sourceHeadSha??'')||
    !SHA.test(envelope.body?.checkedOutSha??'')||
    envelope.body?.globalZeroCriticalHighAuditPassed!==false)
  errors.add('CG_SOURCE_ENVELOPE_MALFORMED_OR_FALSE_GO');
 if(!own(context)||!Number.isSafeInteger(context.runId)||context.runId<1||
   !Number.isSafeInteger(context.runAttempt)||context.runAttempt<1||
   !HASH.test(context.challengeNonce??'')||
   context.challengeNonce==='0'.repeat(64)||
   !ID.test(context.archiveObjectVersion??'')||
   !HASH.test(context.archivedEnvelopeSha256??'')||
   typeof context.lastPushAt!=='string'||!Number.isFinite(stamp(context.lastPushAt))||
   stamp(context.lastPushAt)>time)
  errors.add('CG_RUN_ARCHIVE_NONCE_OR_LAST_PUSH_INVALID');
 if(!exact(anchor,ANCHOR)||!ID.test(anchor.storeId??'')||
   !Number.isSafeInteger(anchor.version)||anchor.version<1||
   !Number.isSafeInteger(anchor.epoch)||anchor.epoch<1||
   !HASH.test(anchor.publicationSha256??'')||
   !Number.isSafeInteger(anchor.treeSize)||anchor.treeSize<1||
   !HASH.test(anchor.treeRootSha256??'')||
   !Number.isFinite(stamp(anchor.observedAt))||stamp(anchor.observedAt)>time)
  errors.add('CG_EXTERNALLY_PERSISTED_ANCHOR_NOT_PROVEN');
 if(!exact(publication,PUB)){
  errors.add('CG_PUBLICATION_MALFORMED_OR_UNBOUNDED');
 }else{
  if(publication.schemaVersion!==1||publication.storeId!==anchor?.storeId||
    !Number.isSafeInteger(publication.previousVersion)||
    !Number.isSafeInteger(publication.nextVersion)||
    !Number.isSafeInteger(publication.epoch)||
    publication.previousVersion!==anchor?.version||
    publication.nextVersion!==anchor?.version+1||
    publication.epoch!==anchor?.epoch+1||
    publication.previousPublicationSha256!==anchor?.publicationSha256||
    !Number.isSafeInteger(publication.treeSize)||publication.treeSize<anchor?.treeSize||
    publication.treeSize>1000000000||
    !HASH.test(publication.treeRootSha256??'')||
    (publication.treeSize===anchor?.treeSize&&publication.treeRootSha256!==anchor?.treeRootSha256)||
    (publication.treeSize>anchor?.treeSize&&publication.treeRootSha256===anchor?.treeRootSha256))
   errors.add('CG_CHECKPOINT_CAS_REPLAY_ROLLBACK_OR_FORK');
  if(publication.repository!==REPO||publication.prNumber!==1||
    publication.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    publication.checkoutSha!==envelope?.body?.checkedOutSha||
    publication.envelopeSha256!==envelope?.envelopeSha256||
    publication.runId!==context?.runId||
    publication.runAttempt!==context?.runAttempt||
    publication.challengeNonce!==context?.challengeNonce||
    publication.archiveObjectVersion!==context?.archiveObjectVersion||
    publication.archivedEnvelopeSha256!==context?.archivedEnvelopeSha256||
    publication.archivedEnvelopeSha256!==envelope?.envelopeSha256)
   errors.add('CG_PUBLICATION_REPO_RUN_HEAD_ARCHIVE_MISMATCH');
  const issued=stamp(publication.issuedAt),expires=stamp(publication.expiresAt);
  if(!Number.isFinite(issued)||!Number.isFinite(expires)||
     issued<=stamp(anchor?.observedAt)||issued<time-900000||
     issued>time+300000||expires<=time||expires<=issued||
     expires-issued>900000)
   errors.add('CG_PUBLICATION_STALE_OR_UNBOUNDED');
 }
 let publicationSha256=null;
 try{publicationSha256=sha256(publicationBytes(publication));}
 catch{errors.add('CG_PUBLICATION_DIGEST_UNAVAILABLE');}
 if(!Array.isArray(sourceRecords)||sourceRecords.length!==2||
   !own(sourceKeys)||Object.keys(sourceKeys).length!==2)
  errors.add('CG_TWO_INDEPENDENT_SOURCE_SIGNERS_REQUIRED');
 const distinct={issuers:new Set(),organizations:new Set(),administrators:new Set(),
  logins:new Set(),keys:new Set(),hosts:new Set()};
 for(const role of SOURCE_ROLES){
  const entries=Array.isArray(sourceRecords)?
    sourceRecords.filter(x=>x?.statement?.role===role):[];
  if(entries.length!==1){errors.add('CG_MISSING_OR_DUPLICATE_SOURCE_'+role);continue;}
  const entry=entries[0],s=entry.statement,key=sourceKeys?.[role];
  if(!exact(s,OBS)||!exact(key,KEY)){
   errors.add('CG_SIGNED_SOURCE_SCHEMA_OR_ENROLLMENT_INVALID_'+role);continue;
  }
  const issued=stamp(s.observedAt),expires=stamp(s.expiresAt);
  if(s.schemaVersion!==1||s.role!==role||key.role!==role||
    s.issuerId!==key.issuerId||s.organization!==key.organization||
    s.administrator!==key.administrator||
    !ID.test(key.issuerId??'')||!ID.test(key.organization??'')||
    !ID.test(key.administrator??'')||
    !ID.test(key.login??'')||key.login===AUTHOR||
    s.endpointHost!==(role===SOURCE_ROLES[0]?'publisher.example.org':'witness.example.net')||
    !HASH.test(s.tlsPeerSpkiSha256??'')||s.httpStatus!==200||
    s.redirectCount!==0||s.retrievedPublicationSha256!==publicationSha256||
    s.observedAnchorVersion!==anchor?.version||
    s.observedAnchorDigest!==anchor?.publicationSha256||
    s.previousVersion!==publication?.previousVersion||
    s.nextVersion!==publication?.nextVersion||
    s.epoch!==publication?.epoch||
    s.publicationSha256!==publicationSha256||
    s.repository!==REPO||s.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    s.challengeNonce!==context?.challengeNonce||
    !Number.isFinite(issued)||!Number.isFinite(expires)||
    issued<stamp(publication?.issuedAt)||issued<time-900000||
    issued>time+300000||expires<=time||expires<=issued||expires-issued>900000||
    key.revoked!==false||!Number.isFinite(stamp(key.enrolledAt))||
    !Number.isFinite(stamp(key.expiresAt))||
    stamp(key.enrolledAt)>issued||stamp(key.expiresAt)<expires||
    !signatureOk(s,entry,key))
   errors.add('CG_UNVERIFIED_SIGNATURE_TLS_OR_SOURCE_SCOPE_'+role);
  for(const [collection,value] of [
   [distinct.issuers,key.issuerId],[distinct.organizations,key.organization],
   [distinct.administrators,key.administrator],[distinct.logins,key.login],
   [distinct.keys,key.spkiSha256],[distinct.hosts,s.endpointHost]]){
   if(collection.has(value))errors.add('CG_SOURCE_AUTHORITY_OR_ENDPOINT_REUSED');
   collection.add(value);
  }
 }
 if(!Array.isArray(forkReports)||forkReports.length>8)
  errors.add('CG_FORK_GOSSIP_PACKET_MALFORMED');
 else for(const report of forkReports){
  if(!own(report)||!Number.isSafeInteger(report.epoch)||
    !HASH.test(report.publicationSha256??'')||
    !ID.test(report.sourceId??'')){
   errors.add('CG_FORK_GOSSIP_PACKET_MALFORMED');continue;
  }
  if((report.epoch===anchor?.epoch&&
     report.publicationSha256!==anchor?.publicationSha256)||
     (report.epoch===publication?.epoch&&
     report.publicationSha256!==publicationSha256)||
     report.epoch>publication?.epoch)
   errors.add('CG_EXTERNALLY_REPORTED_FORK_OR_ADVANCED_HIGH_WATERMARK');
 }
 // External read-only GitHub data from phase 1BY can be transported to this
 // pure verifier only as candidate content. Never treat a supplied snapshot
 // or role assignment as a verified Security/business approval.
 if(!own(githubObservation)||
   githubObservation.phase!=='1BY'||
   githubObservation.kind!=='READ_ONLY_GITHUB_GOVERNANCE_OBSERVATION'||
   githubObservation.githubRepoContextMatched!==true||
   githubObservation.observedPrDraftAndUnmerged!==true||
   githubObservation.eventSourceHeadAndBaseMatch!==true||
   githubObservation.ciMergeMatchesPrApi!==true||
   githubObservation.observedDevHeadSha!==envelope?.body?.sourceHeadSha||
   githubObservation.observedPrMergeSha!==envelope?.body?.checkedOutSha||
   githubObservation.observableRequiredBranchRulesPresent!==true||
   githubObservation.independentReviewerSecurityAndBusinessRolesVerified!==false||
   githubObservation.effectiveProtectedBranchPolicyIndependentlyAuthenticated!==false||
   githubObservation.productionReleaseAuthorized!==false||
   githubObservation.releaseDecision!=='HOLD')
  errors.add('CG_READONLY_GITHUB_REVIEW_OR_RULE_SOURCE_NOT_CORRELATED');
 if(!Array.isArray(reviewRecords)||reviewRecords.length<2||reviewRecords.length>200||
   !own(reviewerAssignments)||Object.keys(reviewerAssignments).length!==2||
   REVIEW_ROLES.some(role=>!ID.test(reviewerAssignments[role]??''))||
   reviewerAssignments.SECURITY_REVIEWER===reviewerAssignments.BUSINESS_OWNER||
   REVIEW_ROLES.some(role=>reviewerAssignments[role]===AUTHOR))
  errors.add('CG_REVIEWER_ROLE_ASSIGNMENT_OR_QUORUM_MISSING');
 const latest=new Map();
 if(Array.isArray(reviewRecords)){
  for(const row of reviewRecords.slice(0,200)){
   if(!exact(row,REVIEW)||!ID.test(row?.login??'')||
     !Number.isSafeInteger(row.id)||row.id<1||
     !Number.isFinite(stamp(row.submittedAt))||stamp(row.submittedAt)>time+300000||
     !['APPROVED','CHANGES_REQUESTED','DISMISSED','COMMENTED'].includes(row.state)){
    errors.add('CG_MALFORMED_GITHUB_REVIEW_EVENT');continue;
   }
   const prior=latest.get(row.login);
   if(!prior||stamp(row.submittedAt)>stamp(prior.submittedAt)||
     (row.submittedAt===prior.submittedAt&&row.id>prior.id))
    latest.set(row.login,row);
  }
 }
 for(const role of REVIEW_ROLES){
  const login=reviewerAssignments?.[role],row=latest.get(login);
  if(!row||row.login===AUTHOR||row.state!=='APPROVED'||
     row.commitSha!==envelope?.body?.sourceHeadSha||
     stamp(row.submittedAt)<=stamp(context?.lastPushAt)||
     !Array.isArray(githubObservation?.reviews?.observedApproverLogins)||
     !githubObservation.reviews.observedApproverLogins.includes(login))
   errors.add('CG_LATEST_NONAUTHOR_GITHUB_REVIEW_MISSING_OR_STALE_'+role);
 }
 return result(errors);
}
function readBounded(path){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>262144)
  throw Error('CG missing or oversized unsigned local HOLD source');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CG only accepts zero-input --ci-hold');
 const envelope=readBounded('phase1cc-unsigned-source-receipt-hold.json');
 const cf=readBounded('phase1cf-zero-input-review-history-hold.json');
 const env=process.env;
 if(!verifyUnsignedEnvelopeDigest(envelope)||
    envelope.localSourceAndArtifactsConsistent!==true||
    cf.phase!=='1CF'||cf.localSignedChainMathematicallyConsistent!==false||
    cf.productionReleaseAuthorized!==false||cf.releaseDecision!=='HOLD'||
    env.CI!=='true'||env.GITHUB_ACTIONS!=='true'||
    env.GITHUB_REPOSITORY!==REPO||env.GITHUB_JOB!=='build-input-provenance'||
    env.GITHUB_SHA!==envelope.body?.checkedOutSha||
    env.GITHUB_EVENT_NAME!==envelope.body?.githubEventName||
    env.GITHUB_REF!==envelope.body?.githubRef)
  throw Error('CG GitHub context / upstream receipt cannot authenticate source');
 const verdict=assessExternalSourceReconciliation({envelope});
 writeFileSync('phase1cg-zero-input-external-reconciliation-hold.json',
  JSON.stringify(verdict,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(verdict,null,2));
 if(verdict.candidateSourceAndReviewerObservationsConsistent||
    verdict.productionReleaseAuthorized||verdict.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(error){
  console.error('CG independently trusted source HOLD failed:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 }
}
