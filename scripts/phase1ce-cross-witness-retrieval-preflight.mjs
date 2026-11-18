import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyUnsignedEnvelopeDigest} from './phase1cc-ci-evidence-envelope.mjs';
import {phase1BbVerifyConsistencyProof} from './lib/phase1BbWitnessConsistency.mjs';

// 1CE: OFFLINE consistency preflight for TWO supplied candidate witness keys,
// an append-only log proof and supplied retrieved object bytes. Never trust a
// self-supplied enrollment, TLS claim, checkpoint anchor or WORM retrieval as
// independently authenticated. No network, external credentials or release.
export const REPOSITORY='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const WITNESS_DOMAIN='aaditech/phase1ce/cross-witness-signed-checkpoint/v1\n';
const SHA=/^[0-9a-f]{40}$/;
const DIGEST=/^[0-9a-f]{64}$/;
const REF=/^[a-z][a-z0-9_-]{5,63}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const BASE64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RETRIEVAL_MAX_BYTES=262144;
const MAX_RECEIPT_BYTES=262144;
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const hash=b=>createHash('sha256').update(b).digest('hex');
const exact=(x,keys)=>obj(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const requiredStatement=Object.freeze(['schemaVersion','purpose','witnessRef','keyId',
 'organizationRef','administratorRef','repository','sourceHeadSha',
 'checkedOutSha','envelopeSha256','ciRunId','runAttempt','challengeNonce',
 'logRef','previousSequence','sequence','previousDigest','oldTreeSize',
 'oldRootSha256','treeSize','rootSha256','artifactVersionId',
 'artifactSha256','retrievalNonce','observedAt','expiresAt']);
const requiredAuthority=Object.freeze(['witnessRef','keyId','organizationRef',
 'administratorRef','publicKeyPem','spkiSha256','enrolledAt','expiresAt','revoked']);
const requiredAnchor=Object.freeze(['sequence','lastDigest','treeSize','rootSha256']);
const requiredRetrieval=Object.freeze(['schemaVersion','objectPath',
 'objectVersionId','repository','sourceHeadSha','checkedOutSha',
 'retrievalNonce','retrievedAt','contentLength','contentSha256','bodyBase64']);
function canonical(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')
  return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(obj(value))return '{'+Object.keys(value).sort().map(k=>
  JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 throw Error('CE noncanonical candidate field');
}
export function witnessSigningBytes(statement){
 if(!obj(statement)||JSON.stringify(statement).length>8192)
  throw Error('CE missing or oversized checkpoint statement');
 return Buffer.from(WITNESS_DOMAIN+canonical(statement),'utf8');
}
const timestamp=value=>{
 if(typeof value!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value))
  return NaN;
 const t=Date.parse(value);
 return Number.isFinite(t)&&new Date(t).toISOString()===value?t:NaN;
};
function isSignatureValid(statement,signatureBase64,authority){
 if(typeof signatureBase64!=='string'||!SIG.test(signatureBase64)||
    typeof authority?.publicKeyPem!=='string'||authority.publicKeyPem.length>4096||
    !DIGEST.test(authority.spkiSha256??''))return false;
 try{
  const decoded=Buffer.from(signatureBase64,'base64');
  if(decoded.length!==64||decoded.toString('base64')!==signatureBase64)return false;
  const key=createPublicKey(authority.publicKeyPem);
  return key.asymmetricKeyType==='ed25519'&&
    hash(key.export({type:'spki',format:'der'}))===authority.spkiSha256&&
    verify(null,witnessSigningBytes(statement),key,decoded);
 }catch{return false;}
}
function checkRetrievedCandidate({retrieval,envelope,context,now}){
 const anomalies=[];
 if(!exact(retrieval,requiredRetrieval)){
  anomalies.push('CE_RETRIEVAL_METADATA_UNBOUNDED_OR_MALFORMED');
  return {anomalies,digest:null,version:null};
 }
 if(retrieval.schemaVersion!==1||
    retrieval.repository!==REPOSITORY||
    retrieval.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    retrieval.checkedOutSha!==envelope?.body?.checkedOutSha||
    retrieval.retrievalNonce!==context?.retrievalNonce||
    !REF.test(retrieval.objectVersionId??'')||
    typeof retrieval.objectPath!=='string'||
    !/^custody\/[a-zA-Z0-9_/-]{1,160}\.json$/.test(retrieval.objectPath)||
    !Number.isFinite(timestamp(retrieval.retrievedAt))||
    timestamp(retrieval.retrievedAt)>now+300000||
    timestamp(retrieval.retrievedAt)<now-900000)
  anomalies.push('CE_RETRIEVAL_OBJECT_SOURCE_NONCE_OR_FRESHNESS_MISMATCH');
 let digest=null;
 if(!Number.isSafeInteger(retrieval.contentLength)||
   retrieval.contentLength<1||retrieval.contentLength>RETRIEVAL_MAX_BYTES||
   !DIGEST.test(retrieval.contentSha256??'')||
   typeof retrieval.bodyBase64!=='string'||
   retrieval.bodyBase64.length>Math.ceil(RETRIEVAL_MAX_BYTES/3)*4+4||
   !BASE64.test(retrieval.bodyBase64)){
  anomalies.push('CE_RETRIEVED_BYTES_OVERSIZED_OR_UNSAFE');
 }else{
  try{
   const bytes=Buffer.from(retrieval.bodyBase64,'base64');
   digest=hash(bytes);
   if(!bytes.length||bytes.length!==retrieval.contentLength||
      bytes.length>RETRIEVAL_MAX_BYTES||
      bytes.toString('base64')!==retrieval.bodyBase64||
      digest!==retrieval.contentSha256)
    anomalies.push('CE_RETRIEVED_BYTES_LENGTH_OR_SHA256_MISMATCH');
   const parsed=JSON.parse(bytes.toString('utf8'));
   if(!verifyUnsignedEnvelopeDigest(parsed)||
      parsed.envelopeSha256!==envelope?.envelopeSha256||
      canonical(parsed)!==canonical(envelope))
    anomalies.push('CE_RETRIEVED_ENVELOPE_SUBSTITUTION');
  }catch{anomalies.push('CE_RETRIEVED_JSON_OR_CANONICAL_PAYLOAD_INVALID');}
 }
 return {anomalies,digest,version:retrieval.objectVersionId};
}
export function assessCrossWitnessRetrieval({
 envelope,context={},witnesses=[],authorities={},anchors={},
 consistencyProofSha256=[],retrieval=null,now='2026-11-18T13:30:00.000Z'
}={}){
 const errors=new Set();
 const nowMs=timestamp(now);
 if(!Number.isFinite(nowMs))errors.add('CE_INVALID_VERIFICATION_CLOCK');
 if(!obj(envelope)||!verifyUnsignedEnvelopeDigest(envelope)||
   envelope.localSourceAndArtifactsConsistent!==true||
   envelope.body?.kind!=='UNSIGNED_SOURCE_BOUND_CI_RECEIPT'||
   envelope.body?.phase!=='1CC'||envelope.body?.repository!==REPOSITORY||
   envelope.body?.sourceAndReceiptAnomalyCodes?.length!==0||
   !SHA.test(envelope.body?.sourceHeadSha??'')||
   !SHA.test(envelope.body?.checkedOutSha??'')||
   envelope.body?.globalZeroCriticalHighAuditPassed!==false)
  errors.add('CE_LOCAL_CI_ENVELOPE_TAMPER_OR_RELEASE_CLAIM');
 if(!obj(context)||context.ciJobId!=='build-input-provenance'||
   !Number.isSafeInteger(context.ciRunId)||context.ciRunId<1||
   !Number.isSafeInteger(context.runAttempt)||context.runAttempt<1||
   !DIGEST.test(context.challengeNonce??'')||
   context.challengeNonce==='0'.repeat(64)||
   !DIGEST.test(context.retrievalNonce??'')||
   context.retrievalNonce==='0'.repeat(64)||
   !REF.test(context.logRef??''))
  errors.add('CE_MISSING_INDEPENDENT_RUN_AND_RETRIEVAL_CHALLENGE');
 if(!Array.isArray(witnesses)||witnesses.length!==2||
   !obj(authorities)||Object.keys(authorities).length!==2||
   !obj(anchors)||Object.keys(anchors).length!==2)
  errors.add('CE_INDEPENDENT_WITNESS_QUORUM_UNAVAILABLE');
 if(!Array.isArray(consistencyProofSha256)||consistencyProofSha256.length>64||
   consistencyProofSha256.some(x=>!DIGEST.test(x)))
  errors.add('CE_MERKLE_CONSISTENCY_PATH_MALFORMED');
 const retrievalAssessment=checkRetrievedCandidate({
  retrieval,envelope,context,now:nowMs
 });
 for(const code of retrievalAssessment.anomalies)errors.add(code);
 const pair=Array.isArray(witnesses)?witnesses.slice(0,2):[];
 const unique={witness:new Set(),organization:new Set(),admin:new Set(),key:new Set()};
 let firstHead=null,previousHead=null,checked=0;
 for(const entry of pair){
  const s=entry?.statement;
  if(!obj(entry)||!exact(s,requiredStatement)||!REF.test(s?.witnessRef??'')){
   errors.add('CE_UNRECOGNIZED_OR_MALFORMED_SIGNED_HEAD');
   continue;
  }
  const a=authorities?.[s.witnessRef],anchor=anchors?.[s.witnessRef];
  if(!exact(a,requiredAuthority)||a.witnessRef!==s.witnessRef||
    a.keyId!==s.keyId||a.organizationRef!==s.organizationRef||
    a.administratorRef!==s.administratorRef||
    !REF.test(s.organizationRef??'')||!REF.test(s.administratorRef??'')||
    !REF.test(s.keyId??'')||a.revoked!==false||
    !Number.isFinite(timestamp(a.enrolledAt))||
    !Number.isFinite(timestamp(a.expiresAt))||
    timestamp(a.enrolledAt)>timestamp(s.observedAt)||
    timestamp(a.expiresAt)<timestamp(s.expiresAt)||
    s.organizationRef==='j9619655391-max'){
   errors.add('CE_SUPPLIED_WITNESS_ENROLLMENT_OR_REVOCATION_INVALID');
   continue;
  }
  const observed=timestamp(s.observedAt),expires=timestamp(s.expiresAt);
  if(s.schemaVersion!==1||s.purpose!=='AUDITED_APPEND_ONLY_HEAD'||
    s.repository!==REPOSITORY||s.sourceHeadSha!==envelope?.body?.sourceHeadSha||
    s.checkedOutSha!==envelope?.body?.checkedOutSha||
    s.envelopeSha256!==envelope?.envelopeSha256||
    s.ciRunId!==context?.ciRunId||s.runAttempt!==context?.runAttempt||
    s.challengeNonce!==context?.challengeNonce||
    s.logRef!==context?.logRef||s.retrievalNonce!==context?.retrievalNonce||
    s.artifactVersionId!==retrievalAssessment.version||
    s.artifactSha256!==retrievalAssessment.digest||
    !Number.isFinite(observed)||!Number.isFinite(expires)||
    observed>nowMs+300000||observed<nowMs-900000||
    expires<=nowMs||expires<=observed||expires-observed>900000)
   errors.add('CE_SIGNED_HEAD_CONTEXT_SOURCE_OR_FRESHNESS_DRIFT');
  if(!exact(anchor,requiredAnchor)||
    !Number.isSafeInteger(anchor.sequence)||anchor.sequence<0||
    anchor.sequence>=Number.MAX_SAFE_INTEGER||
    !DIGEST.test(anchor.lastDigest??'')||
    !Number.isSafeInteger(anchor.treeSize)||anchor.treeSize<1||
    !DIGEST.test(anchor.rootSha256??'')||
    !Number.isSafeInteger(s.previousSequence)||
    s.previousSequence!==anchor.sequence||
    !Number.isSafeInteger(s.sequence)||s.sequence!==anchor.sequence+1||
    s.previousDigest!==anchor.lastDigest||
    s.oldTreeSize!==anchor.treeSize||
    s.oldRootSha256!==anchor.rootSha256)
   errors.add('CE_REPLAY_FORK_OR_ROLLBACK_VS_SUPPLIED_ANCHOR');
  const old=s.oldTreeSize+'|'+s.oldRootSha256;
  const head=s.treeSize+'|'+s.rootSha256;
  if(previousHead!==null&&previousHead!==old)
   errors.add('CE_CROSS_WITNESS_PREVIOUS_HEAD_EQUIVOCATION');
  if(firstHead!==null&&firstHead!==head)
   errors.add('CE_CROSS_WITNESS_CURRENT_HEAD_EQUIVOCATION');
  previousHead=previousHead??old;firstHead=firstHead??head;
  if(!Number.isSafeInteger(s.oldTreeSize)||!Number.isSafeInteger(s.treeSize)||
    s.oldTreeSize<1||s.treeSize<s.oldTreeSize||s.treeSize>1000000000||
    !DIGEST.test(s.oldRootSha256??'')||!DIGEST.test(s.rootSha256??''))
   errors.add('CE_MERKLE_TREE_HEAD_INVALID');
  else{
   try{
    if(!phase1BbVerifyConsistencyProof({
      oldSize:s.oldTreeSize,newSize:s.treeSize,
      oldRootSha256:s.oldRootSha256,newRootSha256:s.rootSha256,
      proofSha256:consistencyProofSha256
    }))errors.add('CE_RFC6962_APPEND_ONLY_PROOF_REJECTED');
   }catch{errors.add('CE_RFC6962_APPEND_ONLY_PROOF_REJECTED');}
  }
  if(unique.witness.has(s.witnessRef)||unique.organization.has(s.organizationRef)||
    unique.admin.has(s.administratorRef)||unique.key.has(s.keyId))
   errors.add('CE_WITNESS_OR_ORGANIZATION_ADMIN_KEY_REUSED');
  unique.witness.add(s.witnessRef);unique.organization.add(s.organizationRef);
  unique.admin.add(s.administratorRef);unique.key.add(s.keyId);
  if(!isSignatureValid(s,entry.signatureBase64,a))
   errors.add('CE_DETACHED_SIGNATURE_OR_PINNED_SPKI_INVALID');
  else checked++;
 }
 if(unique.witness.size!==2||unique.organization.size!==2||
    unique.admin.size!==2||unique.key.size!==2)
  errors.add('CE_TWO_DISTINCT_WITNESS_ADMINISTRATIONS_NOT_ESTABLISHED');
 // Candidate bytes, source keys and supplied anchors can all be forged by one
 // submitter. No caller-controlled material establishes real external trust.
 return Object.freeze({
  phase:'1CE',schemaVersion:1,
  kind:'UNTRUSTED_TWO_WITNESS_MERKLE_AND_RETRIEVAL_PREFLIGHT',
  candidateSignedHeadsMathematicallyConsistent:errors.size===0,
  verifiedSuppliedSignatureCount:checked,
  receivedCandidateWitnessCount:pair.length,
  observedCurrentHead:firstHead,
  observedPreviousHead:previousHead,
  suppliedRetrievedBytesSha256:retrievalAssessment.digest,
  observedVersionId:retrievalAssessment.version,
  anomalyCodes:Object.freeze([...errors].sort()),
  outOfBandWitnessEnrollmentsAuthenticated:false,
  independentLogPublisherIdentityVerified:false,
  authenticatedWitnessHighWatermarksTrusted:false,
  externallyWitnessedAntiEquivocationOrMonotonicity:false,
  officialWormObjectVersionApiResponseVerified:false,
  retrievalTlsPeerAndStorageProviderVerified:false,
  objectLockDeniedDeletionAndRetentionVerified:false,
  independentlyRecoveredDrBytesVerified:false,
  independentSourceCIWorkloadIdentityVerified:false,
  independentSecurityBusinessLegalOwnerApprovalsVerified:false,
  globalZeroCriticalHighAuditPassed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function readBounded(path,max){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>max)
  throw Error('CE missing, symlink or oversized local hold report');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CE accepts only zero-input --ci-hold');
 const envelope=readBounded('phase1cc-unsigned-source-receipt-hold.json',MAX_RECEIPT_BYTES);
 const cd=readBounded('phase1cd-zero-input-external-custody-hold.json',MAX_RECEIPT_BYTES);
 if(cd.phase!=='1CD'||cd.submittedExternalClaimCount!==0||
    cd.candidateSignaturesAndClaimChainsLocallyConsistent!==false||
    cd.productionReleaseAuthorized!==false||cd.releaseDecision!=='HOLD')
  throw Error('CE cannot bootstrap external custody from self-supplied CI claims');
 const env=process.env;
 if(env.CI!=='true'||env.GITHUB_ACTIONS!=='true'||
   env.GITHUB_REPOSITORY!==REPOSITORY||
   env.GITHUB_JOB!=='build-input-provenance'||
   env.GITHUB_SHA!==envelope.body?.checkedOutSha||
   env.GITHUB_EVENT_NAME!==envelope.body?.githubEventName||
   env.GITHUB_REF!==envelope.body?.githubRef)
  throw Error('CE hosted GitHub context does not match source-bound envelope');
 const verdict=assessCrossWitnessRetrieval({envelope});
 writeFileSync('phase1ce-zero-input-cross-witness-hold.json',
  JSON.stringify(verdict,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(verdict,null,2));
 if(!verifyUnsignedEnvelopeDigest(envelope)||
    envelope.localSourceAndArtifactsConsistent!==true||
    verdict.receivedCandidateWitnessCount!==0||
    verdict.candidateSignedHeadsMathematicallyConsistent||
    verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||verdict.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(error){
  console.error('CE two-witness retrieval HARD HOLD failed:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 }
}
