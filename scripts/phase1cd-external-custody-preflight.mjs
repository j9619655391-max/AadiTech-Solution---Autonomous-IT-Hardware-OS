import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyUnsignedEnvelopeDigest} from './phase1cc-ci-evidence-envelope.mjs';

// 1CD: cryptographically check CANDIDATE records with caller-supplied keys
// and checkpoints. Key enrollment, trusted monotonic state, external WORM,
// OIDC workload identity and restoration are NOT independently authenticated.
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
export const ROLES=Object.freeze(['CI_ATTESTOR','WORM_AUDITOR','DR_AUDITOR']);
export const DOMAIN='aaditech/phase1cd/detached-independent-custody-claim/v1\n';
const DIGEST=/^[0-9a-f]{64}$/;
const SHA=/^[0-9a-f]{40}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const hash=x=>createHash('sha256').update(x).digest('hex');
const zero='0'.repeat(64);
const baseKeys=Object.freeze([
 'schemaVersion','type','issuerId','repository','sourceHeadSha',
 'checkedOutSha','envelopeSha256','ciRunId','ciJobId','runAttempt',
 'challengeNonce','sequence','previousDigest','issuedAt','expiresAt'
]);
const extraKeys=Object.freeze({
 CI_ATTESTOR:['githubWorkflowPath','oidcIssuer','oidcSubject','subjectDigest'],
 WORM_AUDITOR:['attestorClaimDigest','bucketArn','objectKey','objectVersionId',
   'objectLockMode','retentionUntil','storedEnvelopeDigest','primaryRegion',
   'deleteDeniedObserved'],
 DR_AUDITOR:['wormClaimDigest','restoredVersionId','restoredEnvelopeDigest',
   'restoreCheckedAt','recoveryRegion']
});
function canonical(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')
  return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(object(value))return '{'+Object.keys(value).sort().map(k=>
  JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 throw Error('CD unsupported signed claim type');
}
export function signingPayload(statement){
 if(!object(statement)||JSON.stringify(statement).length>8192)
  throw Error('CD missing or oversized signed claim');
 return Buffer.from(DOMAIN+canonical(statement),'utf8');
}
const date=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
function strictKeys(x,keys){
 return object(x)&&Object.keys(x).length===keys.length&&
  keys.every(k=>Object.hasOwn(x,k));
}
function signatureBytes(value){
 if(typeof value!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(value))return null;
 const b=Buffer.from(value,'base64');
 return b.length===64&&b.toString('base64')===value?b:null;
}
function checkStatement({s,role,context,envelope,anchor,now,accepted}){
 if(!object(s)||!object(envelope?.body))
  return ['CD_CLAIM_CONTEXT_OR_SCHEMA_'+role];
 const issues=[];
 if(!strictKeys(s,[...baseKeys,...extraKeys[role]])||
    s.schemaVersion!==1||s.type!==role||
    s.issuerId!==context.issuerIds?.[role]||
    s.repository!==REPO||s.sourceHeadSha!==envelope.body.sourceHeadSha||
    s.checkedOutSha!==envelope.body.checkedOutSha||
    s.envelopeSha256!==envelope.envelopeSha256||
    s.ciRunId!==context.ciRunId||s.ciJobId!==context.ciJobId||
    s.runAttempt!==context.runAttempt||
    s.challengeNonce!==context.challengeNonce)
  issues.push('CD_CLAIM_CONTEXT_OR_SCHEMA_'+role);
 const issued=date(s?.issuedAt),expires=date(s?.expiresAt);
 if(!Number.isFinite(issued)||!Number.isFinite(expires)||
    issued>now+300000||issued<now-900000||
    expires<=now||expires<=issued||expires-issued>900000)
  issues.push('CD_CLAIM_EXPIRED_OR_FUTURE_'+role);
 if(!object(anchor)||!Number.isSafeInteger(anchor.sequence)||
   anchor.sequence<0||anchor.sequence>=Number.MAX_SAFE_INTEGER||
   !DIGEST.test(anchor.lastDigest??'')||
   !Number.isSafeInteger(s?.sequence)||
   s.sequence!==anchor.sequence+1||
   s.previousDigest!==anchor.lastDigest)
  issues.push('CD_REPLAY_ROLLBACK_OR_GAP_'+role);
 if(role==='CI_ATTESTOR'){
  const expectedSubject=envelope.body.githubEventName==='pull_request'?
   'repo:'+REPO+':pull_request':
   'repo:'+REPO+':ref:refs/heads/'+DEV;
  if(s.githubWorkflowPath!=='.github/workflows/ci.yml'||
     s.oidcIssuer!=='https://token.actions.githubusercontent.com'||
     s.oidcSubject!==expectedSubject||
     s.subjectDigest!==envelope.envelopeSha256)
   issues.push('CD_OIDC_SOURCE_SUBJECT_NOT_BOUND');
 }
 if(role==='WORM_AUDITOR'){
  if(s.attestorClaimDigest!==accepted.CI_ATTESTOR||
    !/^arn:aws:s3:::[a-z0-9][a-z0-9.-]{2,62}$/.test(s.bucketArn??'')||
    typeof s.objectKey!=='string'||!/^custody\/[A-Za-z0-9/_-]{1,180}\.json$/.test(s.objectKey)||
    typeof s.objectVersionId!=='string'||
    !/^[A-Za-z0-9._=-]{4,180}$/.test(s.objectVersionId)||
    s.objectLockMode!=='COMPLIANCE'||
    !Number.isFinite(date(s.retentionUntil))||
    date(s.retentionUntil)<now+30*86400000||
    s.storedEnvelopeDigest!==envelope.envelopeSha256||
    !/^[a-z]{2}-[a-z]+-\d$/.test(s.primaryRegion??'')||
    s.deleteDeniedObserved!==true)
   issues.push('CD_WORM_VERSION_LOCK_RETENTION_OR_CI_LINK_INVALID');
 }
 if(role==='DR_AUDITOR'){
  const worm=accepted.wormStatement;
  if(!worm||s.wormClaimDigest!==accepted.WORM_AUDITOR||
    s.restoredVersionId!==worm.objectVersionId||
    s.restoredEnvelopeDigest!==envelope.envelopeSha256||
    !Number.isFinite(date(s.restoreCheckedAt))||
    date(s.restoreCheckedAt)<date(worm.issuedAt)||
    date(s.restoreCheckedAt)>now+300000||
    s.recoveryRegion===worm.primaryRegion||
    !/^[a-z]{2}-[a-z]+-\d$/.test(s.recoveryRegion??''))
   issues.push('CD_DR_RETRIEVAL_VERSION_OR_WITNESS_INVALID');
 }
 return issues;
}
export function assessIndependentCustody({
 envelope,context={},enrollments={},checkpoints={},proofs=[],
 now='2026-11-18T12:00:00.000Z'
}={}){
 const errors=new Set();
 const nowMs=date(now);
 if(!Number.isFinite(nowMs))errors.add('CD_INVALID_VERIFICATION_CLOCK');
 if(!object(envelope)||!verifyUnsignedEnvelopeDigest(envelope)||
   envelope.localSourceAndArtifactsConsistent!==true||
   envelope.body?.phase!=='1CC'||
   envelope.body?.kind!=='UNSIGNED_SOURCE_BOUND_CI_RECEIPT'||
   envelope.body?.repository!==REPO||
   envelope.body?.sourceAndReceiptAnomalyCodes?.length!==0||
   !SHA.test(envelope.body?.sourceHeadSha??'')||
   !SHA.test(envelope.body?.checkedOutSha??'')||
   !DIGEST.test(envelope.body?.selectedInputBundleSha256??'')||
   envelope.body?.unsignedGithubArtifactOnly!==true||
   envelope.body?.globalZeroCriticalHighAuditPassed!==false)
  errors.add('CD_CI_SOURCE_ENVELOPE_UNTRUSTED_OR_TAMPERED');
 if(!object(context)||!Number.isSafeInteger(context.ciRunId)||
   context.ciRunId<1||context.ciJobId!=='build-input-provenance'||
   !Number.isSafeInteger(context.runAttempt)||context.runAttempt<1||
   !DIGEST.test(context.challengeNonce??'')||
   context.challengeNonce===zero||
   !object(context.issuerIds)||
   ROLES.some(role=>typeof context.issuerIds[role]!=='string'||
     !/^[A-Za-z0-9_-]{4,72}$/.test(context.issuerIds[role]))||
   new Set(ROLES.map(role=>context.issuerIds?.[role])).size!==ROLES.length)
  errors.add('CD_UNTRUSTED_RUN_CONTEXT_CHALLENGE_OR_ROLE_ASSIGNMENT');
 if(!Array.isArray(proofs)||proofs.length>ROLES.length||
    !object(enrollments)||Object.keys(enrollments).length>ROLES.length||
    !object(checkpoints)||Object.keys(checkpoints).length>ROLES.length)
  errors.add('CD_OVERSIZED_OR_MALFORMED_CUSTODY_PACKET');
 const received=Array.isArray(proofs)?proofs.slice(0,ROLES.length):[];
 const usedIds=new Set(),usedOrgs=new Set(),accepted={};
 for(const role of ROLES){
  const items=received.filter(x=>x?.statement?.type===role);
  if(items.length!==1){
   errors.add(items.length?'CD_DUPLICATE_WITNESS_'+role:
     'CD_MISSING_OUT_OF_BAND_WITNESS_'+role);
   continue;
  }
  const record=items[0],s=record.statement;
  const authority=enrollments?.[role],anchor=checkpoints?.[role];
  for(const issue of checkStatement({
   s,role,context,envelope,anchor,now:nowMs,accepted
  }))errors.add(issue);
  const enrollmentValid=object(authority)&&
   strictKeys(authority,['role','issuerId','organization','publicKeyPem',
     'spkiSha256','validFrom','validUntil','revoked'])&&
   authority.role===role&&authority.issuerId===s.issuerId&&
   authority.issuerId===context.issuerIds?.[role]&&
   typeof authority.organization==='string'&&
   /^[A-Za-z0-9._-]{4,100}$/.test(authority.organization)&&
   !usedIds.has(authority.issuerId)&&!usedOrgs.has(authority.organization)&&
   authority.organization!=='j9619655391-max'&&
   authority.revoked===false&&
   DIGEST.test(authority.spkiSha256??'')&&
   Number.isFinite(date(authority.validFrom))&&
   Number.isFinite(date(authority.validUntil))&&
   date(authority.validFrom)<=date(s.issuedAt)&&
   date(authority.validUntil)>=date(s.expiresAt)&&
   typeof authority.publicKeyPem==='string'&&
   authority.publicKeyPem.length<4096;
  if(!enrollmentValid){
   errors.add('CD_ROLE_ENROLLMENT_OR_KEY_LIFECYCLE_INVALID_'+role);
   continue;
  }
  usedIds.add(authority.issuerId);
  usedOrgs.add(authority.organization);
  if(record.algorithm!=='Ed25519'||!signatureBytes(record.signature)){
   errors.add('CD_INVALID_DETACHED_SIGNATURE_FORMAT_'+role);continue;
  }
  try{
   const key=createPublicKey(authority.publicKeyPem);
   if(key.asymmetricKeyType!=='ed25519'||
      hash(key.export({type:'spki',format:'der'}))!==authority.spkiSha256||
      !verify(null,signingPayload(s),key,signatureBytes(record.signature))){
    errors.add('CD_SIGNATURE_OR_OUT_OF_BAND_KEY_MISMATCH_'+role);
    continue;
   }
  }catch{
   errors.add('CD_UNVERIFIABLE_EXTERNAL_CUSTODY_SIGNATURE_'+role);continue;
  }
  // The matched signature is only mathematical, with a SUPPLIED keyring.
  // Re-used signed records must also satisfy a genuine independently
  // authenticated external checkpoint, which this program never establishes.
  accepted[role]=hash(signingPayload(s));
  if(role==='WORM_AUDITOR')accepted.wormStatement=s;
 }
 if(received.length!==ROLES.length)
  errors.add('CD_CUSTODY_SIGNER_QUORUM_INCOMPLETE');
 const mathematicallyConsistent=errors.size===0;
 return Object.freeze({
  schemaVersion:1,phase:'1CD',
  kind:'OUT_OF_BAND_SIGNER_AND_WORM_DR_PREREQUISITES_HOLD',
  selectedCiEnvelopeSha256:DIGEST.test(envelope?.envelopeSha256??'')?
   envelope.envelopeSha256:null,
  submittedExternalClaimCount:received.length,
  candidateSignaturesAndClaimChainsLocallyConsistent:mathematicallyConsistent,
  acceptedSuppliedClaimCount:ROLES.filter(r=>typeof accepted[r]==='string').length,
  expectedRoles:ROLES,
  anomalyCodes:Object.freeze([...errors].sort()),
  outOfBandAuthorityEnrollmentAuthenticated:false,
  trustedRevocationFreshnessIndependentlyVerified:false,
  monotonicCheckpointExternallyWitnessed:false,
  antiEquivocationExternalJournalVerified:false,
  githubOidcJwtIssuerSignatureAndSubjectVerified:false,
  ciWorkloadBinaryIndependentlyAttested:false,
  realS3ObjectLockVersionRetentionIndependentlyVerified:false,
  realDeniedDeletionAndLegalHoldIndependentlyWitnessed:false,
  offsiteDrRestorationIndependentlyVerified:false,
  independentSecurityAndBusinessApprovalsVerified:false,
  globallyCleanZeroCriticalHighAuditPassed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CD supports zero-input --ci-hold only, no secrets or external signing');
 const path='phase1cc-unsigned-source-receipt-hold.json',st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>262144)
  throw Error('CD unsafe local source envelope');
 const envelope=JSON.parse(readFileSync(path,'utf8'));
 const env=process.env;
 if(env.CI!=='true'||env.GITHUB_ACTIONS!=='true'||
    env.GITHUB_REPOSITORY!==REPO||
    env.GITHUB_JOB!=='build-input-provenance'||
    env.GITHUB_SHA!==envelope.body?.checkedOutSha||
    env.GITHUB_EVENT_NAME!==envelope.body?.githubEventName||
    env.GITHUB_REF!==envelope.body?.githubRef)
  throw Error('CD observed GitHub CI job/source context mismatch');
 const run=Number(env.GITHUB_RUN_ID),attempt=Number(env.GITHUB_RUN_ATTEMPT);
 if(!Number.isSafeInteger(run)||run<1||
    !Number.isSafeInteger(attempt)||attempt<1)
  throw Error('CD GitHub run ID or attempt missing/invalid');
 const context={ciRunId:run,ciJobId:env.GITHUB_JOB,runAttempt:attempt,
  // A zero challenge denotes NOT enrolled. It intentionally cannot pass
  // any external claim checks. Real unpredictable challenge: independent issuer.
  challengeNonce:zero,issuerIds:{}};
 const result=assessIndependentCustody({envelope,context});
 writeFileSync('phase1cd-zero-input-external-custody-hold.json',
  JSON.stringify(result,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(result,null,2));
 if(!verifyUnsignedEnvelopeDigest(envelope)||
    envelope.localSourceAndArtifactsConsistent!==true||
    result.submittedExternalClaimCount!==0||
    result.candidateSignaturesAndClaimChainsLocallyConsistent||
    result.productionReleaseAuthorized||
    result.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(err){
  console.error('CD independent custody zero-input HARD HOLD failed:',
   err instanceof Error?err.message:'Unknown');
  process.exitCode=1;
 }
}
