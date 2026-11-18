import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// 1BX: cryptographic prerequisites for OUT-OF-BAND enrolled authorities.
// A successful signature against caller-supplied keys is NOT authentication of
// the claimed real issuer. CI deliberately has no external keys or approvals.
export const EXPECTED_REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const EXPECTED_BASE='main';
export const EXPECTED_PR=1;
export const EVIDENCE_TYPES=Object.freeze({
 'branch-ruleset':'REPOSITORY_ADMIN',
 'security-review':'SECURITY_REVIEWER',
 'business-review':'BUSINESS_OWNER',
 'ci-provenance':'CI_ATTESTOR',
 'external-worm-receipt':'WORM_AUDITOR'
});
export const REQUIRED_RULESET_CONTROLS=Object.freeze([
 'preventDirectPush','preventForcePush','preventDeletion','requirePullRequest',
 'dismissStaleReviews','requireApprovalOfMostRecentPush','requireCodeOwnerReview',
 'requireConversationResolution','forbidBypassForAdmins'
]);
const domain='aaditech/phase1bx/detached-ed25519-evidence/v1\n';
const sha256=s=>createHash('sha256').update(s).digest('hex');
const shaPattern=/^[0-9a-f]{40}$/;
const hashPattern=/^[0-9a-f]{64}$/;
const noncePattern=/^[0-9a-f]{64}$/;
const base64Pattern=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
function canonical(value){
 if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(object(value))return '{'+Object.keys(value).sort().map(k=>
  JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 throw Error('BX evidence has unsupported types or numbers');
}
export function signingPayload(statement){
 if(!object(statement)||JSON.stringify(statement).length>8192)
  throw Error('BX invalid or oversized signed statement');
 return Buffer.from(domain+canonical(statement),'utf8');
}
function base64Signature(value){
 if(typeof value!=='string'||!base64Pattern.test(value)||value.length>1024)
  return null;
 const decoded=Buffer.from(value,'base64');
 return decoded.length===64&&decoded.toString('base64')===value?decoded:null;
}
function parseRfc3339(value){
 if(typeof value!=='string'||!/^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value))
  return NaN;
 const date=Date.parse(value);
 return Number.isFinite(date)&&new Date(date).toISOString()===value?date:NaN;
}
function expectedTarget(target){
 return object(target)&&target.repository===EXPECTED_REPO&&
  target.baseBranch===EXPECTED_BASE&&target.prNumber===EXPECTED_PR&&
  typeof target.prAuthor==='string'&&target.prAuthor.length>0&&
  shaPattern.test(target.developmentHead??'')&&shaPattern.test(target.baseSha??'')&&
  shaPattern.test(target.prMergeCheckoutSha??'')&&
  noncePattern.test(target.challengeNonce??'')&&
  hashPattern.test(target.ciInputBundleSha256??'')&&
  target.productionReleaseAuthorized===false;
}
export function assessExternalGovernanceEvidence({
 target,authorities={},evidence=[],now='2026-11-18T09:00:00.000Z'
}={}){
 const anomalies=new Set();
 if(!expectedTarget(target))anomalies.add('BX_INVALID_EXACT_HEAD_AND_CHALLENGE_TARGET');
 const nowMs=parseRfc3339(now);
 if(!Number.isFinite(nowMs))anomalies.add('BX_INVALID_REVIEW_CLOCK');
 if(!object(authorities)||Object.keys(authorities).length>12)
  anomalies.add('BX_MISSING_OR_OVERSIZED_OUT_OF_BAND_KEYRING');
 if(!Array.isArray(evidence)||evidence.length>12)
  anomalies.add('BX_MALFORMED_OR_OVERSIZED_EVIDENCE_SET');
 const submitted=Array.isArray(evidence)?evidence.slice(0,12):[];
 const accepted=new Map(),usedKeyIds=new Set(),usedIdentity=new Set();
 for(const item of submitted){
  if(!object(item)||!object(item.statement)){
   anomalies.add('BX_MALFORMED_SIGNED_RECORD');continue;
  }
  const s=item.statement;
  const requiredRole=EVIDENCE_TYPES[s.type];
  if(!requiredRole){
   anomalies.add('BX_UNKNOWN_EVIDENCE_TYPE');continue;
  }
  if(accepted.has(s.type)){
   anomalies.add('BX_REPLAY_OR_DUPLICATE_EVIDENCE_TYPE_'+s.type);continue;
  }
  if(!expectedTarget(target)||
     s.schemaVersion!==1||s.type!==s.type||
     s.repository!==target.repository||s.baseBranch!==target.baseBranch||
     s.prNumber!==target.prNumber||s.developmentHead!==target.developmentHead||
     s.baseSha!==target.baseSha||
     s.prMergeCheckoutSha!==target.prMergeCheckoutSha||
     s.challengeNonce!==target.challengeNonce||
     s.productionReleaseAuthorized!==false||
     s.role!==requiredRole||typeof s.signerId!=='string'||
     !hashPattern.test(s.evidenceSha256??'')){
   anomalies.add('BX_SIGNED_STATEMENT_SOURCE_OR_ROLE_MISMATCH_'+s.type);continue;
  }
  if(s.type==='ci-provenance'&&
     s.evidenceSha256!==target.ciInputBundleSha256){
   anomalies.add('BX_CI_BUILD_INPUT_DIGEST_MISMATCH');continue;
  }
  if(s.type==='external-worm-receipt'&&
     (s.witnessedCiBundleSha256!==target.ciInputBundleSha256||
      !Number.isSafeInteger(s.wormSequence)||s.wormSequence<1||
      s.wormRetentionVerified!==true)){
   anomalies.add('BX_WORM_RECEIPT_BUNDLE_SEQUENCE_OR_RETENTION_INVALID');continue;
  }
  if(s.type==='branch-ruleset'&&
     (!object(s.observedRuleset)||
      REQUIRED_RULESET_CONTROLS.some(k=>s.observedRuleset[k]!==true)||
      s.observedRuleset.minimumIndependentApprovals!==2||
      s.observedRuleset.protectionBranch!=='main')){
   anomalies.add('BX_RULESET_SIGNED_SNAPSHOT_INSUFFICIENT');continue;
  }
  const issued=parseRfc3339(s.issuedAt),expires=parseRfc3339(s.expiresAt);
  if(!Number.isFinite(issued)||!Number.isFinite(expires)||
     !Number.isFinite(nowMs)||issued>nowMs+300000||
     expires<=nowMs||expires<=issued||expires-issued>86400000){
   anomalies.add('BX_STALE_OR_FUTURE_SIGNED_EVIDENCE_'+s.type);continue;
  }
  const authority=object(authorities)?authorities[s.signerId]:undefined;
  if(!object(authority)||authority.role!==requiredRole||
     typeof authority.login!=='string'||authority.login!==s.signerLogin||
     typeof authority.publicKeyPem!=='string'||
     !hashPattern.test(authority.spkiSha256??'')){
   anomalies.add('BX_UNENROLLED_SIGNER_OR_ROLE_'+s.type);continue;
  }
  if(s.signerLogin===target.prAuthor||
     usedKeyIds.has(s.signerId)||usedIdentity.has(s.signerLogin)){
   anomalies.add('BX_SELF_REVIEW_OR_SIGNER_REUSE_'+s.type);continue;
  }
  const sig=base64Signature(item.signature);
  if(!sig||item.algorithm!=='Ed25519'){
   anomalies.add('BX_MALFORMED_SIGNATURE_OR_ALGORITHM_'+s.type);continue;
  }
  try{
   const key=createPublicKey(authority.publicKeyPem);
   if(key.asymmetricKeyType!=='ed25519'||
      sha256(key.export({type:'spki',format:'der'}))!==authority.spkiSha256||
      !verify(null,signingPayload(s),key,sig)){
    anomalies.add('BX_SIGNATURE_OR_ENROLLED_KEY_MISMATCH_'+s.type);continue;
   }
  }catch{
   anomalies.add('BX_UNVERIFIABLE_SIGNATURE_'+s.type);continue;
  }
  accepted.set(s.type,s.signerId);
  usedKeyIds.add(s.signerId);
  usedIdentity.add(s.signerLogin);
 }
 for(const type of Object.keys(EVIDENCE_TYPES)){
  if(!accepted.has(type))anomalies.add('BX_MISSING_INDEPENDENT_PROOF_'+type);
 }
 if(submitted.length!==Object.keys(EVIDENCE_TYPES).length)
  anomalies.add('BX_EVIDENCE_QUORUM_INCOMPLETE');
 return Object.freeze({
  phase:'1BX',schemaVersion:1,
  suppliedKeySignaturesCryptographicallyConsistent:anomalies.size===0,
  acceptedSuppliedRecordCount:accepted.size,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  // Caller-supplied keyrings/snapshots do not constitute authenticated
  // GitHub API, provider-verified identities, OIDC trust or real WORM proof.
  independentGithubRulesetVerified:false,
  authenticatedIndependentReviewerEnrollmentVerified:false,
  realGithubReviewSubmissionVerified:false,
  externalKeyProvenanceAuthenticated:false,
  independentCIWorkloadIdentityVerified:false,
  externallyWitnessedWormReceiptVerified:false,
  independentSecurityAcceptanceVerified:false,
  vendorPicomatchPatchVerified:false,
  globalZeroHighAuditPassed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function createZeroInputHoldReport(){
 const result=assessExternalGovernanceEvidence({
  now:'2026-11-18T09:00:00.000Z',
  target:{
   repository:EXPECTED_REPO,baseBranch:'main',prNumber:1,
   prAuthor:'j9619655391-max',
   // Purely syntactic fake target is NOT real branch/PR evidence.
   developmentHead:'0'.repeat(40),baseSha:'0'.repeat(40),
   prMergeCheckoutSha:'0'.repeat(40),challengeNonce:'0'.repeat(64),
   ciInputBundleSha256:'0'.repeat(64),
   productionReleaseAuthorized:false
  }
 });
 return Object.freeze({
  kind:'ZERO_INPUT_CI_GOVERNANCE_HARD_HOLD',phase:'1BX',
  externalPacketCount:0,independentKeysSupplied:false,
  evidence:result,releaseDecision:'HOLD',productionReleaseAuthorized:false
 });
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('BX allows only --ci-hold; no external evidence/approval options');
 const report=createZeroInputHoldReport();
 // The generated report cannot authenticate external signatures or claims.
 writeFileSync('phase1bx-zero-input-independent-hold-report.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(report.externalPacketCount!==0||report.evidence.acceptedSuppliedRecordCount!==0||
    report.evidence.productionReleaseAuthorized||report.evidence.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Phase 1BX independent evidence verification HOLD failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
