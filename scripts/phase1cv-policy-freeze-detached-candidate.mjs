import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,validateReviewerNominees}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {verifyIndependentGovernanceHandoff}
 from './phase1cu-independent-governance-handoff.mjs';
import {collectActualRulesets}
 from './phase1cn-ruleset-bypass-reconciliation.mjs';
import {fetchReadOnlyGithubGovernance,ENDPOINTS}
 from './phase1cl-live-codeowners-reviewer-onboarding.mjs';

// 1CV: two separately collected actual-main governance fingerprints, plus
// mathematically validated *candidate* detached Security/Business signatures.
// Operator supplied keys and monotonic anchor are NOT authenticated trust
// enrollment, externally durable compare-and-swap, OIDC, WORM or legal roles.
export const DOMAIN='aaditech/phase1cv/policy-freeze-detached-candidate/v1\n';
export const ROLES=Object.freeze(['SECURITY_WITNESS','BUSINESS_WITNESS']);
const SHA=/^[a-f0-9]{40}$/;
const DIGEST=/^[a-f0-9]{64}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const KEY_ID=/^[A-Za-z0-9][A-Za-z0-9._-]{4,79}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const keys=(x,arr)=>own(x)&&Object.keys(x).length===arr.length&&
 arr.every(k=>Object.hasOwn(x,k));
const hash=v=>createHash('sha256').update(v).digest('hex');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const number=x=>Number.isSafeInteger(x)&&x>0;
const date=x=>{
 if(typeof x!=='string'||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const ms=Date.parse(x);
 return Number.isFinite(ms)&&new Date(ms).toISOString()===x?ms:NaN;
};
export function canonical(v){
 if(v===null||typeof v==='string'||typeof v==='boolean')
  return JSON.stringify(v);
 if(typeof v==='number'&&Number.isSafeInteger(v))return JSON.stringify(v);
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(own(v))return '{'+Object.keys(v).sort().map(k=>
  JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
 throw Error('CV_UNSUPPORTED_CANONICAL_SIGNED_INPUT');
}
export function candidateSigningBytes(statement){
 if(!own(statement)||JSON.stringify(statement).length>8192)
  throw Error('CV_UNTRUSTED_OR_OVERSIZE_SIGNED_STATEMENT');
 return Buffer.from(DOMAIN+canonical(statement),'utf8');
}
function officialRuleInventory(obs){
 const list=obs?.listStatus==='read'&&obs.listingComplete===true&&
  Array.isArray(obs.listed)&&obs.listed.length>0&&obs.listed.length<=12?
  obs.listed:null;
 if(!list)return null;
 const collected=[],ids=new Set();
 for(const item of list){
  if(!number(item?.id)||ids.has(item.id)||
     obs.detailStatus?.[String(item.id)]!=='read')return null;
  ids.add(item.id);
  const detail=obs.details?.[String(item.id)];
  if(!own(detail)||detail.id!==item.id||
     detail.name!==item.name||detail.target!==item.target||
     detail.enforcement!==item.enforcement||
     !Array.isArray(detail.bypass_actors))return null;
  // No admin/app bypass is a hard gate; read-only hidden field is unknown.
  if(detail.bypass_actors.length!==0)return null;
  collected.push({id:item.id,detail});
 }
 if(Object.keys(obs.details??{}).length!==ids.size||
    Object.keys(obs.detailStatus??{}).length!==ids.size)return null;
 collected.sort((a,b)=>a.id-b.id);
 return collected;
}
function officialCodeowners(record){
 const d=record?.status==='read'?record.data:null;
 if(!own(d)||d.type!=='file'||d.path!=='.github/CODEOWNERS'||
   d.encoding!=='base64'||!SHA.test(d.sha??'')||
   typeof d.content!=='string'||d.size<1||d.size>65536)return null;
 const normalized=d.content.replace(/\s/g,'');
 if(!/^(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?$/.test(normalized))
  return null;
 const bytes=Buffer.from(normalized,'base64');
 if(bytes.length!==d.size||bytes.toString('base64')!==normalized||
    !Buffer.from(bytes.toString('utf8'),'utf8').equals(bytes))return null;
 const blobHash=createHash('sha1').update(
  Buffer.concat([Buffer.from('blob '+bytes.length+'\0'),bytes])).digest('hex');
 if(blobHash!==d.sha)return null;
 return {sha:d.sha,size:d.size,contentSha256:hash(bytes)};
}
export function assessGovernanceFingerprint({
 handoff=null,rulesets=null,codeowners=null
}={}){
 const errors=new Set();
 const h=handoff;
 if(h?.phase!=='1CU'||h.kind!==
   'OPERATOR_ONLY_CROSS_SOURCE_REVIEWER_MAIN_PROTECTION_HANDOFF_HOLD'||
    h.technicalGovernanceHandoffPreconditionsObserved!==true||
    h.actualMainBaseStableAcrossAllSources!==true||
    h.exactHeadPushAndPrTechnicalCiReceiptsMatched!==true||
    h.distinctNominatedLatestHeadTechnicalGithubApprovalsMatched!==true||
    h.exactActiveMainRulesAndNoBypassFieldsObservable!==true||
    h.installedMainCodeownersExactNominatedBytesMatched!==true||
    !SHA.test(h.currentDevHeadSha??'')||
    !DIGEST.test(h.localUnsignedObservationSha256??'')||
    h.productionReleaseAuthorized!==false||
    h.productionReleaseBlocked!==true||h.releaseDecision!=='HOLD')
  errors.add('CV_PRECEDING_ACTUAL_MAIN_GOVERNANCE_CUSTODY_INVALID');
 const list=officialRuleInventory(rulesets);
 if(!list)errors.add('CV_RULESET_DETAIL_BY_ID_MISSING_HIDDEN_OR_BYPASSED');
 const owners=officialCodeowners(codeowners);
 if(!owners)errors.add('CV_BASE_MAIN_CODEOWNERS_BYTES_UNREADABLE_OR_TAMPERED');
 const snapshot=h?{
  sourceHead:h.currentDevHeadSha,
  mainSha:h.actualMainBaseStableAcrossAllSources?
   h.currentDevHeadSha===null?null:
   h.verifiedMainBaseSha??null:null,
  pushRunId:h.pushRunId??null,prRunId:h.prRunId??null,
  handoffHash:h.localUnsignedObservationSha256,
  rules:list,
  codeowners:owners
 }:null;
 // Actual 1CU report does not expose reviewer names, signed role mandates,
 // CA keys or any secret. The digest contains policy details, not secrets.
 const valid=errors.size===0&&snapshot!==null&&
   SHA.test(snapshot.mainSha??'')&&
   number(snapshot.pushRunId)&&number(snapshot.prRunId);
 if(!valid)errors.add('CV_INCOMPLETE_EXACT_HEAD_BASE_OR_RUN_ID_FINGERPRINT');
 return Object.freeze({
  phase:'1CV',schemaVersion:1,
  technicalSnapshotConsistent:valid,
  currentHeadSha:valid?snapshot.sourceHead:null,
  mainBaseSha:valid?snapshot.mainSha:null,
  pushRunId:valid?snapshot.pushRunId:null,
  prRunId:valid?snapshot.prRunId:null,
  policyFingerprintSha256:valid?hash(canonical(snapshot)):null,
  reasonCodes:Object.freeze([...errors].sort()),
  signerAuthoritiesIndependentlyVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessDetachedCandidate({
 before=null,after=null,statement=null,signatures=[],
 registry={},checkpoint=null,now='2026-11-19T12:00:00.000Z'
}={}){
 const errors=new Set();
 const pre=before?.technicalSnapshotConsistent===true&&
   before.phase==='1CV'&&DIGEST.test(before.policyFingerprintSha256??'')&&
   SHA.test(before.currentHeadSha??'')&&SHA.test(before.mainBaseSha??'')&&
   number(before.pushRunId)&&number(before.prRunId)&&
   before.productionReleaseAuthorized===false&&before.releaseDecision==='HOLD';
 const post=after?.technicalSnapshotConsistent===true&&
   after.phase==='1CV'&&DIGEST.test(after.policyFingerprintSha256??'')&&
   after.productionReleaseAuthorized===false&&after.releaseDecision==='HOLD';
 if(!pre||!post)errors.add('CV_TWO_INDEPENDENT_CURRENT_SOURCE_SNAPSHOTS_REQUIRED');
 const same=pre&&post&&
   before.policyFingerprintSha256===after.policyFingerprintSha256&&
   before.currentHeadSha===after.currentHeadSha&&
   before.mainBaseSha===after.mainBaseSha&&
   before.pushRunId===after.pushRunId&&before.prRunId===after.prRunId;
 if(!same)errors.add('CV_TOCTOU_RULESET_CODEOWNERS_REVIEW_OR_SOURCE_DRIFT');
 const fields=[
  'schemaVersion','kind','repository','sourceHeadSha','mainBaseSha',
  'pushRunId','prRunId','policyFingerprintSha256','nonce',
  'epoch','previousDigest','issuedAt','expiresAt','releaseDecision'
 ];
 if(!keys(statement,fields)||statement.schemaVersion!==1||
    statement.kind!=='CANDIDATE_OFFREPO_POLICY_FREEZE'||
    statement.repository!==REPO||
    !SHA.test(statement.sourceHeadSha??'')||
    !SHA.test(statement.mainBaseSha??'')||
    !number(statement.pushRunId)||!number(statement.prRunId)||
    !DIGEST.test(statement.policyFingerprintSha256??'')||
    !DIGEST.test(statement.nonce??'')||
    statement.nonce==='0'.repeat(64)||
    statement.releaseDecision!=='HOLD')
  errors.add('CV_UNTRUSTED_DETACHED_CANDIDATE_SCHEMA');
 if(!same||statement?.sourceHeadSha!==before?.currentHeadSha||
    statement?.mainBaseSha!==before?.mainBaseSha||
    statement?.pushRunId!==before?.pushRunId||
    statement?.prRunId!==before?.prRunId||
    statement?.policyFingerprintSha256!==before?.policyFingerprintSha256)
  errors.add('CV_DETACHED_CANDIDATE_NOT_BOUND_TO_CURRENT_POLICY');
 if(!keys(checkpoint,['epoch','lastDigest','observedAt'])||
    !Number.isSafeInteger(checkpoint.epoch)||checkpoint.epoch<0||
    !DIGEST.test(checkpoint.lastDigest??'')||
    !Number.isSafeInteger(statement?.epoch)||
    statement.epoch!==checkpoint.epoch+1||
    statement.previousDigest!==checkpoint.lastDigest)
  errors.add('CV_REPLAY_ROLLBACK_GAP_OR_UNANCHORED_EPOCH');
 const clock=date(now),issued=date(statement?.issuedAt),
  expires=date(statement?.expiresAt),anchorTime=date(checkpoint?.observedAt);
 if(!Number.isFinite(clock)||!Number.isFinite(issued)||
    !Number.isFinite(expires)||!Number.isFinite(anchorTime)||
    issued>clock+300000||issued<clock-900000||
    issued<=anchorTime||expires<=clock||expires<=issued||
    expires-issued>900000)
  errors.add('CV_EXPIRED_FUTURE_OR_NONMONOTONIC_CANDIDATE_TIME');
 if(!Array.isArray(signatures)||signatures.length!==ROLES.length)
  errors.add('CV_EXACT_TWO_DETACHED_ROLE_SIGNATURES_REQUIRED');
 if(!keys(registry,ROLES))
  errors.add('CV_TWO_SEPARATE_ROLE_KEY_REGISTRY_REQUIRED');
 const sigMap=new Map(),usedFingerprints=new Set(),verified=[];
 for(const entry of Array.isArray(signatures)?signatures:[]){
  if(!keys(entry,['role','keyId','algorithm','signature'])||
     !ROLES.includes(entry.role)||sigMap.has(entry.role)){
   errors.add('CV_DUPLICATE_OR_UNREVIEWED_SIGNER_ROLE');continue;
  }
  sigMap.set(entry.role,entry);
 }
 for(const role of ROLES){
  const entry=sigMap.get(role),key=registry?.[role];
  if(!keys(entry,['role','keyId','algorithm','signature'])||
     !keys(key,['keyId','publicKeyPem','spkiSha256','validFrom','validUntil','revoked'])||
     !KEY_ID.test(key.keyId??'')||entry.keyId!==key.keyId||
     entry.algorithm!=='Ed25519'||typeof entry.signature!=='string'||
     !B64.test(entry.signature)||typeof key.publicKeyPem!=='string'||
     key.publicKeyPem.length>4096||!DIGEST.test(key.spkiSha256??'')||
     key.revoked!==false||!Number.isFinite(date(key.validFrom))||
     !Number.isFinite(date(key.validUntil))||
     date(key.validFrom)>issued||date(key.validUntil)<=clock){
   errors.add('CV_'+role+'_ENROLLMENT_SIGNATURE_OR_TIME_INVALID');continue;
  }
  try{
   const publicKey=createPublicKey(key.publicKeyPem),sig=Buffer.from(entry.signature,'base64');
   const fingerprint=hash(publicKey.export({type:'spki',format:'der'}));
   const ok=publicKey.asymmetricKeyType==='ed25519'&&
    sig.length===64&&sig.toString('base64')===entry.signature&&
    fingerprint===key.spkiSha256&&
    verify(null,candidateSigningBytes(statement),publicKey,sig);
   if(!ok)errors.add('CV_'+role+'_BAD_DETACHED_SIGNATURE');
   else{
    if(usedFingerprints.has(fingerprint))
     errors.add('CV_SIGNER_KEY_REUSE_OR_ROLE_COLLUSION');
    usedFingerprints.add(fingerprint);
    verified.push(role);
   }
  }catch{
   errors.add('CV_'+role+'_BAD_DETACHED_SIGNATURE');
  }
 }
 const technicallyConsistent=errors.size===0&&verified.length===2&&same;
 const statementHash=keys(statement,fields)?hash(candidateSigningBytes(statement)):null;
 return Object.freeze({
  phase:'1CV',schemaVersion:1,
  kind:'TWO_SNAPSHOT_OFFREPO_CANDIDATE_DETACHED_SIGNED_HOLD',
  currentHeadSha:same?before.currentHeadSha:null,
  mainBaseSha:same?before.mainBaseSha:null,
  policyFingerprintSha256:same?before.policyFingerprintSha256:null,
  detachedCandidateSha256:statementHash,
  verifiedCandidateSignatureCount:verified.length,
  twoSnapshotsAndDetachedCandidateMathematicallyConsistent:technicallyConsistent,
  anomalyCodes:Object.freeze([...errors].sort()),
  callerSuppliedKeyEnrollmentIndependentlyAuthenticated:false,
  legalSecurityBusinessRolesIndependentlyAuthenticated:false,
  externallyDurableHighWatermarkAndAtomicCASVerified:false,
  independentCrossRunAntiEquivocationWitnessVerified:false,
  remotelyRetrievedOffrepoBytesAndTrustedTlsIdentityVerified:false,
  githubOidcSlsaAttestationOrWormObjectLockVerified:false,
  liveProviderMcaAndExternalStagingAcceptanceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export async function captureLiveFingerprint({
 pushId,prId,securityLogin,businessLogin,token,proposal,fetchImpl=fetch
}={}){
 const handoff=await verifyIndependentGovernanceHandoff({
  pushId,prId,securityLogin,businessLogin,token,proposal,fetchImpl
 });
 // Separate policy reads bind the actual rule IDs/contents and CODEOWNERS
 // git-blob bytes; no single 1CU boolean stands in for an entire policy.
 const rulesets=await collectActualRulesets({token,fetchImpl});
 const codeowners=await fetchReadOnlyGithubGovernance(
  ENDPOINTS.codeownersGithub,token,fetchImpl);
 return assessGovernanceFingerprint({handoff,rulesets,codeowners});
}
export async function verifyLiveDetachedCandidate({
 pushId,prId,securityLogin,businessLogin,token,proposal,
 loadCandidate,fetchImpl=fetch,now=new Date().toISOString()
}={}){
 if(!validateReviewerNominees(securityLogin,businessLogin).valid)
  throw Error('CV_NOMINATED_SECURITY_BUSINESS_IDENTITIES_INVALID');
 if(!number(pushId)||!number(prId)||pushId===prId)
  throw Error('CV_DISTINCT_COMPLETED_RUN_IDS_REQUIRED');
 if(typeof loadCandidate!=='function')
  throw Error('CV_INDEPENDENT_OFFREPO_FILE_LOADER_REQUIRED');
 const before=await captureLiveFingerprint({
  pushId,prId,securityLogin,businessLogin,token,proposal,fetchImpl
 });
 // Candidate is loaded BETWEEN independent GitHub read-only rounds;
 // second round never reuses prior in-memory policy source objects.
 const packet=await loadCandidate();
 const after=await captureLiveFingerprint({
  pushId,prId,securityLogin,businessLogin,token,proposal,fetchImpl
 });
 return assessDetachedCandidate({
  before,after,statement:packet?.statement,
  signatures:packet?.signatures,registry:packet?.registry,
  checkpoint:packet?.checkpoint,now
 });
}
function safeJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('CV_INVALID_OPERATOR_FILE_PATH');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>131072)
  throw Error('CV_CANDIDATE_JSON_MISSING_UNSAFE_OR_OVERSIZE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function runId(s){
 return typeof s==='string'&&/^[1-9]\d{0,15}$/.test(s)&&
  Number.isSafeInteger(Number(s));
}
async function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true')
  throw Error('CV_OPERATOR_SECRET_AND_REVIEWER_ENROLLMENT_FORBIDDEN_IN_CI');
 const [flag,pushId,prId,security,business,...rest]=args;
 if(!['--capture-fingerprint','--verify-signed-freeze'].includes(flag)||
    !runId(pushId)||!runId(prId)||pushId===prId||
    !validateReviewerNominees(security,business).valid)
  throw Error('CV_ONLY_APPROVED_HUMAN_READONLY_OPERATOR_COMMANDS');
 const proposal=safeJson(
  'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json');
 const shared={pushId:Number(pushId),prId:Number(prId),
  securityLogin:security,businessLogin:business,
  token:process.env.GITHUB_READ_TOKEN,proposal};
 let output;
 if(flag==='--capture-fingerprint'&&rest.length===0)
  output=await captureLiveFingerprint(shared);
 else if(flag==='--verify-signed-freeze'&&rest.length===1)
  output=await verifyLiveDetachedCandidate({
   ...shared,loadCandidate:async()=>safeJson(rest[0])
  });
 else throw Error('CV_UNREVIEWED_OPERATOR_ARGUMENT_SHAPE');
 console.log(JSON.stringify(output,null,2));
 if(flag==='--capture-fingerprint'){
  if(!output.technicalSnapshotConsistent)process.exitCode=1;
 }else if(!output.twoSnapshotsAndDetachedCandidateMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CV candidate attestation policy-drift HOLD:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
