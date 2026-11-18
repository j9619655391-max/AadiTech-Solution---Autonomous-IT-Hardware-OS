import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {BUILD_INPUT_PATHS,makeBuildInputInventory} from './phase1bv-build-input-provenance.mjs';
import {REVIEWED_ACTIONS} from './phase1bz-actions-pin-preflight.mjs';
import {assessGithubPrTestMergeLineage,parseGitCommitParents} from './phase1by-pr-merge-lineage.mjs';

// Phase 1CC creates a PORTABLE BUT UNSIGNED source/receipt digest envelope.
// GitHub-hosted checkout metadata and applicant-editable JSON are not
// independent publisher authority, OIDC signatures, WORM or release approval.
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
const BASE='main';
const SHA=/^[a-f0-9]{40}$/;
const DIGEST=/^[a-f0-9]{64}$/;
const DOMAIN='aaditech/phase1cc/unsigned-ci-source-receipt-envelope/v1\n';
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const sha256=x=>createHash('sha256').update(x).digest('hex');
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(object(x))return '{'+Object.keys(x).sort().map(k=>
  JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('CC unsupported canonical envelope field');
}
export function verifyUnsignedEnvelopeDigest(envelope){
 if(!object(envelope)||!object(envelope.body)||
   JSON.stringify(envelope).length>262144||
   !DIGEST.test(envelope.envelopeSha256??''))return false;
 try{
  return envelope.envelopeSha256===sha256(DOMAIN+canonical(envelope.body))&&
   envelope.body.releaseDecision==='HOLD'&&
   envelope.productionReleaseAuthorized===false&&
   envelope.independentlySignedWorkloadProvenanceVerified===false&&
   envelope.externallyWitnessedImmutableRetentionVerified===false;
 }catch{return false;}
}
export function assessCiSourceReceipt({
 bv,bz,sources={},rawBV='',rawBZ='',environment={},event={},
 checkoutSha,commitRaw
}={}){
 const errors=new Set();
 const sourceFiles=[];
 for(const path of BUILD_INPUT_PATHS){
  const data=sources?.[path];
  if(typeof data!=='string'||data.length===0||Buffer.byteLength(data)>1024*1024){
   errors.add('CC_REQUIRED_SOURCE_FILE_MISSING_OR_OVERSIZED');
   continue;
  }
  sourceFiles.push({path,bytes:Buffer.byteLength(data),sha256:sha256(data)});
 }
 let selectedInputBundleSha256=null;
 if(sourceFiles.length===BUILD_INPUT_PATHS.length){
  try{
   const computed=makeBuildInputInventory(sources,{GITHUB_SHA:checkoutSha});
   selectedInputBundleSha256=computed.bundleSha256;
   if(!object(bv?.inventory)||
      bv.inventory.kind!=='UNSIGNED_LOCAL_CI_INPUT_INVENTORY'||
      bv.inventory.bundleSha256!==computed.bundleSha256||
      bv.inventory.claimedGithubSha!==checkoutSha||
      JSON.stringify(bv.inventory.files)!==JSON.stringify(computed.files))
    errors.add('CC_BUILD_INPUT_INVENTORY_FILE_OR_BUNDLE_MISMATCH');
  }catch{
   errors.add('CC_BUILD_INPUT_INVENTORY_UNVERIFIABLE');
  }
 }
 if(bv?.boundary?.localBuildInputBoundaryConsistent!==true||
    bv?.boundary?.productionReleaseAuthorized!==false||
    bv?.boundary?.releaseDecision!=='HOLD'||
    bv?.inventory?.productionReleaseAuthorized!==false||
    bv?.inventory?.signedByIndependentWitness!==false||
    bv?.inventory?.verifiedExternalWormRetention!==false)
  errors.add('CC_BUILD_RECEIPT_SELF_APPROVAL_OR_MISSING_HOLD');
 if(!object(bz)||bz.immutableSelectedActionRefsCorroborated!==true||
    bz.phase1caBoundedJobScopeConsistent!==true||
    bz.releaseDecision!=='HOLD'||bz.productionReleaseAuthorized!==false||
    bz.publisherIdentityIndependentlyVerified!==false||
    bz.actionExecutionAndRunnerIndependentlyAttested!==false||
    bz.externalWormRetentionVerified!==false||
    bz.selectedActionUses!==20||
    bz.selectedWorkflowSha256!==sha256(sources['.github/workflows/ci.yml']??'')||
    JSON.stringify(bz.selectedWorkflowFiles)!==JSON.stringify(['ci.yml'])||
    JSON.stringify(bz.expectedPinnedActionCommitIds)!==JSON.stringify(REVIEWED_ACTIONS))
  errors.add('CC_ACTIONS_AND_JOB_SCOPE_RECEIPT_MISMATCH');
 if(typeof rawBV!=='string'||!rawBV||Buffer.byteLength(rawBV)>131072||
    typeof rawBZ!=='string'||!rawBZ||Buffer.byteLength(rawBZ)>131072)
  errors.add('CC_MISSING_OR_OVERSIZED_LOCAL_RECEIPT_BYTES');
 else {
  try{
   if(JSON.stringify(JSON.parse(rawBV))!==JSON.stringify(bv)||
      JSON.stringify(JSON.parse(rawBZ))!==JSON.stringify(bz))
    errors.add('CC_REPORT_BYTES_AND_PARSED_RECORD_DIVERGE');
  }catch{errors.add('CC_MALFORMED_REPORT_BYTES');}
 }
 if(environment.CI!=='true'||environment.GITHUB_ACTIONS!=='true'||
   environment.GITHUB_REPOSITORY!==REPO||
   !SHA.test(environment.GITHUB_SHA??'')||
   checkoutSha!==environment.GITHUB_SHA||
   event?.repository?.full_name!==REPO)
  errors.add('CC_CI_RUN_REPOSITORY_OR_CHECKOUT_UNTRUSTED');
 let gitTreeSha=null,gitParents=[];
 try{
  const parsed=parseGitCommitParents(commitRaw);
  gitTreeSha=parsed.treeSha;
  gitParents=[...parsed.parentShas];
 }catch{errors.add('CC_GIT_CHECKOUT_OBJECT_MISSING_OR_MALFORMED');}
 let sourceHeadSha=null,baseSha=null;
 if(environment.GITHUB_EVENT_NAME==='pull_request'){
  const l=assessGithubPrTestMergeLineage({
   environment,event,checkedOutSha:checkoutSha,commitObject:commitRaw
  });
  if(!l.localSourceGraphCorroborated)
   errors.add('CC_PR_TEST_MERGE_EVENT_OR_PARENT_LINEAGE_INVALID');
  sourceHeadSha=l.observedSourceHeadSha;
  baseSha=l.observedBaseSha;
 }else if(environment.GITHUB_EVENT_NAME==='push'){
  if(environment.GITHUB_REF!=='refs/heads/'+DEV||
     event?.ref!=='refs/heads/'+DEV||
     event?.after!==checkoutSha||event?.deleted===true||
     event?.forced===true||gitParents.length<1)
   errors.add('CC_PUSH_EVENT_OR_REF_ROLLBACK_INVALID');
  sourceHeadSha=checkoutSha;
 }else errors.add('CC_UNREVIEWED_CI_EVENT_TYPE');
 const body={
  schemaVersion:1,phase:'1CC',kind:'UNSIGNED_SOURCE_BOUND_CI_RECEIPT',
  repository:REPO,developmentBranch:DEV,baseBranch:BASE,prNumber:1,
  githubEventName:environment.GITHUB_EVENT_NAME??null,
  githubRef:environment.GITHUB_REF??null,
  checkedOutSha:SHA.test(checkoutSha??'')?checkoutSha:null,
  observedGitTreeSha:gitTreeSha,observedGitParentShas:gitParents,
  sourceHeadSha,baseSha,
  selectedInputBundleSha256,
  selectedSources:sourceFiles,
  reportedBuildInputSha256:typeof rawBV==='string'?sha256(rawBV):null,
  reportedActionPinSha256:typeof rawBZ==='string'?sha256(rawBZ):null,
  requiredActionPins:REVIEWED_ACTIONS,
  sourceAndReceiptAnomalyCodes:[...errors].sort(),
  unsignedGithubArtifactOnly:true,
  independentOidcAttestationAccepted:false,
  externalWormObjectLockAndRestoreVerified:false,
  verifiedIndependentReviewQuorum:0,
  globalZeroCriticalHighAuditPassed:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 };
 const envelope={
  body,envelopeSha256:sha256(DOMAIN+canonical(body)),
  localSourceAndArtifactsConsistent:errors.size===0,
  independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,
  independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 };
 return Object.freeze(envelope);
}
function readBounded(path,max){
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)
  throw Error('CC refused absent, symlink or oversized CI report/source');
 return readFileSync(path,'utf8');
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CC only supports --ci-hold');
 const rawBV=readBounded('phase1bv-held-build-input-report.json',131072);
 const rawBZ=readBounded('phase1bz-actions-pin-hold.json',131072);
 const eventPath=process.env.GITHUB_EVENT_PATH;
 if(typeof eventPath!=='string'||!eventPath||eventPath.length>1024)
  throw Error('CC GitHub native event path unavailable');
 const event=JSON.parse(readBounded(eventPath,262144));
 const sources=Object.fromEntries(BUILD_INPUT_PATHS.map(path=>
  [path,readBounded(path,1024*1024)]));
 const checkoutSha=execFileSync('git',['rev-parse','HEAD'],{
  encoding:'utf8',timeout:5000,maxBuffer:4096}).trim();
 if(!SHA.test(checkoutSha))throw Error('CC invalid checkout commit');
 const commitRaw=execFileSync('git',['cat-file','-p',checkoutSha],{
  encoding:'utf8',timeout:5000,maxBuffer:65536});
 const envelope=assessCiSourceReceipt({
  bv:JSON.parse(rawBV),bz:JSON.parse(rawBZ),rawBV,rawBZ,
  sources,environment:process.env,event,checkoutSha,commitRaw
 });
 writeFileSync('phase1cc-unsigned-source-receipt-hold.json',
  JSON.stringify(envelope,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify({
  phase:'1CC',kind:envelope.body.kind,
  localSourceAndArtifactsConsistent:envelope.localSourceAndArtifactsConsistent,
  githubEventName:envelope.body.githubEventName,
  checkedOutSha:envelope.body.checkedOutSha,
  sourceHeadSha:envelope.body.sourceHeadSha,
  baseSha:envelope.body.baseSha,
  selectedInputBundleSha256:envelope.body.selectedInputBundleSha256,
  envelopeSha256:envelope.envelopeSha256,
  anomalyCodes:envelope.body.sourceAndReceiptAnomalyCodes,
  independentlySignedWorkloadProvenanceVerified:false,
  externallyWitnessedImmutableRetentionVerified:false,
  releaseDecision:'HOLD',productionReleaseAuthorized:false
 },null,2));
 if(!envelope.localSourceAndArtifactsConsistent||
   !verifyUnsignedEnvelopeDigest(envelope)||
   envelope.productionReleaseAuthorized||envelope.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(err){
  console.error('CC source-bound CI receipt HARD HOLD check failed:',
   err instanceof Error?err.message:'Unknown');
  process.exitCode=1;
 }
}
