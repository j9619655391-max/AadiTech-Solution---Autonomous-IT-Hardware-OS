import {Worker} from 'node:worker_threads';
import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {readBunLock} from './phase1bt-production-scope.mjs';
import {triageDependencyAudit} from './triage-dependencies.mjs';
import {checkCurrentAudit} from './verify-patched-dependencies.mjs';

// Actual installed Picomatch, *fixed tiny* patterns derived from advisory,
// isolated workers, bounded runtime/memory. This does NOT reproduce the full
// exploit or establish a vendor patch / independently signed risk decision.
export const CASE_IDS=Object.freeze([
 'control_literal','repeated_extglob_star','repeated_extglob_a'
]);
export const WORKER_TIMEOUT_MS=2000;
export const GHSA='GHSA-fc5q-39xc-vjpf';
export const CVE='CVE-2026-112366';
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const SHA=/^[0-9a-f]{40}$/;
const INTEGRITY=/^sha512-[A-Za-z0-9+/]{86}==$/;
const MAX_FILE=1024*1024;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const bounded=x=>Number.isFinite(x)&&x>=0&&x<=WORKER_TIMEOUT_MS+400;
export async function runBoundedPicomatchSample(id){
 if(!CASE_IDS.includes(id))throw Error('CK_UNAPPROVED_SAMPLE_ID');
 return new Promise(resolveResult=>{
  let settled=false;
  const worker=new Worker(new URL('./phase1ck-picomatch-worker.cjs',import.meta.url),{
   workerData:{id},resourceLimits:{
    maxOldGenerationSizeMb:48,maxYoungGenerationSizeMb:16,stackSizeMb:4
   }
  });
  const complete=v=>{
   if(settled)return;
   settled=true;clearTimeout(timer);
   if(v.state!=='COMPLETED')worker.terminate().catch(()=>{});
   resolveResult(Object.freeze(v));
  };
  const timer=setTimeout(()=>complete({
   caseId:id,state:'TIMEOUT',installedVersion:null,matched:null,
   executionMs:null
  }),WORKER_TIMEOUT_MS);
  worker.once('message',message=>{
   if(!object(message)||message.caseId!==id||
      !['COMPLETED','ERROR'].includes(message.state)){
    complete({caseId:id,state:'ERROR',
     reason:'UNRECOGNIZED_WORKER_RESPONSE',installedVersion:null,
     matched:null,executionMs:null});
    return;
   }
   if(message.state==='ERROR'){
    complete({caseId:id,state:'ERROR',
     reason:String(message.reason??'UNKNOWN').slice(0,120),
     installedVersion:null,matched:null,executionMs:null});
    return;
   }
   complete({caseId:id,state:'COMPLETED',
    installedVersion:message.installedVersion,
    matched:message.matched,executionMs:message.executionMs});
  });
  worker.once('error',()=>complete({caseId:id,state:'ERROR',
   reason:'WORKER_ERROR',installedVersion:null,matched:null,executionMs:null}));
  worker.once('exit',code=>{
   if(!settled)complete({caseId:id,state:'ERROR',
    reason:'WORKER_EXIT_'+String(code),installedVersion:null,
    matched:null,executionMs:null});
  });
 });
}
const outcome=(errors,d={})=>Object.freeze({
 phase:'1CK',schemaVersion:1,
 kind:'REAL_FROZEN_LOCK_ISOLATED_PICOMATCH_TIMING_AND_AUDIT_HARD_HOLD',
 repository:REPO,advisoryId:GHSA,cveId:CVE,
 frozenPicomatchVersion:d.version??null,
 frozenPicomatchIntegritySha256:d.integrityDigest??null,
 fullLockAuditAdvisoryCount:d.advisoryCount??null,
 fullLockCurrentCritical:d.critical??null,
 fullLockCurrentHigh:d.high??null,
 fullLockCurrentUnknown:d.unknown??null,
 fullLockCriticalHighOrUnknownObserved:d.advisoryObserved??null,
 sampleTimeoutMs:WORKER_TIMEOUT_MS,
 sampledFixedCases:d.samples??[],
 actualInstalledMatcherWorkerSamplingCompleted:d.completed??false,
 boundedWorkerTimeoutObserved:d.timedOut??false,
 localAuditAndSampleInputsStructurallyConsistent:errors.size===0,
 anomalyCodes:Object.freeze([...errors].sort()),
 reproducibleFullComplexityGrowthIndependentlyEstablished:false,
 completeAttackerControlledPatternReachabilityExcluded:false,
 advisoryWithdrawnThereforeSafe:false,
 withdrawnGhsaIndependentlyAdjudicatedBySecurity:false,
 realVendorPatchAndIndependentPublisherProvenanceVerified:false,
 fullDependencySecurityGateWaived:false,
 independentThirdPartyEvidenceOrReviewerSignoffVerified:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});
export function assessBoundedTechnicalAdjudication({
 pkg,lock,rawAudit,normalizedAudit,samples=[],environment={}
}={}){
 const errors=new Set();
 const match=lock?.packages?.picomatch;
 const ver=Array.isArray(match)?match[0]:null;
 const integrity=Array.isArray(match)?match[3]:null;
 if(!object(pkg)||pkg?.type!=='module'||!object(lock?.packages)||
    ver!=='picomatch@4.0.7'||!INTEGRITY.test(integrity??''))
  errors.add('CK_REAL_FROZEN_LOCK_VERSION_OR_INTEGRITY_INVALID');
 if(object(pkg)&&object(lock?.workspaces?.[''])&&
    (JSON.stringify(pkg.dependencies??{})!==
      JSON.stringify(lock.workspaces[''].dependencies??{})||
     JSON.stringify(pkg.devDependencies??{})!==
      JSON.stringify(lock.workspaces[''].devDependencies??{})))
  errors.add('CK_FROZEN_ROOT_WORKSPACE_MISMATCH');
 let report=null,verifier=null;
 try{
  report=triageDependencyAudit(rawAudit);
  if(!object(normalizedAudit)||JSON.stringify(report)!==JSON.stringify(normalizedAudit))
   errors.add('CK_RAW_VS_NORMALIZED_AUDIT_DISAGREEMENT');
  else verifier=checkCurrentAudit(rawAudit,normalizedAudit);
 }catch{errors.add('CK_INVALID_OR_MISSING_WHOLE_LOCK_AUDIT');}
 const complete=Array.isArray(samples)&&samples.length===CASE_IDS.length;
 let timedOut=false;
 if(!complete)errors.add('CK_SAMPLE_QUORUM_NOT_COMPLETED');
 else{
  for(let i=0;i<CASE_IDS.length;i++){
   const s=samples[i],id=CASE_IDS[i];
   if(!object(s)||s.caseId!==id||
      !['COMPLETED','TIMEOUT'].includes(s.state)){
    errors.add('CK_FIXED_SAMPLE_OR_WORKER_FAILED_'+id);continue;
   }
   if(s.state==='TIMEOUT'){
    timedOut=true;
    if(s.installedVersion!==null||s.matched!==null||s.executionMs!==null)
     errors.add('CK_MALFORMED_TIMEOUT_RECEIPT_'+id);
   }else if(s.installedVersion!=='4.0.7'||typeof s.matched!=='boolean'||
    !bounded(s.executionMs))
    errors.add('CK_INSTALLED_VERSION_OR_BOUNDED_WORKER_RECEIPT_'+id);
  }
  if(new Set(samples.map(s=>s?.caseId)).size!==CASE_IDS.length)
   errors.add('CK_DUPLICATED_OR_MISSING_SAMPLE_ID');
 }
 if(environment===null||typeof environment!=='object'||Array.isArray(environment)||
    environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_JOB!=='baseline'||
    environment.GITHUB_REPOSITORY!==REPO||
    !SHA.test(environment.GITHUB_SHA??'')||
    !['refs/pull/1/merge','refs/heads/chore/phase0-foundation-20261106'].includes(
      environment.GITHUB_REF))
  errors.add('CK_GITHUB_RUN_JOB_AND_SHA_CONTEXT_INVALID');
 return outcome(errors,{
  version:ver,integrityDigest:INTEGRITY.test(integrity??'')?
    createHash('sha256').update(integrity).digest('hex'):null,
  advisoryCount:report?.advisoryCount??null,
  critical:report?.bySeverity.critical??null,
  high:report?.bySeverity.high??null,
  unknown:report?.bySeverity.unknown??null,
  advisoryObserved:report?Boolean(report.bySeverity.critical+
    report.bySeverity.high+report.bySeverity.unknown):null,
  samples:Array.isArray(samples)?samples.map(x=>object(x)?{...x}:null):[],
  completed:complete&&samples.every(x=>x?.state==='COMPLETED'),
  timedOut
 });
}
function readBounded(path,max=MAX_FILE){
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)
  throw Error('CK_SOURCE_NOT_REGULAR_OR_UNBOUNDED_'+path);
 return readFileSync(path,'utf8');
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CK only accepts zero-input --ci-hold (real frozen CI)');
 const [pkg,lock,rawAudit,normalizedAudit]=[
  JSON.parse(readBounded('package.json',65536)),
  readBunLock(readBounded('bun.lock')),
  JSON.parse(readBounded('dependency-audit.json')),
  JSON.parse(readBounded('dependency-triage.json'))];
 const samples=[];
 for(const id of CASE_IDS)samples.push(await runBoundedPicomatchSample(id));
 const decision=assessBoundedTechnicalAdjudication({
  pkg,lock,rawAudit,normalizedAudit,samples,environment:process.env
 });
 writeFileSync('phase1ck-real-picomatch-bounded-worker-hold.json',
  JSON.stringify(decision,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(decision,null,2));
 if(!decision.localAuditAndSampleInputsStructurallyConsistent||
    decision.productionReleaseAuthorized!==false||
    decision.productionReleaseBlocked!==true||
    decision.releaseDecision!=='HOLD')process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(error=>{
  console.error('CK isolated real Picomatch technical evidence denied:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
}
