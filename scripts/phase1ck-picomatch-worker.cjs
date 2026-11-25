'use strict';
const {parentPort,workerData}=require('node:worker_threads');
const {performance}=require('node:perf_hooks');

// Phase 1CK: fixed, deliberately SMALL advisory-inspired samples ONLY.
// This worker is terminated by its parent on a hard wall-time deadline.
// Never accept a caller-provided pattern or input. Not a CVE exploit PoC,
// not a negative proof of ReDoS, and not a production-facing matcher.
const CASES=Object.freeze({
 control_literal:Object.freeze({pattern:'alpha*',input:'alphabet'}),
 repeated_extglob_star:Object.freeze({pattern:'+(*)',input:'aaaaaaaa!'}),
 repeated_extglob_a:Object.freeze({pattern:'+(*a)',input:'aaaaaaaa!'})
});
try{
 if(!workerData||typeof workerData!=='object'||
    Object.keys(workerData).length!==1||
    !Object.hasOwn(CASES,workerData.id))
  throw Error('CK_UNREVIEWED_WORKER_SCENARIO');
 const {pattern,input}=CASES[workerData.id];
 if(pattern.length>12||input.length>12)
  throw Error('CK_SCENARIO_INPUT_EXCEEDS_SMALL_BOUNDED_LIMIT');
 const matcher=require('picomatch');
 const version=require('picomatch/package.json').version;
 if(typeof matcher!=='function'||version!=='4.0.7')
  throw Error('CK_INSTALLED_LOCKED_MATCHER_VERSION_MISMATCH');
 const before=performance.now();
 const matched=matcher(pattern)(input);
 const duration=performance.now()-before;
 if(!Number.isFinite(duration)||duration<0||typeof matched!=='boolean')
  throw Error('CK_INVALID_WORKER_TIMING_OR_RESULT');
 parentPort.postMessage({
  caseId:workerData.id,state:'COMPLETED',
  installedVersion:version,matched,executionMs:Math.round(duration*1000)/1000
 });
}catch(error){
 parentPort.postMessage({
  caseId:typeof workerData?.id==='string'?workerData.id:'unknown',
  state:'ERROR',reason:error instanceof Error?error.message:'UNEXPECTED',
  installedVersion:null,matched:null,executionMs:null
 });
}
