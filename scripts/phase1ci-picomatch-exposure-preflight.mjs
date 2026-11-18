import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock,assessProductionDependencyClosure}
 from './phase1bt-production-scope.mjs';

// Phase 1CI: real frozen Bun lock reverse-edge and entrypoint reachability
// inventory for GHSA-fc5q-39xc-vjpf. This records build-only exposure and
// detects newly introduced routes. It NEVER patches the vendor package,
// accepts a waiver or turns a successful scoped audit into a global PASS.
export const VULNERABLE='picomatch@4.0.7';
export const ADVISORY='GHSA-fc5q-39xc-vjpf';
export const EXPECTED_INBOUND=Object.freeze([
 Object.freeze({name:'fdir',kind:'peerDependencies',range:'^3 || ^4'}),
 Object.freeze({name:'tinyglobby',kind:'dependencies',range:'^4.0.4'}),
 Object.freeze({name:'vite',kind:'dependencies',range:'^4.0.2'})
]);
export const EXPECTED_LOCK=Object.freeze({
 picomatch:'picomatch@4.0.7',
 tinyglobby:'tinyglobby@0.2.17',fdir:'fdir@6.5.0',vite:'vite@6.4.5',
 integrity:'sha512-qcJu88Q2IWqJsDD529JKMdwGm/dvInW4HvQnRwiH9JtihJvzGOscDtHE3x1pBKeUOTysQ8kVmLnJ2kJu7yhcGA=='
});
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const NAME=/^(?:@[-a-z0-9_.]+\/)?[-a-z0-9_.]+$/;
const SHA=/^[0-9a-f]{40}$/;
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const sorted=a=>[...a].sort((x,y)=>x.localeCompare(y));
function directEdges(meta){
 if(!obj(meta))return [];
 const names=[];
 for(const kind of ['dependencies','optionalDependencies']){
  const group=meta[kind];
  if(!obj(group))continue;
  for(const name of Object.keys(group))names.push(name);
 }
 return sorted([...new Set(names)]);
}
function findRoute(roots,target,packages){
 const queue=sorted(roots).map(name=>[name]),seen=new Set();
 let expanded=0;
 while(queue.length){
  if(++expanded>4000)return {route:null,overflow:true};
  const path=queue.shift(),name=path.at(-1);
  if(name===target)return {route:path,overflow:false};
  if(seen.has(name))continue;
  seen.add(name);
  if(!NAME.test(name)||!Array.isArray(packages?.[name]))continue;
  for(const next of directEdges(packages[name][2])){
   if(!seen.has(next)&&path.length<40)queue.push([...path,next]);
  }
 }
 return {route:null,overflow:false};
}
export function assessLockedPicomatchExposure({
 pkg,lock,serverSource,viteConfigSource,environment={}
}={}){
 const problems=new Set();
 const packages=lock?.packages,workspace=lock?.workspaces?.[''];
 if(!obj(pkg)||!obj(packages)||!obj(workspace)||
   !obj(pkg.dependencies)||!obj(pkg.devDependencies)||
   typeof serverSource!=='string'||typeof viteConfigSource!=='string'){
  problems.add('CI_INPUTS_OR_LOCK_GRAPH_MALFORMED');
  return createResult(problems,null,[],[],[],null,0);
 }
 const baseline=assessProductionDependencyClosure(pkg,lock,serverSource);
 if(!baseline.productionDependencyClosureLocallyConsistent||
    baseline.productionContainsPicomatch||baseline.productionContainsVite)
  problems.add('CI_PRODUCTION_DEPENDENCY_SCOPE_BREACHED');
 if(Object.hasOwn(pkg.dependencies,'picomatch')||
    Object.hasOwn(pkg.devDependencies,'picomatch')||
    Object.hasOwn(workspace.dependencies??{},'picomatch')||
    Object.hasOwn(workspace.devDependencies??{},'picomatch'))
  problems.add('CI_PICOMATCH_DIRECT_WORKSPACE_INTRODUCER');
 for(const [name,expected] of Object.entries(EXPECTED_LOCK)){
  if(name==='integrity')continue;
  if(packages[name]?.[0]!==expected)
   problems.add('CI_UNREVIEWED_LOCKED_BUILD_PACKAGE_'+name.toUpperCase());
 }
 if(packages.picomatch?.[3]!==EXPECTED_LOCK.integrity)
  problems.add('CI_PICOMATCH_LOCKED_TARBALL_INTEGRITY_DRIFT');
 if(packages.picomatch?.[1]!==''||
    !obj(packages.picomatch?.[2])||
    Object.keys(packages.picomatch[2]).length!==0)
  problems.add('CI_PICOMATCH_PACKAGE_METADATA_DRIFT');
 const parents=[];
 const keys=Object.keys(packages);
 if(keys.length>1500)problems.add('CI_LOCK_GRAPH_EXCESS_PACKAGE_COUNT');
 for(const name of keys.slice(0,1501)){
  const tuple=packages[name];
  const declared=Array.isArray(tuple)&&typeof tuple[0]==='string'?
   tuple[0].slice(0,tuple[0].lastIndexOf('@')):'';
  if(typeof name!=='string'||name.length>160||
    !/^[@a-z0-9._/-]+$/.test(name)||
    !Array.isArray(tuple)||tuple.length!==4||
    !NAME.test(declared)||
    !(name===declared||name.endsWith('/'+declared))||
    !obj(tuple[2])){
   problems.add('CI_UNBOUNDED_OR_MALFORMED_LOCK_NODE');
   continue;
  }
  for(const kind of ['dependencies','optionalDependencies','peerDependencies']){
   const edges=tuple[2][kind];
   if(edges!==undefined&&!obj(edges)){
    problems.add('CI_UNBOUNDED_OR_MALFORMED_DEPENDENCY_EDGES');
    continue;
   }
   if(edges&&Object.hasOwn(edges,'picomatch')){
    if(typeof edges.picomatch!=='string'||edges.picomatch.length>96)
     problems.add('CI_INVALID_PICOMATCH_EDGE_RANGE');
    parents.push({name,kind,range:edges.picomatch});
   }
  }
 }
 parents.sort((a,b)=>a.name.localeCompare(b.name)||a.kind.localeCompare(b.kind));
 if(JSON.stringify(parents)!==JSON.stringify(EXPECTED_INBOUND))
  problems.add('CI_UNREVIEWED_PICOMATCH_INTRODUCER_OR_EDGE_DRIFT');
 if(packages.fdir?.[2]?.optionalPeers?.includes('picomatch')!==true)
  problems.add('CI_FDIR_OPTIONAL_PEER_POLICY_DRIFT');
 const productionRoots=Object.keys(pkg.dependencies);
 const devRoots=Object.keys(pkg.devDependencies);
 const prod=findRoute(productionRoots,'picomatch',packages);
 const directDev=findRoute(devRoots,'picomatch',packages);
 const via={};
 for(const parent of ['tinyglobby','vite']){
  const result=findRoute(devRoots,parent,packages);
  via[parent]=result.route?[...result.route,'picomatch']:null;
  if(!result.route||result.overflow)
   problems.add('CI_EXPECTED_DEV_INTRODUCER_NOT_REACHABLE_'+parent.toUpperCase());
 }
 if(prod.route||prod.overflow)
  problems.add('CI_VULNERABLE_PICOMATCH_REACHABLE_FROM_PRODUCTION_ROOT');
 if(!directDev.route||directDev.overflow)
  problems.add('CI_EXPECTED_BUILD_ONLY_PICOMATCH_PATH_MISSING');
 // This source check is an explicit two-entrypoint boundary, NOT a full
 // repository-wide source scan or proof of no runtime dynamic code loading.
 const importRx=/(?:\bfrom\s*['"]|\brequire\s*\(\s*['"]|\bimport\s*\(\s*['"])(?:picomatch|tinyglobby|fdir)(?:\/[^'"]*)?['"]/;
 if(importRx.test(serverSource))
  problems.add('CI_SERVER_ENTRYPOINT_IMPORTS_VULNERABLE_BUILD_MATCHER');
 if(importRx.test(viteConfigSource))
  problems.add('CI_UNREVIEWED_VITE_CONFIG_MATCHER_IMPORT');
 if(!/host:\s*['"]127\.0\.0\.1['"]/.test(viteConfigSource)||
    !/allowedHosts:\s*\[\s*['"]localhost['"]\s*,\s*['"]127\.0\.0\.1['"]\s*\]/.test(viteConfigSource)||
    !/strictPort:\s*true/.test(viteConfigSource)||
    !/cors:\s*false/.test(viteConfigSource)||
    !/hmr:\s*false/.test(viteConfigSource)||
    !/fs:\s*\{\s*strict:\s*true\s*\}/.test(viteConfigSource))
  problems.add('CI_DEV_SERVER_LOOPBACK_AND_RESTRICTED_MATCHER_BOUNDARY_DRIFT');
 if(!/process\.env\.DISABLE_HMR\s*===\s*['"]true['"]\s*\?\s*null\s*:\s*\{\s*\}/.test(viteConfigSource))
  problems.add('CI_DEV_WATCHER_ISOLATION_OPTION_MISSING');
 if(!obj(environment))problems.add('CI_UNTRUSTED_RUN_CONTEXT');
 else if(environment.CI==='true'||environment.GITHUB_ACTIONS==='true'){
  if(environment.CI!=='true'||environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_REPOSITORY!==REPO||
    !SHA.test(environment.GITHUB_SHA??'')||
    !/^(?:refs\/pull\/1\/merge|refs\/heads\/chore\/phase0-foundation-20261106)$/.test(environment.GITHUB_REF??''))
   problems.add('CI_UNTRUSTED_RUN_CONTEXT');
 }
 return createResult(problems,baseline,parents,prod.route??[],
   devRoots, {via,representative:directDev.route,overflow:prod.overflow||directDev.overflow},keys.length);
}
function createResult(problems,baseline,parents,productionPath,devRoots,dev,packageCount){
 const anomalies=sorted(problems);
 return Object.freeze({
  phase:'1CI',schemaVersion:1,kind:'REAL_LOCKED_BUILD_MATCHER_EXPOSURE_HARD_HOLD',
  inspectedPackageCount:packageCount,
  picomatchAdvisory:ADVISORY,picomatchLockedVersion:EXPECTED_LOCK.picomatch,
  directLockedIntroducers:parents,
  representativeProductionRootRoute:productionPath.length?productionPath:null,
  representativeDevelopmentRootRoute:dev?.representative??null,
  reviewedIntroducerRoutes:dev?.via??null,
  inspectedDevRootCount:devRoots.length,
  declaredBuildOnlyIsolationLocallyConsistent:baseline?.productionDependencyClosureLocallyConsistent===true&&
    productionPath.length===0,
  newUnreviewedIntroductionRejected:anomalies.length>0,
  localRealLockSelectedEntrypointsConsistent:anomalies.length===0,
  anomalyCodes:Object.freeze(anomalies),
  // A scoped local graph inventory does NOT validate the installed global
  // dependency advisory closure, vendor patch or external release authority.
  wholeRepositoryRuntimeSourceGraphExhaustivelyScanned:false,
  actualUntrustedPatternReachabilityProvenAbsent:false,
  actualUpstreamPatchedReleaseVerified:false,
  globalZeroCriticalHighAuditPassed:false,
  independentlyAuthenticatedSecurityAndBusinessApprovals:false,
  genuineEmudhraAndCcaRcaIdentityVerified:false,
  remoteWormRetentionDrAndForkPersistenceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function safeText(path,max){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>max)
  throw Error('CI missing or invalid selected source: '+path);
 return readFileSync(path,'utf8');
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CI only supports read-only zero-input --ci-hold');
 const pkg=JSON.parse(safeText('package.json',65536));
 const lock=readBunLock(safeText('bun.lock',1024*1024));
 const serverSource=safeText('server.ts',524288);
 const viteConfigSource=safeText('vite.config.ts',65536);
 const verdict=assessLockedPicomatchExposure({
  pkg,lock,serverSource,viteConfigSource,environment:process.env
 });
 writeFileSync('phase1ci-locked-matchers-exposure-hold.json',
  JSON.stringify(verdict,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(verdict,null,2));
 if(!verdict.localRealLockSelectedEntrypointsConsistent||
    verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||
    verdict.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('CI actual build dependency exposure HARD HOLD failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
