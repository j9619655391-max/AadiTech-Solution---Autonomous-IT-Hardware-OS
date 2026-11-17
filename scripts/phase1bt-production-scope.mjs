import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1BT: inspect the real Bun lock dependency graph for production closure.
// This is a containment check, NOT remediation of unpatched picomatch itself.
// A green result cannot satisfy the separate zero-Critical/High CI audit.
export const BUILD_ONLY=Object.freeze({
 'vite':'6.4.5',
 '@tailwindcss/vite':'^4.1.14',
 '@vitejs/plugin-react':'^5.0.4'
});
export function readBunLock(text){
 if(typeof text!=='string'||text.length>1024*1024)
  throw Error('Missing/oversize Bun v2 lock');
 // Bun emits JSON with trailing commas. No comments or JS evaluation.
 const data=JSON.parse(text.replace(/,\s*([}\]])/g,'$1'));
 if(data?.lockfileVersion!==2||!data?.workspaces?.['']||
    !data?.packages||typeof data.packages!=='object')
  throw Error('Unsupported Bun lock data');
 return data;
}
function sameObject(a,b){
 if(!a||!b||typeof a!=='object'||typeof b!=='object'||
    Array.isArray(a)||Array.isArray(b))return false;
 const left=Object.entries(a).sort(([x],[y])=>x.localeCompare(y));
 const right=Object.entries(b).sort(([x],[y])=>x.localeCompare(y));
 return JSON.stringify(left)===JSON.stringify(right);
}
export function assessProductionDependencyClosure(pkg,lock,serverSource){
 const problems=[],workspace=lock?.workspaces?.[''],packages=lock?.packages;
 if(!pkg||typeof pkg!=='object'||!workspace||!packages||
    typeof serverSource!=='string')
  throw Error('Incomplete production dependency verification inputs');
 if(!sameObject(pkg.dependencies,workspace.dependencies))
  problems.push('Package/Bun production dependency constraints mismatch');
 if(!sameObject(pkg.devDependencies,workspace.devDependencies))
  problems.push('Package/Bun development dependency constraints mismatch');
 for(const [name,version] of Object.entries(BUILD_ONLY)){
  if(Object.hasOwn(pkg.dependencies??{},name)||
     Object.hasOwn(workspace.dependencies??{},name)||
     pkg.devDependencies?.[name]!==version||
     workspace.devDependencies?.[name]!==version)
   problems.push('Build-only package not isolated or pinned: '+name);
 }
 if(/(?:\bfrom\s*['"]vite['"]|\brequire\s*\(\s*['"]vite['"])/.test(serverSource))
  problems.push('Vite imported at module evaluation outside production path gate');
 if(!/process\.env\.NODE_ENV\s*!==\s*['"]production['"]\s*\)\s*\{[\s\S]{0,260}?\bawait\s+import\s*\(\s*['"]vite['"]\s*\)/.test(serverSource))
  problems.push('Development-only guarded dynamic Vite import missing');
 const roots=Object.keys(pkg.dependencies??{}),seen=new Set(),routes=new Map(),
  queue=roots.map(name=>({name,path:[name]}));
 let work=0;
 while(queue.length){
  if(++work>10000){problems.push('Dependency traversal exceeded strict bound');break;}
  const {name,path}=queue.shift();
  if(seen.has(name))continue;
  seen.add(name);routes.set(name,path);
  if(!/^(?:@[-a-z0-9_.]+\/)?[-a-z0-9_.]+$/.test(name)){
   problems.push('Unrecognized locked package key: '+name);continue;
  }
  const entry=packages[name];
  if(!Array.isArray(entry)||typeof entry[0]!=='string'||!entry[0].startsWith(name+'@')){
   problems.push('Missing or unpinned production package in lock: '+name);continue;
  }
  const meta=entry[2];
  if(meta&&typeof meta!=='object'){problems.push('Malformed dependency edges: '+name);continue;}
  const edges={...meta?.dependencies,...meta?.optionalDependencies};
  for(const dep of Object.keys(edges)){
   if(!seen.has(dep))queue.push({name:dep,path:[...path,dep]});
  }
 }
 for(const name of Object.keys(BUILD_ONLY)){
  if(seen.has(name))problems.push('Build-only module production-reachable: '+routes.get(name)?.join(' -> '));
 }
 if(seen.has('picomatch'))
  problems.push('Unpatched picomatch production-reachable: '+routes.get('picomatch')?.join(' -> '));
 // This intentionally leaves a known-vulnerable development dependency in
 // the lock; the global advisory audit MUST remain active and may stay red.
 const knownVersion=packages?.picomatch?.[0]??null;
 const result={
  schemaVersion:1,phase:'1BT',
  productionDependencyClosureLocallyConsistent:problems.length===0,
  productionDependencyCount:seen.size,
  productionContainsPicomatch:seen.has('picomatch'),
  productionContainsVite:seen.has('vite'),
  picomatchLockedVersion:knownVersion,
  picomatchGHSA:'GHSA-fc5q-39xc-vjpf',
  unpatchedDevelopmentDependencyRemains:knownVersion==='picomatch@4.0.7',
  independentSecurityApprovalVerified:false,
  upstreamVendorFixVerified:false,
  criticalHighDependencyAuditStillRequired:true,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',
  anomalyCodes:problems.sort()
 };
 return Object.freeze(result);
}
function main(){
 const pkg=JSON.parse(readFileSync('package.json','utf8'));
 const lock=readBunLock(readFileSync('bun.lock','utf8'));
 const server=readFileSync('server.ts','utf8');
 const result=assessProductionDependencyClosure(pkg,lock,server);
 writeFileSync('phase1bt-production-closure-report.json',
  JSON.stringify(result,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(result,null,2));
 if(!result.productionDependencyClosureLocallyConsistent)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Phase 1BT dependency isolation failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
