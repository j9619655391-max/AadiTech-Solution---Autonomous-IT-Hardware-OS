import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {triageDependencyAudit} from './triage-dependencies.mjs';

export const REVIEWED_PATCHES=Object.freeze({
 'proxy-addr':'2.0.8','body-parser':'1.20.9',
 'source-map-js':'1.2.2','qs':'6.16.1','vite':'6.4.5'
});
export const REMEDIATED_GHSA=new Set([
 'GHSA-jqcg-44mw-7w3h','GHSA-27r3-jxmh-p828',
 'GHSA-68fv-2mgg-jv7q','GHSA-587h-7wmj-h5pm'
]);
export function checkLockedPatches(pkg,lock){
 const problems=[];
 const workspace=lock?.workspaces?.[''];
 if(!workspace||!lock?.packages)throw Error('Invalid Bun lock format');
 for(const [name,wanted] of Object.entries(REVIEWED_PATCHES)){
  const actual=lock.packages[name]?.[0];
  if(actual!==name+'@'+wanted)problems.push('Unexpected locked version for '+name);
  if(name==='vite'){
   if(pkg.dependencies?.vite!==wanted||pkg.devDependencies?.vite!==wanted)
    problems.push('Vite dependency constraints are not pinned');
  }else if(pkg.overrides?.[name]!==wanted)
   problems.push('Missing reviewed override: '+name);
 }
 if(workspace.dependencies?.vite!==REVIEWED_PATCHES.vite||
   workspace.devDependencies?.vite!==REVIEWED_PATCHES.vite)
  problems.push('Bun workspace Vite constraint is not pinned');
 return {lockedPatchVersionsVerified:problems.length===0,problems,
  productionReleaseAuthorized:false};
}
export function checkCurrentAudit(raw,normalized){
 const fresh=triageDependencyAudit(raw);
 if(JSON.stringify(fresh)!==JSON.stringify(normalized))
  throw Error('Raw/normalized dependency audit mismatch');
 const problems=[];
 if(fresh.bySeverity.critical||fresh.bySeverity.high||fresh.bySeverity.unknown)
  problems.push('Critical, high or unknown-severity advisories still found');
 for(const pkg of fresh.packages)
  for(const issue of pkg.advisories)
   if(REMEDIATED_GHSA.has(issue.id))
    problems.push('Previously targeted advisory still found: '+issue.id);
 return {criticalHighAuditPassed:problems.length===0,
  currentCritical: fresh.bySeverity.critical,currentHigh:fresh.bySeverity.high,
  moderate:fresh.bySeverity.moderate,low:fresh.bySeverity.low,
  problems,productionReleaseAuthorized:false};
}
function main(){
 const pkg=JSON.parse(readFileSync('package.json','utf8'));
 // Bun's v2 JSONC lock permits trailing commas. Strip those without mutating file.
 const lock=JSON.parse(readFileSync('bun.lock','utf8').replace(/,\s*([}\]])/g,'$1'));
 const versions=checkLockedPatches(pkg,lock);
 const raw=JSON.parse(readFileSync('dependency-audit.json','utf8'));
 const triage=JSON.parse(readFileSync('dependency-triage.json','utf8'));
 const audit=checkCurrentAudit(raw,triage);
 console.log(JSON.stringify({versions,audit},null,2));
 if(!versions.lockedPatchVersionsVerified||!audit.criticalHighAuditPassed)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Dependency security remediation verification failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
