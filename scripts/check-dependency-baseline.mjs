import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {triageDependencyAudit} from './triage-dependencies.mjs';

const LEVELS={low:1,moderate:2,high:3,critical:4,unknown:5};
const GHSA=/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
function baselineMap(input){
 if(!input||input.schemaVersion!==1||input.kind!=='known-unresolved-development-only'||
  !Array.isArray(input.advisories))throw Error('Unrecognized development advisory baseline');
 const ids=new Map();
 for(const a of input.advisories){
  if(!a||!GHSA.test(a.id)||typeof a.packageName!=='string'||
    !Object.hasOwn(LEVELS,a.severity)||ids.has(a.id))
    throw Error('Malformed or duplicated baseline advisory');
  ids.set(a.id,{packageName:a.packageName,severity:a.severity});
 }
 return ids;
}
export function evaluateDependencyBaseline(raw,documented,baseline){
 const fresh=triageDependencyAudit(raw),known=baselineMap(baseline);
 if(!documented||documented.schemaVersion!==1||
  JSON.stringify(fresh)!==JSON.stringify(documented))
  throw Error('Triage report is missing or does not match raw Bun audit');
 const problems=[],seen=new Set(),resolved=[];
 for(const item of fresh.packages){
  for(const a of item.advisories){
   if(seen.has(a.id))throw Error('Duplicate advisory in current audit');
   seen.add(a.id);
   const prior=known.get(a.id);
   if(!prior){problems.push('New advisory requires security triage: '+a.id);continue;}
   if(prior.packageName!==item.name)
    problems.push('Changed package for '+a.id);
   if(LEVELS[a.severity]>LEVELS[prior.severity])
    problems.push('Advisory severity increased: '+a.id);
   if(a.severity==='unknown')problems.push('Unknown current severity: '+a.id);
  }
 }
 for(const id of known.keys())if(!seen.has(id))resolved.push(id);
 return {
  schemaVersion:1,developmentBaselinePassed:problems.length===0,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  currentAdvisoryCount:fresh.advisoryCount,
  currentCriticalHigh:fresh.bySeverity.critical+fresh.bySeverity.high,
  newOrEscalated:problems,
  noLongerReported:resolved.sort(),
  reason:'Baseline only prevents unreviewed advisory drift. Existing vulnerabilities remain unresolved. Production deployment never authorized by this check.'
 };
}
function main(){
 const raw=JSON.parse(readFileSync(process.argv[2]||'dependency-audit.json','utf8'));
 const triage=JSON.parse(readFileSync(process.argv[3]||'dependency-triage.json','utf8'));
 const baseline=JSON.parse(readFileSync(process.argv[4]||'docs/security/dependency-advisory-baseline.json','utf8'));
 const report=evaluateDependencyBaseline(raw,triage,baseline);
 writeFileSync('dependency-baseline-status.json',JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(!report.developmentBaselinePassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Dependency baseline verification failed:',e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
