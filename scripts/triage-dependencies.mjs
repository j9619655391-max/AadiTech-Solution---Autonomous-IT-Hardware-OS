import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const LEVELS=['critical','high','moderate','low','unknown'];
const ADVISORY=/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
const severityRank=Object.fromEntries(LEVELS.map((level,i)=>[level,i]));
function remediationFor(name){
 if(['proxy-addr','body-parser','qs'].includes(name))
  return 'Review Express production dependency tree; update to a verified fixed version in a separate lockfile-tested security PR';
 if(name==='source-map-js')return 'Review source-map-js dependency path, patched release and build-only exposure';
 if(name==='vite')return 'Review Vite dev-server exposure; upgrade to a supported patched version and rerun build/browser CI';
 return 'Trace direct/transitive dependency, verify patch version and reachability';
}
export function triageDependencyAudit(raw){
 if(raw===null||typeof raw!=='object'||Array.isArray(raw))
  throw Error('Expected Bun audit JSON map of packages to advisories');
 const packages=[],summary={critical:0,high:0,moderate:0,low:0,unknown:0};
 for(const [name,items] of Object.entries(raw)){
  if(!/^[a-zA-Z0-9@._/-]{1,180}$/.test(name)||!Array.isArray(items))
   throw Error('Malformed package advisory entry');
  const advisories=[];
  for(const item of items){
   if(!item||typeof item!=='object'||Array.isArray(item)||
      typeof item.severity!=='string'||typeof item.url!=='string')
    throw Error('Malformed advisory details');
   const severity=LEVELS.includes(item.severity.toLowerCase())?
    item.severity.toLowerCase():'unknown';
   const ghsa=item.url.match(/^https:\/\/github\.com\/advisories\/(GHSA-[a-z0-9-]+)$/i)?.[1]??'';
   if(!ADVISORY.test(ghsa))throw Error('Invalid GitHub security advisory URL');
   summary[severity]++;
   advisories.push({id:ghsa,severity,url:item.url,
     title:typeof item.title==='string'?item.title.slice(0,250):'Unnamed advisory',
     vulnerableVersions:typeof item.vulnerable_versions==='string'?
      item.vulnerable_versions.slice(0,160):'unknown'});
  }
  advisories.sort((a,b)=>severityRank[a.severity]-severityRank[b.severity]||
    a.id.localeCompare(b.id));
  packages.push({name,highestSeverity:advisories[0]?.severity??'none',
   advisories,reviewAction:remediationFor(name)});
 }
 packages.sort((a,b)=> (severityRank[a.highestSeverity]??99)-
  (severityRank[b.highestSeverity]??99)||a.name.localeCompare(b.name));
 const total=Object.values(summary).reduce((a,b)=>a+b,0);
 return {schemaVersion:1,source:'bun audit --json',advisoryCount:total,
  affectedPackageCount:packages.filter(p=>p.advisories.length).length,
  bySeverity:summary,requiresManualSecurityApproval:total>0,
  productionReady:false,dependencyUpdatesPerformed:false,
  limitations:'Advisory match only; reachability, exploitability and fix versions require human investigation.',
  packages};
}
function main(){
 const input=process.argv[2]??'dependency-audit.json';
 const output=process.argv[3]??'dependency-triage.json';
 const report=triageDependencyAudit(JSON.parse(readFileSync(input,'utf8')));
 writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log('Dependency triage:',JSON.stringify({
  total:report.advisoryCount,packages:report.affectedPackageCount,
  severity:report.bySeverity,requiresManualSecurityApproval:report.requiresManualSecurityApproval
 }));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Dependency triage unavailable:',e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
