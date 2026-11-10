import {createHash} from 'node:crypto';
import {lstatSync,readdirSync,readFileSync} from 'node:fs';
import {join,relative,resolve,sep} from 'node:path';
import {MIGRATIONS} from './stagingPreflight';

export interface CandidateFile{
 path:string;
 sha256:string;
 sizeBytes:number;
}
export interface CandidateSecurityAudit{
 baseline:{schemaVersion:number;developmentBaselinePassed:boolean;
  productionReleaseBlocked:boolean;productionReleaseAuthorized:boolean;
  currentCriticalHigh:number};
 triage:{schemaVersion:number;bySeverity:{
  critical:number;high:number;unknown:number;moderate:number;low:number}};
}
const MAX_ARTIFACTS=500;
const MAX_FILE_BYTES=25*1024*1024;
function checkedFile(root:string,rel:string):CandidateFile{
 const file=resolve(root,rel),r=relative(root,file);
 if(!r||r.startsWith('..'+sep)||r==='..'||r.startsWith(sep))
  throw Error('Candidate file escaped build root');
 const stat=lstatSync(file);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>MAX_FILE_BYTES)
  throw Error('Candidate artifact is missing, symlinked, empty or oversized: '+rel);
 const bytes=readFileSync(file);
 return {path:rel.replace(/\\/g,'/'),
  sha256:createHash('sha256').update(bytes).digest('hex'),sizeBytes:stat.size};
}
function walkDist(root:string,dir:string,out:string[]){
 const full=resolve(root,dir),stat=lstatSync(full);
 if(!stat.isDirectory()||stat.isSymbolicLink())
  throw Error('Build directory is missing or unsafe');
 for(const entry of readdirSync(full,{withFileTypes:true})){
  if(entry.isSymbolicLink())throw Error('Symlinks forbidden in build output');
  const rel=join(dir,entry.name);
  if(entry.isDirectory())walkDist(root,rel,out);
  else if(entry.isFile())out.push(rel);
  else throw Error('Unapproved artifact type in build');
  if(out.length>MAX_ARTIFACTS)throw Error('Too many release candidate files');
 }
}
export function captureCandidateFiles(rootPath:string):CandidateFile[]{
 const root=resolve(rootPath),paths:string[]=[];
 walkDist(root,'dist',paths);
 for(const p of ['package.json','bun.lock',...MIGRATIONS.map(m=>'database/migrations/'+m+'.sql')])
  paths.push(p);
 const unique=[...new Set(paths.map(p=>p.replace(/\\/g,'/')))].sort();
 if(unique.length!==paths.length||unique.length>MAX_ARTIFACTS||
    !unique.includes('dist/server.cjs')||!unique.includes('dist/index.html')||
    !unique.some(p=>p.startsWith('dist/assets/')))
  throw Error('Incomplete or duplicate production build artifacts');
 return unique.map(p=>checkedFile(root,p));
}
export function assessReleaseCandidate(args:{
 sourceSha:string;sourceRef:string;root:string;audit:CandidateSecurityAudit;
 generatedAt:string;
}){
 const problems:string[]=[];
 if(!/^[a-f0-9]{40}$/.test(args.sourceSha))
  throw Error('Full Git commit SHA is required');
 if(args.sourceRef!=='chore/phase0-foundation-20261106')
  throw Error('Release candidate must come from the development Draft PR branch');
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(args.generatedAt)||
    !Number.isFinite(Date.parse(args.generatedAt)))
  throw Error('Invalid UTC build timestamp');
 const audit=args.audit;
 if(!audit||audit.baseline?.schemaVersion!==1||audit.triage?.schemaVersion!==1||
    audit.baseline?.developmentBaselinePassed!==true||
    audit.baseline?.productionReleaseBlocked!==true||
    audit.baseline?.productionReleaseAuthorized!==false)
  throw Error('Security advisory baseline verification is missing or not passed');
 const levels=audit.triage.bySeverity;
 if(!levels||Object.values(levels).some(n=>!Number.isSafeInteger(n)||n<0)||
    audit.baseline.currentCriticalHigh!==levels.critical+levels.high)
  throw Error('Security audit severity counts are inconsistent');
 if(levels.critical||levels.high||levels.unknown)
  throw Error('Unresolved critical/high/unknown advisories block candidate preparation');
 const files=captureCandidateFiles(args.root);
 const lines=files.map(f=>f.path+'\0'+f.sizeBytes+'\0'+f.sha256+'\n').join('');
 const artifactSetSha256=createHash('sha256').update(lines).digest('hex');
 return {
  schemaVersion:1,
  purpose:'Development-only reproducibility record — not a deployable release or an attestation',
  gitCommitSha:args.sourceSha,
  sourceRef:args.sourceRef,
  generatedAt:args.generatedAt,
  artifactSetSha256,
  files,
  fileCount:files.length,
  currentAuditCounts:{critical:levels.critical,high:levels.high,
   unknown:levels.unknown,moderate:levels.moderate,low:levels.low},
  buildHashManifestComplete:true,
  dependencyAuditGatePassed:true,
  // A green CI / hash record alone cannot prove approved staging or restores.
  privateStagingAcceptanceIndependentlyVerified:false,
  stagingTlsAndProxyIndependentlyVerified:false,
  actualEncryptedRestoreIndependentlyVerified:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD — independent staging, disaster recovery, infrastructure and owner approvals are pending'
 };
}
