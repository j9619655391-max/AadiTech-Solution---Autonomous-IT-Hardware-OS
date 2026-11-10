import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve,relative,sep,dirname} from 'node:path';

export const REQUIRED_EVIDENCE_KINDS=[
 'tls-chain','proxy-headers','listener-isolation','mysql-ca',
 'browser-mfa','encrypted-backup','restore-reconciliation','mfa-key-recovery',
 'outbox-held','security-signoff','infrastructure-signoff','restore-witness'
] as const;

export interface EvidenceFile{
 kind:string;
 path:string;
 sha256:string;
}
export interface StagingEvidenceManifest{
 schemaVersion:number;
 changeTicket:string;
 stagingOrigin:string;
 files:EvidenceFile[];
}
function under(root:string,full:string){
 const rel=relative(root,full);
 return rel!==''&&!rel.startsWith('..'+sep)&&rel!=='..'&&!isAbsolute(rel);
}
export function verifyStagingEvidenceFiles(
 manifest:StagingEvidenceManifest,rootPath:string,
 expected:{changeTicket:string;stagingOrigin:string}){
 const problems:string[]=[];
 if(!manifest||manifest.schemaVersion!==1||
    manifest.changeTicket!==expected.changeTicket||
    manifest.stagingOrigin!==expected.stagingOrigin)
  problems.push('Evidence manifest schema, origin or change ticket mismatch');
 const files=manifest?.files;
 if(!Array.isArray(files)||files.length!==REQUIRED_EVIDENCE_KINDS.length)
  problems.push('Evidence categories are incomplete');
 const seen=new Set<string>();
 let root:string|undefined;
 try{
  if(!isAbsolute(rootPath)||lstatSync(rootPath).isSymbolicLink())
   throw Error('Unsafe root');
  root=realpathSync(rootPath);
  const repo=realpathSync(process.cwd());
  if(root===repo||root.startsWith(repo+sep))
   throw Error('Evidence root must be outside source checkout');
 }catch{problems.push('Private evidence root unavailable or unsafe');}
 let checked=0;
 if(Array.isArray(files)&&files.length<=32){
  for(const item of files){
   const kind=item?.kind;
   if(typeof kind!=='string'||!(REQUIRED_EVIDENCE_KINDS as readonly string[]).includes(kind)||
      seen.has(kind)){
    problems.push('Invalid or duplicate evidence category');continue;
   }
   seen.add(kind);
   if(typeof item.path!=='string'||item.path.length>160||
      !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(item.path)||
      item.path.split('/').some(x=>!x||x==='.'||x==='..')||
      !/^[a-f0-9]{64}$/i.test(item.sha256??'')){
    problems.push('Invalid private evidence reference: '+kind);continue;
   }
   if(!root)continue;
   try{
    const file=resolve(root,item.path);
    if(!under(root,file)||lstatSync(file).isSymbolicLink())throw Error('Unsafe path');
    const actual=realpathSync(file);
    if(!under(root,actual))throw Error('Evidence file escaped root');
    const stat=lstatSync(actual);
    if(!stat.isFile()||stat.size<1||stat.size>8*1024*1024)
     throw Error('Unsafe evidence file type or size');
    const digest=createHash('sha256').update(readFileSync(actual)).digest('hex');
    if(digest!==item.sha256.toLowerCase())throw Error('SHA-256 digest mismatch');
    checked++;
   }catch{
    // Output contains category only: no filenames, file bytes, paths or secrets.
    problems.push('Missing, modified or unsafe evidence file: '+kind);
   }
  }
 }
 for(const kind of REQUIRED_EVIDENCE_KINDS)
  if(!seen.has(kind))problems.push('Required evidence missing: '+kind);
 return {
  integrityChecksPassed:problems.length===0&&checked===REQUIRED_EVIDENCE_KINDS.length,
  checkedEvidenceFileCount:checked,
  requiredEvidenceFileCount:REQUIRED_EVIDENCE_KINDS.length,
  problems,
  signerIdentityExternallyVerified:false,
  evidenceTruthExternallyVerified:false,
  productionReleaseAuthorized:false
 };
}
