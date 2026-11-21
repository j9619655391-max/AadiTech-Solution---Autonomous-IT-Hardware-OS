import {createHash} from 'node:crypto';
import {constants,openSync,closeSync,readSync,lstatSync,fstatSync,realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {isAbsolute,resolve,relative,sep} from 'node:path';

export const REQUIRED_EVIDENCE_KINDS=[
 'tls-chain','proxy-headers','listener-isolation','mysql-ca',
 'browser-mfa','encrypted-backup','restore-reconciliation','mfa-key-recovery',
 'outbox-held','security-signoff','infrastructure-signoff','restore-witness'
] as const;
const MAX_EVIDENCE_BYTES=8*1024*1024;
const REPO_ROOT=realpathSync(fileURLToPath(new URL('../../',import.meta.url)));
const secureOpenFlags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;

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
 return rel!==''&&rel!=='..'&&!rel.startsWith('..'+sep)&&!isAbsolute(rel);
}
function inOrUnder(root:string,full:string){
 return full===root||under(root,full);
}
function exactKeys(record:unknown,keys:readonly string[]):boolean{
 return record!==null&&typeof record==='object'&&!Array.isArray(record)&&
  Object.getPrototypeOf(record)===Object.prototype&&
  Object.keys(record).length===keys.length&&Object.keys(record).every(k=>keys.includes(k));
}
function secureEvidenceDigest(root:string,path:string){
 const target=resolve(root,path);
 if(!under(root,target))throw Error('Unsafe evidence path');
 // Reject symlinked components, even when the final destination is in-root.
 if(realpathSync(target)!==target)throw Error('Symlinked evidence path');
 const before=lstatSync(target);
 if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1)
  throw Error('Not an independent regular evidence file');
 if(!Number.isInteger(constants.O_NOFOLLOW)||!Number.isInteger(constants.O_NONBLOCK))
  throw Error('Secure file opening is unsupported');
 const fd=openSync(target,secureOpenFlags);
 try{
  const stat=fstatSync(fd);
  if(!stat.isFile()||stat.dev!==before.dev||stat.ino!==before.ino||
     stat.nlink!==1||stat.size<1||stat.size>MAX_EVIDENCE_BYTES||
     (stat.mode&0o077)!==0||
     (typeof process.getuid==='function'&&stat.uid!==process.getuid()))
   throw Error('Evidence file identity, ownership, private mode or size invalid');
  // Single descriptor; size+1 bound prevents memory exhaustion and detects
  // a concurrent append/truncate before accepting a checked evidence digest.
  const bytes=Buffer.alloc(stat.size+1);
  let count=0;
  while(count<bytes.length){
   const n=readSync(fd,bytes,count,bytes.length-count,count);
   if(!n)break;
   count+=n;
  }
  if(count!==stat.size||fstatSync(fd).size!==stat.size)
   throw Error('Evidence bytes changed while being checked');
  return createHash('sha256').update(bytes.subarray(0,count)).digest('hex');
 }finally{
  closeSync(fd);
 }
}
export function verifyStagingEvidenceFiles(
 manifest:StagingEvidenceManifest,rootPath:string,
 expected:{changeTicket:string;stagingOrigin:string}){
 const problems:string[]=[];
 if(!exactKeys(manifest,['schemaVersion','changeTicket','stagingOrigin','files'])||
    manifest.schemaVersion!==1||
    manifest.changeTicket!==expected?.changeTicket||
    manifest.stagingOrigin!==expected?.stagingOrigin)
  problems.push('Evidence manifest schema, origin or change ticket mismatch');
 const files=manifest?.files;
 if(!Array.isArray(files)||files.length!==REQUIRED_EVIDENCE_KINDS.length)
  problems.push('Evidence categories are incomplete');
 const seen=new Set<string>();
 let root:string|undefined;
 try{
  if(!isAbsolute(rootPath)||!Number.isInteger(constants.O_NOFOLLOW)||
     !Number.isInteger(constants.O_NONBLOCK))
   throw Error('Secure absolute evidence root required');
  const input=resolve(rootPath);
  const original=lstatSync(input);
  root=realpathSync(input);
  if(input!==root||!original.isDirectory()||original.isSymbolicLink()||
     (original.mode&0o077)!==0||
     (typeof process.getuid==='function'&&original.uid!==process.getuid())||
     inOrUnder(REPO_ROOT,root))
   throw Error('Private evidence root must be an owner-private directory outside checkout');
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
   if(!exactKeys(item,['kind','path','sha256'])||
      typeof item.path!=='string'||item.path.length>160||
      !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(item.path)||
      item.path.split('/').some(x=>!x||x==='.'||x==='..')||
      typeof item.sha256!=='string'||!/^[a-f0-9]{64}$/.test(item.sha256)){
    problems.push('Invalid private evidence reference: '+kind);continue;
   }
   if(!root)continue;
   try{
    const digest=secureEvidenceDigest(root,item.path);
    if(digest!==item.sha256)throw Error('Evidence fingerprint does not match');
    checked++;
   }catch{
    // Category only: do not echo raw evidence, fingerprints, paths or secrets.
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
