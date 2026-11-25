import {constants,openSync,closeSync,readSync,lstatSync,fstatSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve,relative,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {TextDecoder} from 'node:util';
import type {StagingAcceptancePackage} from './stagingAcceptance';
import type {StagingEvidenceManifest} from './stagingEvidenceIntegrity';

// Phase 1AT: never infer the checkout from the operator's current directory.
const CHECKOUT=realpathSync(fileURLToPath(new URL('../../',import.meta.url)));
const MAX_ACCEPTANCE_BYTES=128*1024;
const MAX_MANIFEST_BYTES=32*1024;
const decoder=new TextDecoder('utf-8',{fatal:true});
const ACCEPTANCE_FIELDS=[
 'changeTicket','stagingOrigin','probe','operatorId','independentSecurityReviewerId',
 'independentInfrastructureReviewerId','securityApprovalReference',
 'infrastructureApprovalReference','reviewerSignedAt','networkIsolationEvidenceRef',
 'proxyHeaderRewriteEvidenceRef','mysqlCaEvidenceRef','realHttpsBrowserMfaEvidenceRef',
 'outboundDispatchHeldEvidenceRef','actualRestoreReview'
] as const;
const PROBE_FIELDS=[
 'targetOrigin','changeTicket','observedAt','observedChecksPassed','failures',
 'proxyIpOverwriteIndependentlyVerified','directListenerIsolationIndependentlyVerified',
 'databaseTlsIndependentlyVerified','productionReleaseAuthorized'
] as const;
const RECOVERY_FIELDS=[
 'changeTicket','evidenceLocation','operatorId','independentWitnessId',
 'witnessApprovalReference','isolatedNetworkVerified','outboundDispatchDisabled',
 'stagingTlsVerified','evidence','objectives'
] as const;
const RESTORE_FIELDS=[
 'targetDatabase','sourceSnapshotSha256','restoredSnapshotSha256','backupCompletedAt',
 'restoreStartedAt','restoreCompletedAt','sourceAsOf','recoveryPointAsOf',
 'tableCountsMatch','sampledRecordHashesMatch','mfaKeyRecoveryVerified',
 'independentReviewer','reviewerSignoffAt'
] as const;

function exactRecord(value:unknown,keys:readonly string[]):boolean{
 if(value===null||typeof value!=='object'||Array.isArray(value)||
   Object.getPrototypeOf(value)!==Object.prototype)return false;
 const actual=Object.keys(value);
 return actual.length===keys.length&&actual.every(key=>keys.includes(key));
}
function within(root:string,path:string){
 const rel=relative(root,path);
 return rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep));
}
function privateParent(parent:string){
 const actual=realpathSync(parent);
 const stat=lstatSync(parent);
 if(actual!==parent||within(CHECKOUT,actual)||!stat.isDirectory()||
    stat.isSymbolicLink()||(stat.mode&0o077)!==0||
    (typeof process.getuid==='function'&&stat.uid!==process.getuid()))
  throw Error('Unapproved staging review directory');
}

function readPrivateJsonFile(path:string,maxBytes:number):unknown{
 if(typeof path!=='string'||!isAbsolute(path))throw Error('Absolute private input required');
 const target=resolve(path);
 if(target!==path||realpathSync(target)!==target||within(CHECKOUT,target))
  throw Error('Unsafe staging review input location');
 privateParent(dirname(target));
 if(!Number.isInteger(constants.O_NOFOLLOW)||!Number.isInteger(constants.O_NONBLOCK))
  throw Error('Secure file opening unavailable');
 const before=lstatSync(target);
 if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1)
  throw Error('Private review input must be one regular file');
 const fd=openSync(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const initial=fstatSync(fd);
  if(!initial.isFile()||initial.nlink!==1||initial.dev!==before.dev||
     initial.ino!==before.ino||initial.size<1||initial.size>maxBytes||
     (initial.mode&0o077)!==0||
     (typeof process.getuid==='function'&&initial.uid!==process.getuid()))
   throw Error('Private staging input identity/owner/permissions/size invalid');
  const bytes=Buffer.alloc(initial.size+1);
  let length=0;
  while(length<bytes.length){
   const read=readSync(fd,bytes,length,bytes.length-length,length);
   if(read===0)break;
   length+=read;
  }
  const after=fstatSync(fd);
  if(length!==initial.size||after.size!==initial.size||
     after.mtimeMs!==initial.mtimeMs||after.ctimeMs!==initial.ctimeMs)
   throw Error('Private staging input changed during inspection');
  return JSON.parse(decoder.decode(bytes.subarray(0,length))) as unknown;
 }finally{closeSync(fd);}
}

function assertStagingShape(input:unknown):asserts input is StagingAcceptancePackage{
 if(!exactRecord(input,ACCEPTANCE_FIELDS))
  throw Error('Unexpected staging acceptance fields');
 const p=input as unknown as Record<string,unknown>;
 if(!exactRecord(p.probe,PROBE_FIELDS)||
    !exactRecord(p.actualRestoreReview,RECOVERY_FIELDS))
  throw Error('Unexpected probe or recovery fields');
 const probe=p.probe as Record<string,unknown>;
 const recovery=p.actualRestoreReview as Record<string,unknown>;
 if(!Array.isArray(probe.failures)||probe.failures.length>12||
    probe.failures.some(item=>typeof item!=='string'||item.length>256)||
    !exactRecord(recovery.evidence,RESTORE_FIELDS)||
    !exactRecord(recovery.objectives,['maxRtoMinutes','maxRpoMinutes']))
  throw Error('Unexpected nested staging acceptance fields');
}

function assertManifestShape(input:unknown):asserts input is StagingEvidenceManifest{
 if(!exactRecord(input,['schemaVersion','changeTicket','stagingOrigin','files']))
  throw Error('Unexpected staging manifest fields');
 const obj=input as Record<string,unknown>;
 if(!Array.isArray(obj.files)||obj.files.length!==12||
    obj.files.some(item=>!exactRecord(item,['kind','path','sha256'])))
  throw Error('Unexpected staging evidence inventory');
}

/** Offline *administrative* input, never external authentication or release. */
export function readPrivateStagingReviewInputs(acceptancePath:string,manifestPath:string){
 if(!isAbsolute(acceptancePath)||!isAbsolute(manifestPath))
  throw Error('Two absolute private JSON paths required');
 const a=resolve(acceptancePath),m=resolve(manifestPath);
 if(a===m||dirname(a)!==dirname(m))
  throw Error('Private staging JSON files must share one controlled parent');
 const acceptance=readPrivateJsonFile(a,MAX_ACCEPTANCE_BYTES);
 const manifest=readPrivateJsonFile(m,MAX_MANIFEST_BYTES);
 assertStagingShape(acceptance);
 assertManifestShape(manifest);
 return {acceptance,manifest};
}
