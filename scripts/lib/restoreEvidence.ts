export interface RestoreEvidence{
 targetDatabase:string;
 sourceSnapshotSha256:string;
 restoredSnapshotSha256:string;
 backupCompletedAt:string;
 restoreStartedAt:string;
 restoreCompletedAt:string;
 sourceAsOf:string;
 recoveryPointAsOf:string;
 tableCountsMatch:boolean;
 sampledRecordHashesMatch:boolean;
 mfaKeyRecoveryVerified:boolean;
 independentReviewer:string;
 reviewerSignoffAt:string;
}
export interface Objectives{maxRtoMinutes:number;maxRpoMinutes:number;}
const validTime=(s:string)=>typeof s==='string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(s)
 && Number.isFinite(Date.parse(s));
export function evaluateRestoreEvidence(e:RestoreEvidence,o:Objectives){
 const problems:string[]=[];
 if(!Number.isSafeInteger(o.maxRtoMinutes)||o.maxRtoMinutes<=0||
  !Number.isSafeInteger(o.maxRpoMinutes)||o.maxRpoMinutes<0)
  throw Error('RTO/RPO objectives must be nonnegative integer minutes, RTO > 0');
 if(!/^aaditech_staging_[a-z0-9_]+$/.test(e.targetDatabase??''))
  problems.push('Not an isolated staging database');
 if(!/^[0-9a-f]{64}$/i.test(e.sourceSnapshotSha256??'')||
    e.sourceSnapshotSha256!==e.restoredSnapshotSha256)
  problems.push('Encrypted source/restore snapshot digests missing or mismatched');
 for(const [key,value] of Object.entries({
  backupCompletedAt:e.backupCompletedAt,restoreStartedAt:e.restoreStartedAt,
  restoreCompletedAt:e.restoreCompletedAt,sourceAsOf:e.sourceAsOf,
  recoveryPointAsOf:e.recoveryPointAsOf,reviewerSignoffAt:e.reviewerSignoffAt
 }))if(!validTime(value))problems.push('Invalid UTC timestamp: '+key);
 let rtoMinutes:null|number=null,rpoMinutes:null|number=null;
 if(problems.every(p=>!p.startsWith('Invalid UTC timestamp'))){
  rtoMinutes=(Date.parse(e.restoreCompletedAt)-Date.parse(e.restoreStartedAt))/60000;
  rpoMinutes=(Date.parse(e.sourceAsOf)-Date.parse(e.recoveryPointAsOf))/60000;
  if(rtoMinutes<0||rtoMinutes>o.maxRtoMinutes)problems.push('RTO exceeded or time sequence invalid');
  if(rpoMinutes<0||rpoMinutes>o.maxRpoMinutes)problems.push('RPO exceeded or time sequence invalid');
  if(Date.parse(e.restoreStartedAt)<Date.parse(e.backupCompletedAt))
   problems.push('Restore began before backup completed');
  if(Date.parse(e.reviewerSignoffAt)<Date.parse(e.restoreCompletedAt))
   problems.push('Reviewer signed before restore completed');
 }
 if(e.tableCountsMatch!==true)problems.push('Table row counts not independently reconciled');
 if(e.sampledRecordHashesMatch!==true)problems.push('Sample hashes not reconciled');
 if(e.mfaKeyRecoveryVerified!==true)problems.push('MFA encryption key restore not verified');
 if(typeof e.independentReviewer!=='string'||e.independentReviewer.trim().length<3)
  problems.push('Independent reviewer identity missing');
 return {accepted:problems.length===0,rtoMinutes,rpoMinutes,objectives:o,problems};
}
