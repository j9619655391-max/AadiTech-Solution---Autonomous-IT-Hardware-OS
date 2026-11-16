import {createHash} from 'node:crypto';

// Phase 1AZ: digest-only external onboarding prerequisites. This module never
// accepts credentials, public/private key material, raw legal evidence,
// executable URLs, storage API operations or a production release decision.
export const AZ_PURPOSE='AADITECH_PHASE_1AZ_EXTERNAL_READINESS_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const WITNESS_FIELDS=['witnessRef','organizationRef','administrativeAuthorityRef',
 'publicKeySpkiSha256','contractSha256','publisherPolicySha256','scope','state'];
const ARCHIVE_FIELDS=['logRef','checkpointReceiptSha256','archiveObjectSha256',
 'storageAccountSha256','objectVersionIdSha256','retentionPolicySha256',
 'encryptionKeyIdentifierSha256','claimedLockMode','legalHoldEvidenceSha256',
 'createdAt','retentionUntil','minimumRetentionDays','externalStorageState'];
const DR_FIELDS=['incidentRef','sourceCheckpointReceiptSha256','restoredCheckpointReceiptSha256',
 'sourceManifestSha256','restoredManifestSha256','archiveObjectSha256',
 'revocationSnapshotSha256','startedAt','completedAt','measuredRpoMs',
 'rtoObjectiveMs','rpoObjectiveMs','encryptedRestoreState','outboundHeld'];
const APPROVER_FIELDS=['role','reviewerRef','authorityRef','reviewRecordSha256'];
const PACKET_FIELDS=['schemaVersion','purpose','revision','previousPacketSha256','witnesses',
 'archive','recovery','approvers','releaseDecision'];

function exact(v,fields){
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.getPrototypeOf(v)!==Object.prototype||
    Object.keys(v).length!==fields.length||Object.keys(v).some(k=>!fields.includes(k)))
  throw Error('1AZ exact digest-only schema required');
}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1AZ invalid opaque reference');}
function sha(v){
 if(typeof v!=='string'||!SHA.test(v)||/^0{64}$/.test(v))throw Error('1AZ invalid evidence fingerprint');
}
function utc(v){
 if(typeof v!=='string'||!TIME.test(v)||!Number.isFinite(Date.parse(v))||
    new Date(v).toISOString()!==v)throw Error('1AZ invalid canonical UTC time');
 return Date.parse(v);
}
function int(v,low,high){
 if(!Number.isSafeInteger(v)||v<low||v>high)throw Error('1AZ invalid bounded number');
}
function assessWitnesses(witnesses){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>8)
  throw Error('1AZ requires two or more separately scoped witness candidates');
 const orgs=new Set(),admins=new Set(),ids=new Set(),keys=new Set();
 for(const w of witnesses){
  exact(w,WITNESS_FIELDS);
  id(w.witnessRef);id(w.organizationRef);id(w.administrativeAuthorityRef);
  for(const k of ['publicKeySpkiSha256','contractSha256','publisherPolicySha256'])sha(w[k]);
  if(w.scope!=='CHECKPOINT_WITNESS_ONLY'||w.state!=='CANDIDATE_UNVERIFIED')
   throw Error('1AZ witness cannot be self-promoted or broaden scope');
  if(ids.has(w.witnessRef)||orgs.has(w.organizationRef)||
     admins.has(w.administrativeAuthorityRef)||keys.has(w.publicKeySpkiSha256))
   throw Error('1AZ duplicate or common-admin witness candidates');
  orgs.add(w.organizationRef);admins.add(w.administrativeAuthorityRef);
  ids.add(w.witnessRef);keys.add(w.publicKeySpkiSha256);
 }
 return orgs.size;
}
function assessArchive(a){
 exact(a,ARCHIVE_FIELDS);
 id(a.logRef);
 for(const k of ['checkpointReceiptSha256','archiveObjectSha256',
  'storageAccountSha256','objectVersionIdSha256','retentionPolicySha256',
  'encryptionKeyIdentifierSha256','legalHoldEvidenceSha256'])sha(a[k]);
 if(a.claimedLockMode!=='COMPLIANCE'||a.externalStorageState!=='NOT_VERIFIED')
  throw Error('1AZ immutable storage evidence cannot assert trusted status');
 const start=utc(a.createdAt),end=utc(a.retentionUntil);
 int(a.minimumRetentionDays,1,3650);
 if(end<=start||end-start<a.minimumRetentionDays*86400000)
  throw Error('1AZ claimed WORM retention is insufficient');
}
function assessRecovery(r,a,now){
 exact(r,DR_FIELDS);
 id(r.incidentRef);
 for(const k of ['sourceCheckpointReceiptSha256','restoredCheckpointReceiptSha256',
  'sourceManifestSha256','restoredManifestSha256','archiveObjectSha256','revocationSnapshotSha256'])sha(r[k]);
 const started=utc(r.startedAt),ended=utc(r.completedAt);
 if(started>=ended||ended>now.getTime()+300000||ended-started>14*86400000)
  throw Error('1AZ recovery chronology invalid');
 for(const k of ['measuredRpoMs','rtoObjectiveMs','rpoObjectiveMs'])
  int(r[k],0,14*86400000);
 if(r.encryptedRestoreState!=='NOT_EXTERNALLY_VERIFIED'||r.outboundHeld!==true)
  throw Error('1AZ encrypted restore cannot self-authorize or dispatch');
 const blockers=[];
 if(r.sourceCheckpointReceiptSha256!==a.checkpointReceiptSha256||
    r.restoredCheckpointReceiptSha256!==a.checkpointReceiptSha256||
    r.archiveObjectSha256!==a.archiveObjectSha256||
    r.sourceManifestSha256!==r.restoredManifestSha256)
  blockers.push('RESTORE_DIGEST_OR_ARCHIVE_BINDING_MISMATCH');
 if(ended-started>r.rtoObjectiveMs||r.measuredRpoMs>r.rpoObjectiveMs)
  blockers.push('CLAIMED_RECOVERY_OBJECTIVES_EXCEEDED');
 return blockers;
}
function assessApprovers(approvers){
 if(!Array.isArray(approvers)||approvers.length!==3)
  throw Error('1AZ requires three independent review candidates');
 const roles=['SECURITY','OPERATIONS','OWNER'],actors=new Set(),authorities=new Set();
 approvers.forEach((a,i)=>{
  exact(a,APPROVER_FIELDS);
  id(a.reviewerRef);id(a.authorityRef);sha(a.reviewRecordSha256);
  if(a.role!==roles[i]||actors.has(a.reviewerRef)||authorities.has(a.authorityRef))
   throw Error('1AZ review requires distinct claimed people/authorities');
  actors.add(a.reviewerRef);authorities.add(a.authorityRef);
 });
}
export function phase1AzAssessReadiness(packet=null,{now=new Date()}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('1AZ invalid assessment time');
 const external=['EXTERNAL_WITNESS_ADMINISTRATION_UNAUTHENTICATED',
  'OBJECT_LOCK_IMMUTABILITY_NOT_EXTERNALLY_ATTESTED',
  'ENCRYPTED_RESTORE_AND_RTO_RPO_NOT_INDEPENDENTLY_WITNESSED',
  'PROVIDER_RCAI_CCA_MCA_REVOCATION_APPROVAL_PENDING'];
 if(packet===null) return Object.freeze({phase:'1AZ',packetInspected:false,
  internalEvidenceConsistent:false,externallyAuthenticated:false,
  immutableStorageVerified:false,realDRRestoreVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',blockerCodes:Object.freeze([...external,'NO_ONBOARDING_PACKET'].sort())});
 exact(packet,PACKET_FIELDS);
 if(packet.schemaVersion!==1||packet.purpose!==AZ_PURPOSE||packet.releaseDecision!=='HOLD')
  throw Error('1AZ cannot promote release');
 int(packet.revision,1,1000000);
 if(packet.revision===1&&packet.previousPacketSha256!==null)
  throw Error('1AZ genesis cannot have an ancestor');
 if(packet.revision>1)sha(packet.previousPacketSha256);
 const candidateCount=assessWitnesses(packet.witnesses);
 assessArchive(packet.archive);assessApprovers(packet.approvers);
 const issues=assessRecovery(packet.recovery,packet.archive,now);
 if(utc(packet.archive.createdAt)>now.getTime()+300000)
  issues.push('FUTURE_ARCHIVE_CLAIM');
 const canonical=[
  packet.schemaVersion,packet.purpose,packet.revision,packet.previousPacketSha256,
  packet.witnesses.map(w=>WITNESS_FIELDS.map(k=>w[k])),
  ARCHIVE_FIELDS.map(k=>packet.archive[k]),
  DR_FIELDS.map(k=>packet.recovery[k]),
  packet.approvers.map(a=>APPROVER_FIELDS.map(k=>a[k])),
  packet.releaseDecision
 ];
 const packetSha256=createHash('sha256').update('AADITECH-PHASE-1AZ-READINESS-V1\0')
   .update(JSON.stringify(canonical)).digest('hex');
 return Object.freeze({phase:'1AZ',packetInspected:true,revision:packet.revision,
  packetSha256,selfDeclaredWitnessCandidateCount:candidateCount,
  internalEvidenceConsistent:issues.length===0,
  externallyAuthenticated:false,immutableStorageVerified:false,
  realDRRestoreVerified:false,measuredRtoIndependent:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',blockerCodes:Object.freeze([...external,...issues].sort())});
}
