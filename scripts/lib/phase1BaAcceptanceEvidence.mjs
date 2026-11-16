import {createHash,createPublicKey,verify as verifyEd} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {ANCHOR_PURPOSE,phase1AyVerifyInclusion} from './phase1AyWitnessArchiveRecovery.mjs';

// Phase 1BA is OFFLINE proof inspection, not an external trust enrollment API.
// A caller-provided public key is a cryptographic test key, not an independently
// authenticated CA/witness/storage root or legally verified approver.
export const BA_WITNESS_PURPOSE='AADITECH_PHASE_1BA_WITNESS_ATTESTATION_HOLD_V1';
export const BA_STORAGE_PURPOSE='AADITECH_PHASE_1BA_OBJECT_LOCK_ATTESTATION_HOLD_V1';
export const BA_DR_PURPOSE='AADITECH_PHASE_1BA_RESTORE_ATTESTATION_HOLD_V1';
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const PIN=['role','reviewerRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIGNATURE=['reviewerRef','keyId','signatureBase64'];
const WITNESS=['schemaVersion','purpose','packetSha256','witnessRef','organizationRef',
 'administrativeAuthorityRef','logRef','checkpointReceiptSha256','archiveObjectSha256',
 'treeSize','leafIndex','rootSha256','observedAt','expiresAt','releaseDecision'];
const STORAGE=['schemaVersion','purpose','packetSha256','logRef','checkpointReceiptSha256',
 'archiveObjectSha256','storageAccountSha256','objectVersionIdSha256',
 'retentionPolicySha256','encryptionKeyIdentifierSha256','retentionUntil',
 'observedAt','objectLockMode','retentionEnabled','versioningEnabled',
 'legalHoldEnabled','deleteProbeResult','deleteProbeReceiptSha256','releaseDecision'];
const RESTORE=['schemaVersion','purpose','packetSha256','logRef','checkpointReceiptSha256',
 'archiveObjectSha256','sourceManifestSha256','restoredManifestSha256',
 'revocationSnapshotSha256','encryptedBackupSha256','failureAt','recoveryCompleteAt',
 'latestRecoveredAt','rtoObjectiveMs','rpoObjectiveMs','keysRecovered',
 'restoreIsolationConfirmed','mfaReverified','revocationRechecked',
 'dispatchHeld','releaseDecision'];
const EVIDENCE=['body','signature','pin'];
const WITNESS_ENTRY=['body','signature','pin','inclusionProofSha256'];
const RESTORE_ENTRY=['body','signatures','pins'];
const BASE_BLOCKERS=[
 'EXTERNAL_WITNESS_AUTHORITY_NOT_INDEPENDENTLY_AUTHENTICATED',
 'OBJECT_LOCK_ENFORCEMENT_NOT_INDEPENDENTLY_OBSERVED',
 'INDEPENDENT_LOG_CONSISTENCY_PROOF_NOT_AVAILABLE',
 'ENCRYPTED_RESTORE_NOT_INDEPENDENTLY_WITNESSED',
 'RCAI_CCA_EMUDHRA_MCA_REVOCATION_NOT_AUTHENTICATED',
 'PRODUCTION_SECURITY_OWNER_OPERATIONS_APPROVAL_PENDING'
];
function exact(v,keys){
 if(!v||typeof v!=='object'||Array.isArray(v)||
    Object.getPrototypeOf(v)!==Object.prototype||
    Object.keys(v).length!==keys.length||Object.keys(v).some(k=>!keys.includes(k)))
   throw Error('1BA requires an exact bounded evidence schema');
}
function id(x){if(typeof x!=='string'||!ID.test(x))throw Error('Invalid 1BA reference');}
function sha(x){if(typeof x!=='string'||!SHA.test(x)||/^0{64}$/.test(x))throw Error('Invalid 1BA digest');}
function utc(x){
 if(typeof x!=='string'||!UTC.test(x)||!Number.isFinite(Date.parse(x))||
   new Date(x).toISOString()!==x)throw Error('Invalid canonical 1BA time');
 return Date.parse(x);
}
function safeMillis(x){if(!Number.isSafeInteger(x)||x<0||x>14*86400000)throw Error('Invalid measured milliseconds');}
function canonical(fields,body,purpose){
 exact(body,fields);
 if(body.schemaVersion!==1||body.purpose!==purpose||body.releaseDecision!=='HOLD')
  throw Error('1BA acceptance can never authorize production');
 return Buffer.from('AADITECH-PHASE-1BA-SIGNED-CLAIM-V1\0'+
  JSON.stringify(fields.map(k=>body[k])),'utf8');
}
export function phase1BaWitnessBytes(body){return canonical(WITNESS,body,BA_WITNESS_PURPOSE);}
export function phase1BaStorageBytes(body){return canonical(STORAGE,body,BA_STORAGE_PURPOSE);}
export function phase1BaRestoreBytes(body){return canonical(RESTORE,body,BA_DR_PURPOSE);}
function loadPin(pin){
 exact(pin,PIN);
 id(pin.reviewerRef);id(pin.authorityRef);id(pin.keyId);sha(pin.publicKeySha256);
 if(!['WITNESS','STORAGE','SECURITY','OPERATIONS','OWNER'].includes(pin.role))
  throw Error('Unknown 1BA signature role');
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('Only bounded Ed25519 public SPKI allowed');
 const pub=createPublicKey(pin.publicKeyPem);
 if(pub.asymmetricKeyType!=='ed25519'||
    createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
  throw Error('Unmatched public key fingerprint');
 return pub;
}
function detachedValid(signature,pin,bytes){
 exact(signature,SIGNATURE);
 id(signature.reviewerRef);id(signature.keyId);
 if(typeof signature.signatureBase64!=='string'||!SIG.test(signature.signatureBase64)||
   Buffer.from(signature.signatureBase64,'base64').toString('base64')!==signature.signatureBase64)
  throw Error('Invalid canonical 1BA Ed25519 signature encoding');
 const pub=loadPin(pin);
 return signature.reviewerRef===pin.reviewerRef&&signature.keyId===pin.keyId&&
   verifyEd(null,bytes,pub,Buffer.from(signature.signatureBase64,'base64'));
}
function packetBinding(body,azPacket,packetSha){
 return body.packetSha256===packetSha&&body.logRef===azPacket.archive.logRef&&
  body.checkpointReceiptSha256===azPacket.archive.checkpointReceiptSha256&&
  body.archiveObjectSha256===azPacket.archive.archiveObjectSha256;
}
export function assessPhase1BaExternalAcceptance({
 azPacket=null,witnesses=[],storage=null,restore=null,now=new Date()
}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('Invalid 1BA clock');
 if(!Array.isArray(witnesses)||witnesses.length>16)throw Error('Unbounded witness records');
 const blockers=new Set(BASE_BLOCKERS);
 const missing=!azPacket||witnesses.length===0||!storage||!restore;
 if(missing) return Object.freeze({phase:'1BA',offlineClaimsConsistent:false,
  cryptographicallyValidWitnesses:0,externallyAuthenticated:false,
  wormStorageVerified:false,actualEncryptedRestoreVerified:false,
  incidentQuarantineRequired:true,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers,'MISSING_REQUIRED_EXTERNAL_EVIDENCE'].sort())});
 const az=phase1AzAssessReadiness(azPacket,{now});
 if(!az.packetInspected||!az.internalEvidenceConsistent)
  blockers.add('PREDECESSOR_AZ_PACKET_INVALID');
 const packetSha=az.packetSha256;
 const t=now.getTime(),witnessAuthorities=new Set(),witnessKeys=new Set(),
  witnessRefs=new Set(),witnessSigners=new Set();
 const roots=new Map();
 let validWitnesses=0;
 for(const w of witnesses){
  exact(w,WITNESS_ENTRY);
  const b=w.body,bytes=phase1BaWitnessBytes(b);
  id(b.witnessRef);id(b.organizationRef);id(b.administrativeAuthorityRef);
  id(b.logRef);
  for(const k of ['packetSha256','checkpointReceiptSha256','archiveObjectSha256','rootSha256'])sha(b[k]);
  if(!Number.isSafeInteger(b.treeSize)||b.treeSize<1||b.treeSize>1_000_000_000||
     !Number.isSafeInteger(b.leafIndex)||b.leafIndex<0||b.leafIndex>=b.treeSize)
   throw Error('Invalid witness tree position');
  const observed=utc(b.observedAt),expiry=utc(b.expiresAt);
  if(observed>t+300000||expiry<=t||expiry<=observed||expiry-observed>86400000)
   blockers.add('STALE_OR_FUTURE_WITNESS_EVIDENCE');
  const candidate=azPacket.witnesses.find(x=>x.witnessRef===b.witnessRef);
  if(!candidate||b.organizationRef!==candidate.organizationRef||
     b.administrativeAuthorityRef!==candidate.administrativeAuthorityRef||
     w.pin.publicKeySha256!==candidate.publicKeySpkiSha256||
     w.pin.authorityRef!==b.administrativeAuthorityRef||w.pin.role!=='WITNESS'||
     !packetBinding(b,azPacket,packetSha))
   blockers.add('WITNESS_ENROLLMENT_BINDING_MISMATCH');
  if(witnessRefs.has(b.witnessRef)||witnessAuthorities.has(b.administrativeAuthorityRef)||
     witnessKeys.has(w.pin.keyId)||witnessSigners.has(w.pin.reviewerRef))blockers.add('COMMON_CONTROL_OR_DUPLICATE_WITNESS');
  witnessRefs.add(b.witnessRef);
  witnessAuthorities.add(b.administrativeAuthorityRef);
  witnessKeys.add(w.pin.keyId);
  witnessSigners.add(w.pin.reviewerRef);
  if(!detachedValid(w.signature,w.pin,bytes))
   blockers.add('INVALID_WITNESS_SIGNATURE');
  else validWitnesses++;
  const anchor={schemaVersion:1,purpose:ANCHOR_PURPOSE,
   logRef:b.logRef,checkpointReceiptSha256:b.checkpointReceiptSha256,
   archiveObjectSha256:b.archiveObjectSha256,treeSize:b.treeSize,
   leafIndex:b.leafIndex,rootSha256:b.rootSha256,
   issuedAt:b.observedAt,expiresAt:b.expiresAt,releaseDecision:'HOLD'};
  if(!phase1AyVerifyInclusion(anchor,w.inclusionProofSha256))
   blockers.add('INVALID_WITNESS_MERKLE_INCLUSION');
  const previous=roots.get(b.treeSize);
  if(previous&&previous!==b.rootSha256)blockers.add('WITNESS_CHECKPOINT_EQUIVOCATION');
  roots.set(b.treeSize,b.rootSha256);
 }
 if(validWitnesses<2||witnessAuthorities.size<2||
    validWitnesses!==witnesses.length)
  blockers.add('WITNESS_SIGNATURE_QUORUM_MISSING');
 if(witnessRefs.size!==azPacket.witnesses.length)
  blockers.add('INCOMPLETE_WITNESS_ENROLLMENT');

 exact(storage,EVIDENCE);
 const s=storage.body,storageBytes=phase1BaStorageBytes(s);
 id(s.logRef);
 for(const k of ['packetSha256','checkpointReceiptSha256','archiveObjectSha256',
  'storageAccountSha256','objectVersionIdSha256','retentionPolicySha256',
  'encryptionKeyIdentifierSha256','deleteProbeReceiptSha256'])sha(s[k]);
 if(!packetBinding(s,azPacket,packetSha)||
    s.storageAccountSha256!==azPacket.archive.storageAccountSha256||
    s.objectVersionIdSha256!==azPacket.archive.objectVersionIdSha256||
    s.retentionPolicySha256!==azPacket.archive.retentionPolicySha256||
    s.encryptionKeyIdentifierSha256!==azPacket.archive.encryptionKeyIdentifierSha256)
  blockers.add('STORAGE_POLICY_OR_VERSION_BINDING_MISMATCH');
 const observedStorage=utc(s.observedAt);
 if(observedStorage>t+300000||observedStorage<utc(azPacket.archive.createdAt)||
    utc(s.retentionUntil)<utc(azPacket.archive.retentionUntil))
  blockers.add('STORAGE_RETENTION_OR_CLOCK_INVALID');
 if(s.objectLockMode!=='COMPLIANCE'||s.retentionEnabled!==true||
    s.versioningEnabled!==true||s.legalHoldEnabled!==true||
    s.deleteProbeResult!=='DENIED')
  blockers.add('OBJECT_LOCK_DELETE_DENIAL_NOT_PROVEN');
 if(witnessAuthorities.has(storage.pin.authorityRef)||
    witnessSigners.has(storage.pin.reviewerRef))
  blockers.add('STORAGE_WITNESS_COMMON_CONTROL');
 if(storage.pin.role!=='STORAGE'||!detachedValid(storage.signature,storage.pin,storageBytes))
  blockers.add('INVALID_STORAGE_ATTESTATION_SIGNATURE');

 exact(restore,RESTORE_ENTRY);
 const r=restore.body,restoreBytes=phase1BaRestoreBytes(r);
 id(r.logRef);
 for(const k of ['packetSha256','checkpointReceiptSha256','archiveObjectSha256',
   'sourceManifestSha256','restoredManifestSha256','revocationSnapshotSha256',
   'encryptedBackupSha256'])sha(r[k]);
 const failure=utc(r.failureAt),finished=utc(r.recoveryCompleteAt),
   recovered=utc(r.latestRecoveredAt);
 for(const k of ['rtoObjectiveMs','rpoObjectiveMs'])safeMillis(r[k]);
 const actualRto=finished-failure,actualRpo=failure-recovered;
 if(finished>t+300000||actualRto<=0||recovered>failure||
    recovered<utc(azPacket.archive.createdAt)||actualRpo<0)
  blockers.add('INVALID_RECOVERY_MEASUREMENT_CHRONOLOGY');
 if(r.failureAt!==azPacket.recovery.startedAt||
    r.recoveryCompleteAt!==azPacket.recovery.completedAt)
  blockers.add('RESTORE_EVENT_DOES_NOT_MATCH_AZ_REHEARSAL');
 if(actualRto>r.rtoObjectiveMs||actualRpo>r.rpoObjectiveMs||
    r.rtoObjectiveMs!==azPacket.recovery.rtoObjectiveMs||
    r.rpoObjectiveMs!==azPacket.recovery.rpoObjectiveMs||
    actualRpo!==azPacket.recovery.measuredRpoMs)
  blockers.add('OBSERVED_RTO_RPO_CLAIMS_INCONSISTENT');
 if(!packetBinding(r,azPacket,packetSha)||
    r.sourceManifestSha256!==azPacket.recovery.sourceManifestSha256||
    r.restoredManifestSha256!==azPacket.recovery.restoredManifestSha256||
    r.revocationSnapshotSha256!==azPacket.recovery.revocationSnapshotSha256||
    r.sourceManifestSha256!==r.restoredManifestSha256)
  blockers.add('RECOVERY_MANIFEST_OR_REVOCATION_MISMATCH');
 if(r.keysRecovered!==true||r.restoreIsolationConfirmed!==true||
    r.mfaReverified!==true||r.revocationRechecked!==true||r.dispatchHeld!==true)
  blockers.add('INCOMPLETE_ENCRYPTED_RESTORE_CONTROLS');
 if(!Array.isArray(restore.signatures)||restore.signatures.length!==3||
    !Array.isArray(restore.pins)||restore.pins.length!==3)
  blockers.add('MISSING_TRIPLE_SIGNED_RECOVERY_OBSERVERS');
 else{
  const roles=['SECURITY','OPERATIONS','OWNER'],actors=new Set(),authorities=new Set();
  for(let i=0;i<3;i++){
   const pin=restore.pins[i],sig=restore.signatures[i];
   if(pin.role!==roles[i]||actors.has(pin.reviewerRef)||
      authorities.has(pin.authorityRef)||
      witnessAuthorities.has(pin.authorityRef)||
      pin.authorityRef===storage.pin.authorityRef)
    blockers.add('NONINDEPENDENT_RECOVERY_OBSERVERS');
   actors.add(pin.reviewerRef);authorities.add(pin.authorityRef);
   const candidate=azPacket.approvers[i];
   if(pin.reviewerRef!==candidate.reviewerRef||
      pin.authorityRef!==candidate.authorityRef)
    blockers.add('UNVERIFIED_RECOVERY_ROLE_BINDING');
   if(!detachedValid(sig,pin,restoreBytes))
    blockers.add('INVALID_RECOVERY_ATTESTATION_SIGNATURE');
  }
 }
 const problems=[...blockers].filter(x=>!BASE_BLOCKERS.includes(x));
 return Object.freeze({phase:'1BA',
  offlineClaimsConsistent:problems.length===0,
  cryptographicallyValidWitnesses:validWitnesses,
  claimedMeasuredRtoMs:actualRto,claimedMeasuredRpoMs:actualRpo,
  externallyAuthenticated:false,wormStorageVerified:false,
  actualEncryptedRestoreVerified:false,
  incidentQuarantineRequired:problems.length!==0,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
}
