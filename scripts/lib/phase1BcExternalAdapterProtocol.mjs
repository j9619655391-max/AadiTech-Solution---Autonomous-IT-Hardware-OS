import {createHash,createPublicKey,verify} from 'node:crypto';
import {assessPhase1BbEvidenceIntake} from './phase1BbEvidenceIntake.mjs';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';

// Phase 1BC deliberately performs NO network I/O, storage writes, key enrollment,
// provider authentication, DR restore, or trust promotion. A caller-provided
// Ed25519 public key proves signature mathematics, NOT independent authority.
export const BC_ISSUER_PURPOSE='AADITECH_PHASE_1BC_ISSUER_CHALLENGE_HOLD_V1';
export const BC_STORAGE_PURPOSE='AADITECH_PHASE_1BC_STORAGE_RECEIPT_HOLD_V1';
export const BC_RECOVERY_PURPOSE='AADITECH_PHASE_1BC_RECOVERY_RECEIPT_HOLD_V1';
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const HASH=/^[0-9a-f]{64}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIG=['sourceRef','keyId','signatureBase64'];
const ENTRY=['body','pin','signature'];
const ISSUER=['schemaVersion','purpose','packetSha256','challengeSha256','sourceRole',
 'sourceRef','issuerRef','issuedAt','expiresAt','releaseDecision'];
const STORAGE=['schemaVersion','purpose','packetSha256','logRef','archiveObjectSha256',
 'objectVersionIdSha256','retentionPolicySha256','legalHoldEvidenceSha256',
 'providerRequestSha256','providerResponseSha256','observedAt','retentionUntil',
 'versioned','lockMode','deleteDenied','overwriteDenied','releaseDecision'];
const DR=['schemaVersion','purpose','packetSha256','logRef','checkpointReceiptSha256',
 'encryptedBackupSha256','backupManifestSha256','restoredManifestSha256',
 'revocationSnapshotSha256','failureAt','latestRecoveredAt','completedAt',
 'rtoObjectiveMs','rpoObjectiveMs','isolatedRestore','mfaReverified',
 'revocationRechecked','dispatchHeld','releaseDecision'];
const BASE=['PROVIDER_SANDBOX_AUTHORIZATION_NOT_VERIFIED',
 'ISSUER_KEY_CUSTODY_AND_CHALLENGE_PROVENANCE_NOT_AUTHENTICATED',
 'REMOTE_OBJECT_LOCK_ENFORCEMENT_NOT_VERIFIED',
 'REAL_ENCRYPTED_RESTORE_NOT_INDEPENDENTLY_WITNESSED',
 'RCAI_CCA_EMUDHRA_MCA_AUTHORITY_REVOCATION_PENDING'];
function exact(value,fields){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype||
    Object.keys(value).length!==fields.length||
    Object.keys(value).some(k=>!fields.includes(k)))
  throw Error('1BC exact, digest-only schema required');
}
function ref(v){if(typeof v!=='string'||!ID.test(v))throw Error('1BC invalid opaque identity');}
function sha(v){if(typeof v!=='string'||!HASH.test(v)||/^0{64}$/.test(v))throw Error('1BC invalid SHA-256 fingerprint');}
function instant(v){
 if(typeof v!=='string'||!UTC.test(v)||!Number.isFinite(Date.parse(v))||
    new Date(v).toISOString()!==v)throw Error('1BC invalid canonical timestamp');
 return Date.parse(v);
}
function integer(v){
 if(!Number.isSafeInteger(v)||v<0||v>14*86400000)throw Error('1BC invalid objective');
}
function signing(body,fields,purpose){
 exact(body,fields);
 if(body.schemaVersion!==1||body.purpose!==purpose||body.releaseDecision!=='HOLD')
  throw Error('1BC signature cannot authorize release');
 return Buffer.from('AADITECH-PHASE-1BC-V1\0'+JSON.stringify(fields.map(k=>body[k])),'utf8');
}
export function phase1BcIssuerBytes(body){
 const result=signing(body,ISSUER,BC_ISSUER_PURPOSE);
 for(const k of ['sourceRef','issuerRef'])ref(body[k]);
 for(const k of ['packetSha256','challengeSha256'])sha(body[k]);
 if(!['WITNESS','STORAGE_AUDITOR','SECURITY','OPERATIONS','OWNER'].includes(body.sourceRole))
  throw Error('1BC unsupported evidence role');
 if(instant(body.expiresAt)<=instant(body.issuedAt)||
    instant(body.expiresAt)-instant(body.issuedAt)>600000)
  throw Error('1BC challenge issuance lifetime too wide');
 return result;
}
export function phase1BcStorageBytes(body){
 const result=signing(body,STORAGE,BC_STORAGE_PURPOSE);
 ref(body.logRef);
 for(const k of ['packetSha256','archiveObjectSha256','objectVersionIdSha256',
  'retentionPolicySha256','legalHoldEvidenceSha256','providerRequestSha256',
  'providerResponseSha256'])sha(body[k]);
 if(instant(body.observedAt)>=instant(body.retentionUntil)||
    body.versioned!==true||body.lockMode!=='COMPLIANCE'||
    body.deleteDenied!==true||body.overwriteDenied!==true)
  throw Error('1BC storage fixture must preserve claimed retention and denial');
 return result;
}
export function phase1BcRecoveryBytes(body){
 const result=signing(body,DR,BC_RECOVERY_PURPOSE);
 ref(body.logRef);
 for(const k of ['packetSha256','checkpointReceiptSha256','encryptedBackupSha256',
  'backupManifestSha256','restoredManifestSha256','revocationSnapshotSha256'])sha(body[k]);
 const failure=instant(body.failureAt),recovered=instant(body.latestRecoveredAt),
  finished=instant(body.completedAt);
 if(finished<=failure||recovered>failure||recovered<failure-14*86400000)
  throw Error('1BC recovery chronology invalid');
 integer(body.rtoObjectiveMs);integer(body.rpoObjectiveMs);
 if(body.isolatedRestore!==true||body.mfaReverified!==true||
    body.revocationRechecked!==true||body.dispatchHeld!==true)
  throw Error('1BC recovery fixture must keep isolation and dispatch hold');
 return result;
}
function key(pin){
 exact(pin,PIN);
 for(const k of ['sourceRef','authorityRef','keyId'])ref(pin[k]);
 sha(pin.publicKeySha256);
 if(!['ISSUER','STORAGE_PROVIDER','SECURITY','OPERATIONS','OWNER'].includes(pin.role))
  throw Error('1BC unexpected issuer/observer role');
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
    !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('1BC bounded Ed25519 SPKI is required');
 const publicKey=createPublicKey(pin.publicKeyPem);
 if(publicKey.asymmetricKeyType!=='ed25519'||
    createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
  throw Error('1BC unpinned signer key');
 return publicKey;
}
function signed(entry,bytes,expectedRole){
 exact(entry,ENTRY);
 const p=entry.pin,s=entry.signature;
 exact(s,SIG);ref(s.sourceRef);ref(s.keyId);
 if(p.role!==expectedRole||s.sourceRef!==p.sourceRef||s.keyId!==p.keyId||
    typeof s.signatureBase64!=='string'||!B64.test(s.signatureBase64)||
    Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
  return false;
 return verify(null,bytes,key(p),Buffer.from(s.signatureBase64,'base64'));
}
export function assessPhase1BcOfflineAdapter({
 azPacket=null,bbRecords=[],challengeIssuances=[],storageReceipt=null,
 recoveryReceipts=[],now=new Date()
}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('1BC invalid clock');
 if(!Array.isArray(bbRecords)||bbRecords.length>6||
    !Array.isArray(challengeIssuances)||challengeIssuances.length>6||
    !Array.isArray(recoveryReceipts)||recoveryReceipts.length>3)
  throw Error('1BC bounded evidence inventory exceeded');
 const blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({phase:'1BC',...extra,
  externalProviderAuthorized:false,independentIssuerKeyCustodyVerified:false,
  providerObjectLockVerified:false,independentEncryptedRestoreVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',blockerCodes:Object.freeze([...blockers].sort())});
 if(!azPacket||bbRecords.length!==6||challengeIssuances.length!==6||
    !storageReceipt||recoveryReceipts.length!==3){
  blockers.add('INCOMPLETE_ADAPTER_EVIDENCE');
  return deny({offlineEvidenceConsistent:false,issuerSignatureCount:0});
 }
 const az=phase1AzAssessReadiness(azPacket,{now});
 const bb=assessPhase1BbEvidenceIntake({azPacket,records:bbRecords,now});
 if(!az.internalEvidenceConsistent||!bb.internalEvidenceConsistent)
  blockers.add('PREDECESSOR_CLAIMS_INVALID');
 const nowMs=now.getTime(),issuerAuthorities=new Set(),issuerKeys=new Set();
 const issuerRefs=new Set(),issuerCount=new Map(),witnessAuthorities=
  new Set(bbRecords.map(r=>r.body.authorityRef));
 const byChallenge=new Map(bbRecords.map(r=>[r.body.challengeSha256,r.body]));
 let validIssuers=0;
 for(const entry of challengeIssuances){
  exact(entry,ENTRY);
  const b=entry.body,bytes=phase1BcIssuerBytes(b),pin=entry.pin;
  if(!signed(entry,bytes,'ISSUER'))blockers.add('ISSUER_SIGNATURE_INVALID');
  else validIssuers++;
  if(!byChallenge.has(b.challengeSha256)||b.packetSha256!==az.packetSha256||
     b.sourceRef!==byChallenge.get(b.challengeSha256)?.sourceRef||
     b.sourceRole!==byChallenge.get(b.challengeSha256)?.sourceRole)
   blockers.add('CHALLENGE_NOT_BOUND_TO_SIGNED_RESPONSE');
  const responded=byChallenge.get(b.challengeSha256);
  if(responded&&(instant(b.issuedAt)>instant(responded.issuedAt)||
      instant(b.expiresAt)<instant(responded.issuedAt)))
   blockers.add('CHALLENGE_NOT_VALID_DURING_SIGNED_RESPONSE');
  if(instant(b.expiresAt)<=nowMs-3600000||instant(b.issuedAt)>nowMs+300000)
   blockers.add('STALE_OR_FUTURE_ISSUER_RECEIPT');
  if(b.issuerRef!==pin.sourceRef||witnessAuthorities.has(pin.authorityRef))
   blockers.add('ISSUER_WITNESS_COMMON_CONTROL');
  issuerRefs.add(b.issuerRef);
  issuerAuthorities.add(pin.authorityRef);issuerKeys.add(pin.keyId);
  issuerCount.set(pin.authorityRef,(issuerCount.get(pin.authorityRef)??0)+1);
 }
 if(validIssuers!==6||issuerRefs.size!==2||issuerAuthorities.size!==2||
    issuerKeys.size!==2||[...issuerCount.values()].some(n=>n!==3))
  blockers.add('TWO_INDEPENDENT_ISSUER_QUORUM_UNAVAILABLE');
 const storage=storageReceipt.body,storageBytes=phase1BcStorageBytes(storage);
 if(storage.packetSha256!==az.packetSha256||
    storage.logRef!==azPacket.archive.logRef||
    storage.archiveObjectSha256!==azPacket.archive.archiveObjectSha256||
    storage.objectVersionIdSha256!==azPacket.archive.objectVersionIdSha256||
    storage.retentionPolicySha256!==azPacket.archive.retentionPolicySha256||
    storage.legalHoldEvidenceSha256!==azPacket.archive.legalHoldEvidenceSha256)
  blockers.add('OBJECT_LOCK_RECEIPT_BINDING_MISMATCH');
 if(instant(storage.observedAt)>nowMs+300000||
    instant(storage.observedAt)<instant(azPacket.archive.createdAt)||
    instant(storage.retentionUntil)<instant(azPacket.archive.retentionUntil))
  blockers.add('OBJECT_LOCK_RETENTION_OR_CLOCK_INVALID');
 if(!signed(storageReceipt,storageBytes,'STORAGE_PROVIDER')||
    issuerAuthorities.has(storageReceipt.pin.authorityRef)||
    witnessAuthorities.has(storageReceipt.pin.authorityRef))
  blockers.add('OBJECT_LOCK_PROVIDER_SIGNER_UNTRUSTED');
 const reviewers=new Set(),reviewAuthorities=new Set();
 let validRecoveries=0;
 for(const role of ['SECURITY','OPERATIONS','OWNER']){
  const entry=recoveryReceipts.find(x=>x?.pin?.role===role);
  if(!entry){blockers.add('RECOVERY_ROLE_QUORUM_MISSING');continue;}
  const b=entry.body,bytes=phase1BcRecoveryBytes(b),pin=entry.pin;
  if(!signed(entry,bytes,role))blockers.add('RECOVERY_APPROVER_SIGNATURE_INVALID');
  else validRecoveries++;
  const registered=azPacket.approvers.find(x=>x.role===role);
  if(!registered||registered.reviewerRef!==pin.sourceRef||
     registered.authorityRef!==pin.authorityRef||
     reviewers.has(pin.sourceRef)||reviewAuthorities.has(pin.authorityRef)||
     issuerAuthorities.has(pin.authorityRef)||
     witnessAuthorities.has(pin.authorityRef)||
     storageReceipt.pin.authorityRef===pin.authorityRef)
   blockers.add('RECOVERY_APPROVER_AUTHORITY_COLLISION');
  reviewers.add(pin.sourceRef);reviewAuthorities.add(pin.authorityRef);
  const a=azPacket.archive,r=azPacket.recovery;
  if(b.packetSha256!==az.packetSha256||b.logRef!==a.logRef||
     b.checkpointReceiptSha256!==a.checkpointReceiptSha256||
     b.backupManifestSha256!==r.sourceManifestSha256||
     b.restoredManifestSha256!==r.restoredManifestSha256||
     b.revocationSnapshotSha256!==r.revocationSnapshotSha256||
     b.failureAt!==r.startedAt||b.completedAt!==r.completedAt||
     b.restoredManifestSha256!==b.backupManifestSha256)
   blockers.add('RECOVERY_RECEIPT_NOT_BOUND_TO_BACKUP_AND_REVOCATION');
  const actualRto=instant(b.completedAt)-instant(b.failureAt);
  const actualRpo=instant(b.failureAt)-instant(b.latestRecoveredAt);
  if(actualRto>r.rtoObjectiveMs||actualRpo>r.rpoObjectiveMs||
     actualRpo!==r.measuredRpoMs||
     b.rtoObjectiveMs!==r.rtoObjectiveMs||b.rpoObjectiveMs!==r.rpoObjectiveMs||
     instant(b.completedAt)>nowMs+300000)
   blockers.add('RECOVERY_RTO_RPO_NOT_CORROBORATED');
 }
 if(validRecoveries!==3||recoveryReceipts.length!==3)
  blockers.add('RECOVERY_ROLE_QUORUM_MISSING');
 const issues=[...blockers].filter(x=>!BASE.includes(x));
 return deny({offlineEvidenceConsistent:issues.length===0,
  issuerSignatureCount:validIssuers,recoverySignatureCount:validRecoveries,
  claimedIssuerOrganizations:issuerAuthorities.size,
  internalBatchSha256:bb.batchSha256,actualIndependentProviderConnection:false,
  candidateKeysAuthenticatedOutOfBand:false,
  providerSignedDeletionDenialIndependentlyVerified:false});
}
