import {createHash,createPublicKey,verify as verifyEd} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {assessPhase1BbEvidenceIntake} from './phase1BbEvidenceIntake.mjs';

// Phase 1BD is a strictly OFFLINE review of signed *candidate* claims.
// The applicant supplies its own public pins, enrollment refs, cloud receipt
// digests and recovery telemetry. They are NOT independent proof of authority.
export const BD_WITNESS_PURPOSE='AADITECH_PHASE_1BD_WITNESS_ENROLLMENT_HOLD_V1';
export const BD_STORAGE_PURPOSE='AADITECH_PHASE_1BD_STORAGE_PROVIDER_HOLD_V1';
export const BD_RECOVERY_PURPOSE='AADITECH_PHASE_1BD_DR_TELEMETRY_HOLD_V1';
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIGN=['sourceRef','keyId','signatureBase64'];
const WRAP=['body','pin','signature'];
const WITNESS=['schemaVersion','purpose','packetSha256','batchSha256',
 'witnessRef','organizationRef','administrativeAuthorityRef','publicKeySha256',
 'enrollmentReceiptSha256','independentChannelReceiptSha256','custodyPolicySha256',
 'rotationSequence','validFrom','validUntil','revocationState','releaseDecision'];
const STORAGE=['schemaVersion','purpose','packetSha256','batchSha256','logRef',
 'archiveObjectSha256','storageAccountSha256','objectVersionIdSha256',
 'retentionPolicySha256','legalHoldEvidenceSha256','encryptionKeyIdentifierSha256',
 'providerCreateReceiptSha256','providerPolicyReceiptSha256',
 'deleteDenialReceiptSha256','overwriteDenialReceiptSha256',
 'readbackReceiptSha256','observedAt','retentionUntil',
 'complianceLock','deleteDenied','overwriteDenied','releaseDecision'];
const RECOVERY=['schemaVersion','purpose','packetSha256','batchSha256','logRef',
 'incidentRef','checkpointReceiptSha256','encryptedBackupSha256',
 'sourceManifestSha256','restoredManifestSha256','revocationSnapshotSha256',
 'kmsRecoveryReceiptSha256','isolatedRestoreReceiptSha256','telemetryReceiptSha256',
 'failureAt','latestRecoveredAt','completedAt',
 'rtoObjectiveMs','rpoObjectiveMs','isolatedStaging','mfaReverified',
 'revocationRechecked','outboundHeld','releaseDecision'];
const BASE=['INDEPENDENT_WITNESS_ORGANIZATIONS_UNVERIFIED',
 'WITNESS_KEY_CUSTODY_AND_OUT_OF_BAND_ENROLLMENT_NOT_AUTHENTICATED',
 'OBJECT_LOCK_PROVIDER_SIGNATURE_AND_DENIAL_NOT_INDEPENDENTLY_VERIFIED',
 'ENCRYPTED_DR_TELEMETRY_NOT_INDEPENDENTLY_OBSERVED',
 'RCAI_CCA_EMUDHRA_MCA_AND_SIGNATORY_APPROVAL_PENDING',
 'NO_AUTHORIZED_PRODUCTION_RELEASE'];
const hash=value=>createHash('sha256').update(value).digest('hex');
function exact(value,fields){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype||
    Object.keys(value).length!==fields.length||
    Object.keys(value).some(k=>!fields.includes(k)))
  throw Error('1BD exact bounded digest-only schema required');
}
function id(x){if(typeof x!=='string'||!ID.test(x))throw Error('1BD invalid opaque reference');}
function sha(x){if(typeof x!=='string'||!SHA.test(x)||/^0{64}$/.test(x))throw Error('1BD invalid SHA-256 evidence digest');}
function timestamp(x){
 if(typeof x!=='string'||!UTC.test(x)||!Number.isFinite(Date.parse(x))||
    new Date(x).toISOString()!==x)throw Error('1BD noncanonical UTC timestamp');
 return Date.parse(x);
}
function boundedMs(x){if(!Number.isSafeInteger(x)||x<0||x>14*86400000)throw Error('1BD invalid recovery timing');}
function signing(body,fields,purpose){
 exact(body,fields);
 if(body.schemaVersion!==1||body.purpose!==purpose||body.releaseDecision!=='HOLD')
  throw Error('1BD candidate evidence cannot authorize release');
 return Buffer.from('AADITECH-PHASE-1BD-CLAIM-V1\0'+
  JSON.stringify(fields.map(k=>body[k])),'utf8');
}
export function phase1BdWitnessBytes(body){
 const bytes=signing(body,WITNESS,BD_WITNESS_PURPOSE);
 for(const x of ['witnessRef','organizationRef','administrativeAuthorityRef'])id(body[x]);
 for(const x of ['packetSha256','batchSha256','publicKeySha256',
   'enrollmentReceiptSha256','independentChannelReceiptSha256','custodyPolicySha256'])
  sha(body[x]);
 if(!Number.isSafeInteger(body.rotationSequence)||body.rotationSequence!==1||
    body.revocationState!=='CANDIDATE_UNVERIFIED')throw Error('1BD unapproved witness key rotation');
 const start=timestamp(body.validFrom),end=timestamp(body.validUntil);
 if(end<=start||end-start>365*86400000)throw Error('1BD invalid candidate enrollment lifetime');
 return bytes;
}
export function phase1BdStorageBytes(body){
 const bytes=signing(body,STORAGE,BD_STORAGE_PURPOSE);
 id(body.logRef);
 for(const x of ['packetSha256','batchSha256','archiveObjectSha256',
  'storageAccountSha256','objectVersionIdSha256','retentionPolicySha256',
  'legalHoldEvidenceSha256','encryptionKeyIdentifierSha256',
  'providerCreateReceiptSha256','providerPolicyReceiptSha256',
  'deleteDenialReceiptSha256','overwriteDenialReceiptSha256','readbackReceiptSha256'])
  sha(body[x]);
 if(body.complianceLock!==true||body.deleteDenied!==true||
    body.overwriteDenied!==true)throw Error('1BD retention or delete denial not claimed');
 if(timestamp(body.retentionUntil)<=timestamp(body.observedAt))
  throw Error('1BD archive retention chronology invalid');
 return bytes;
}
export function phase1BdRecoveryBytes(body){
 const bytes=signing(body,RECOVERY,BD_RECOVERY_PURPOSE);
 for(const x of ['logRef','incidentRef'])id(body[x]);
 for(const x of ['packetSha256','batchSha256','checkpointReceiptSha256',
  'encryptedBackupSha256','sourceManifestSha256','restoredManifestSha256',
  'revocationSnapshotSha256','kmsRecoveryReceiptSha256',
  'isolatedRestoreReceiptSha256','telemetryReceiptSha256'])sha(body[x]);
 const failure=timestamp(body.failureAt),latest=timestamp(body.latestRecoveredAt),
   completed=timestamp(body.completedAt);
 if(latest>failure||completed<=failure||latest<failure-14*86400000)
  throw Error('1BD invalid recovery event chronology');
 boundedMs(body.rtoObjectiveMs);boundedMs(body.rpoObjectiveMs);
 if(body.isolatedStaging!==true||body.mfaReverified!==true||
    body.revocationRechecked!==true||body.outboundHeld!==true)
  throw Error('1BD restore isolation or outbound HOLD missing');
 return bytes;
}
function inspectSignature(wrapper,bytes,role){
 exact(wrapper,WRAP);exact(wrapper.pin,PIN);exact(wrapper.signature,SIGN);
 const pin=wrapper.pin,s=wrapper.signature;
 for(const x of ['sourceRef','authorityRef','keyId'])id(pin[x]);
 sha(pin.publicKeySha256);
 if(pin.role!==role||s.sourceRef!==pin.sourceRef||s.keyId!==pin.keyId)
  return false;
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
    !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('1BD bounded public Ed25519 SPKI required');
 if(typeof s.signatureBase64!=='string'||!B64.test(s.signatureBase64)||
    Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
  throw Error('1BD noncanonical Ed25519 detached signature');
 const pub=createPublicKey(pin.publicKeyPem);
 if(pub.asymmetricKeyType!=='ed25519'||
    hash(pub.export({type:'spki',format:'der'}))!==pin.publicKeySha256)
  throw Error('1BD unmatched signed public SPKI');
 return verifyEd(null,bytes,pub,Buffer.from(s.signatureBase64,'base64'));
}
export function assessPhase1BdEvidenceReview({
 azPacket=null,bbRecords=[],witnessEnrollments=[],storageReceipt=null,
 recoveryAttestations=[],now=new Date()
}={}){
 const supplied=arguments[0];
 if(supplied!==undefined&&(!supplied||typeof supplied!=='object'||
    Array.isArray(supplied)||Object.getPrototypeOf(supplied)!==Object.prototype||
    Object.keys(supplied).some(k=>!['azPacket','bbRecords','witnessEnrollments',
      'storageReceipt','recoveryAttestations','now'].includes(k))))
  throw Error('1BD unrecognized dossier attribute rejected');
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('1BD invalid evaluation clock');
 if(!Array.isArray(bbRecords)||bbRecords.length>6||
    !Array.isArray(witnessEnrollments)||witnessEnrollments.length>2||
    !Array.isArray(recoveryAttestations)||recoveryAttestations.length>3)
  throw Error('1BD unbounded external evidence');
 const blockers=new Set(BASE);
 const deny=(details={})=>Object.freeze({phase:'1BD',
  offlineEvidenceConsistent:false,reviewDigestSha256:null,
  candidateWitnessSignaturesChecked:0,candidateDrSignaturesChecked:0,
  candidateProviderSignatureChecked:false,...details,
  independentAuthorityAuthenticated:false,authorizedIssuerKeyEnrollment:false,
  independentlyVerifiedObjectLock:false,realEncryptedRestoreWitnessed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
 if(!azPacket||bbRecords.length!==6||witnessEnrollments.length!==2||
    !storageReceipt||recoveryAttestations.length!==3){
  blockers.add('INCOMPLETE_EXTERNAL_REVIEW_DOSSIER');
  return deny();
 }
 if(Buffer.byteLength(JSON.stringify({azPacket,bbRecords,witnessEnrollments,
   storageReceipt,recoveryAttestations}),'utf8')>48000)
  throw Error('1BD bounded evidence dossier exceeded');
 const az=phase1AzAssessReadiness(azPacket,{now});
 const bb=assessPhase1BbEvidenceIntake({azPacket,records:bbRecords,now});
 if(!az.internalEvidenceConsistent||!bb.internalEvidenceConsistent)
  blockers.add('PREDECESSOR_AZ_BB_CLAIMS_INVALID');
 const pkt=az.packetSha256,batch=bb.batchSha256,t=now.getTime();
 const witnessKeys=new Set(),witnessAdmins=new Set(),witnessRefs=new Set();
 const usedAuthorities=new Set(bbRecords.map(x=>x.body.authorityRef));
 let witnessValid=0;
 for(const item of witnessEnrollments){
  const b=item.body,bytes=phase1BdWitnessBytes(b);
  const p=item.pin;
  const upstream=bbRecords.find(x=>x.body.sourceRole==='WITNESS'&&
     x.body.sourceRef===b.witnessRef);
  const registered=azPacket.witnesses.find(x=>x.witnessRef===b.witnessRef);
  if(!upstream||!registered||p.role!=='WITNESS'||p.sourceRef!==b.witnessRef||
     p.authorityRef!==registered.administrativeAuthorityRef||
     p.publicKeySha256!==registered.publicKeySpkiSha256||
     p.keyId!==upstream.pin.keyId||p.publicKeySha256!==upstream.pin.publicKeySha256||
     b.publicKeySha256!==p.publicKeySha256||
     b.organizationRef!==registered.organizationRef||
     b.administrativeAuthorityRef!==registered.administrativeAuthorityRef||
     b.custodyPolicySha256!==registered.publisherPolicySha256||
     b.packetSha256!==pkt||b.batchSha256!==batch)
   blockers.add('WITNESS_ENROLLMENT_OR_PIN_MISMATCH');
  if(witnessRefs.has(b.witnessRef)||witnessKeys.has(p.keyId)||
     witnessAdmins.has(p.authorityRef))
   blockers.add('WITNESS_COMMON_CONTROL_OR_DUPLICATE_ENROLLMENT');
  witnessRefs.add(b.witnessRef);witnessKeys.add(p.keyId);
  witnessAdmins.add(p.authorityRef);
  if(timestamp(b.validFrom)>t+300000||timestamp(b.validUntil)<=t)
   blockers.add('STALE_OR_FUTURE_ENROLLMENT');
  if(inspectSignature(item,bytes,'WITNESS'))witnessValid++;
  else blockers.add('WITNESS_PROOF_OF_POSSESSION_INVALID');
 }
 if(witnessValid!==2||witnessAdmins.size!==2)
  blockers.add('WITNESS_CANDIDATE_SIGNER_QUORUM_MISSING');
 const s=storageReceipt.body,sbytes=phase1BdStorageBytes(s);
 const a=azPacket.archive,pin=storageReceipt.pin;
 if(s.packetSha256!==pkt||s.batchSha256!==batch||s.logRef!==a.logRef||
    s.archiveObjectSha256!==a.archiveObjectSha256||
    s.storageAccountSha256!==a.storageAccountSha256||
    s.objectVersionIdSha256!==a.objectVersionIdSha256||
    s.retentionPolicySha256!==a.retentionPolicySha256||
    s.legalHoldEvidenceSha256!==a.legalHoldEvidenceSha256||
    s.encryptionKeyIdentifierSha256!==a.encryptionKeyIdentifierSha256)
  blockers.add('OBJECT_LOCK_VERSION_POLICY_BINDING_MISMATCH');
 if(timestamp(s.observedAt)>t+300000||
    timestamp(s.observedAt)<timestamp(a.createdAt)||
    timestamp(s.retentionUntil)<timestamp(a.retentionUntil))
  blockers.add('OBJECT_LOCK_PROVIDER_CHRONOLOGY_INVALID');
 if(pin.role!=='STORAGE_PROVIDER'||usedAuthorities.has(pin.authorityRef)||
    !inspectSignature(storageReceipt,sbytes,'STORAGE_PROVIDER'))
  blockers.add('OBJECT_LOCK_PROVIDER_CANDIDATE_SIGNATURE_INVALID');
 const drRoles=new Set(),drAuthorities=new Set(),drRefs=new Set(),drClaims=new Set();
 let recoveryValid=0;
 for(const item of recoveryAttestations){
  const b=item.body,bytes=phase1BdRecoveryBytes(b),p=item.pin;
  if(!['SECURITY','OPERATIONS','OWNER'].includes(p.role)||
     drRoles.has(p.role)||drAuthorities.has(p.authorityRef)||drRefs.has(p.sourceRef))
   blockers.add('RECOVERY_REVIEWER_DUPLICATE_ROLE_OR_AUTHORITY');
  drRoles.add(p.role);drAuthorities.add(p.authorityRef);drRefs.add(p.sourceRef);
  const reviewer=bbRecords.find(x=>x.body.sourceRole===p.role);
  const candidate=azPacket.approvers.find(x=>x.role===p.role);
  if(!candidate||!reviewer||candidate.reviewerRef!==p.sourceRef||
     candidate.authorityRef!==p.authorityRef||
     reviewer.pin.publicKeySha256!==p.publicKeySha256||
     reviewer.pin.keyId!==p.keyId||pin.authorityRef===p.authorityRef)
   blockers.add('UNAUTHORIZED_RECOVERY_SIGNER_SUBSTITUTION');
  const r=azPacket.recovery;
  if(b.packetSha256!==pkt||b.batchSha256!==batch||
     b.logRef!==a.logRef||b.incidentRef!==r.incidentRef||
     b.checkpointReceiptSha256!==a.checkpointReceiptSha256||
     b.sourceManifestSha256!==r.sourceManifestSha256||
     b.restoredManifestSha256!==r.restoredManifestSha256||
     b.revocationSnapshotSha256!==r.revocationSnapshotSha256||
     b.sourceManifestSha256!==b.restoredManifestSha256||
     b.failureAt!==r.startedAt||b.completedAt!==r.completedAt)
   blockers.add('RECOVERY_MANIFEST_CHECKPOINT_OR_EVENT_MISMATCH');
  const measuredRto=timestamp(b.completedAt)-timestamp(b.failureAt);
  const measuredRpo=timestamp(b.failureAt)-timestamp(b.latestRecoveredAt);
  if(measuredRto>r.rtoObjectiveMs||measuredRpo>r.rpoObjectiveMs||
     measuredRpo!==r.measuredRpoMs||
     b.rtoObjectiveMs!==r.rtoObjectiveMs||b.rpoObjectiveMs!==r.rpoObjectiveMs||
     timestamp(b.completedAt)>t+300000)
   blockers.add('RECOVERY_RTO_RPO_UNCORROBORATED');
  drClaims.add(hash(bytes));
  if(inspectSignature(item,bytes,p.role))recoveryValid++;
  else blockers.add('RECOVERY_ATTESTATION_SIGNATURE_INVALID');
 }
 if(recoveryValid!==3||drRoles.size!==3)
  blockers.add('THREE_PARTY_RECOVERY_QUORUM_MISSING');
 if(drClaims.size!==1)
  blockers.add('RECOVERY_OBSERVERS_DISAGREE_ON_EVIDENCE');
 // Audit commitment must include signer identity/SPKI and detached signature,
 // not only the claim bodies. This detects candidate source substitution even
 // when the same storage retention metadata is re-signed by another local key.
 const signedRef=(entry,bytes)=>[
  hash(bytes),entry.pin.role,entry.pin.sourceRef,entry.pin.authorityRef,
  entry.pin.keyId,entry.pin.publicKeySha256,
  entry.signature.sourceRef,entry.signature.keyId,entry.signature.signatureBase64
 ];
 const ordered=items=>items.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
 const digest=hash(Buffer.from('AADITECH-PHASE-1BD-REVIEW-V1\0'+JSON.stringify([
  pkt,batch,
  ordered(witnessEnrollments.map(x=>signedRef(x,phase1BdWitnessBytes(x.body)))),
  signedRef(storageReceipt,sbytes),
  ordered(recoveryAttestations.map(x=>signedRef(x,phase1BdRecoveryBytes(x.body))))
 ]),'utf8'));
 const issues=[...blockers].filter(x=>!BASE.includes(x));
 return deny({offlineEvidenceConsistent:issues.length===0,reviewDigestSha256:digest,
  candidateWitnessSignaturesChecked:witnessValid,
  candidateDrSignaturesChecked:recoveryValid,
  candidateProviderSignatureChecked:!blockers.has('OBJECT_LOCK_PROVIDER_CANDIDATE_SIGNATURE_INVALID')});
}
