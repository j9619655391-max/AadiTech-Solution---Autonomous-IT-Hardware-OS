import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {assessPhase1BdEvidenceReview} from './phase1BdEvidenceReview.mjs';

// Phase 1BE: OFFLINE witness compromise suspicion and emergency freeze.
// Candidate signatures are not out-of-band authenticated, no network/provider
// actions exist here and no freeze can authorize re-enrollment or release.
export const BE_FREEZE_PURPOSE='AADITECH_PHASE_1BE_WITNESS_REVOCATION_FREEZE_V1';
const SHA=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const FIELDS=['schemaVersion','purpose','logRef','incidentRef',
 'azPacketSha256','bdReviewSha256','revokedWitnessRef',
 'revokedKeySpkiSha256','survivingWitnessRef','survivingKeySpkiSha256',
 'checkpointReceiptSha256','archiveObjectSha256','storageObjectVersionSha256',
 'revocationNoticeSha256','previousRevocationSnapshotSha256',
 'claimedObjectLockDenialReceiptSha256','claimedEncryptedRestoreTelemetrySha256',
 'detectedAt','freezeEffectiveAt','expiresAt','reason',
 'quarantineRequired','outboundHeld','releaseDecision'];
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIG=['sourceRef','keyId','signatureBase64'];
const SIGNER=['pin','signature'];
const OUTSTANDING=[
 'PROVIDER_SIGNED_REVOCATION_NOT_INDEPENDENTLY_AUTHENTICATED',
 'OUT_OF_BAND_SURVIVING_WITNESS_KEY_NOT_AUTHENTICATED',
 'INDEPENDENT_REVOCATION_PUBLISHER_NOT_AUTHENTICATED',
 'OBJECT_LOCK_DENIAL_NOT_EXTERNALLY_VERIFIED',
 'ENCRYPTED_DR_NOT_INDEPENDENTLY_WITNESSED',
 'RCAI_CCA_EMUDHRA_MCA_AND_LEGAL_AUTHORIZATION_PENDING'
];
function exact(v,fields){
 if(!v||typeof v!=='object'||Array.isArray(v)||
    Object.getPrototypeOf(v)!==Object.prototype||
    Object.keys(v).length!==fields.length||
    Object.keys(v).some(k=>!fields.includes(k)))
  throw Error('1BE strict bounded evidence schema required');
}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1BE invalid opaque ref');}
function hash(v){if(typeof v!=='string'||!SHA.test(v)||/^0{64}$/.test(v))
 throw Error('1BE invalid nonzero digest');}
function utc(v){
 if(typeof v!=='string'||!UTC.test(v)||!Number.isFinite(Date.parse(v))||
    new Date(v).toISOString()!==v)
  throw Error('1BE noncanonical UTC timestamp');
 return Date.parse(v);
}
function clock(now){if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
 throw Error('1BE invalid clock');return now.getTime();}
function verifier(pin){
 exact(pin,PIN);
 if(!['WITNESS','SECURITY','OPERATIONS','OWNER'].includes(pin.role))
  throw Error('1BE invalid co-signing role');
 for(const k of ['sourceRef','authorityRef','keyId'])id(pin[k]);
 hash(pin.publicKeySha256);
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('1BE bounded Ed25519 SPKI required');
 const pub=createPublicKey(pin.publicKeyPem);
 if(pub.asymmetricKeyType!=='ed25519'||
    createHash('sha256').update(pub.export({type:'spki',format:'der'})).digest('hex')!==pin.publicKeySha256)
  throw Error('1BE public SPKI fingerprint mismatch');
 return pub;
}
function signed(attestation,bytes){
 exact(attestation,SIGNER);exact(attestation.signature,SIG);
 const {pin,signature}=attestation,pub=verifier(pin);
 if(signature.sourceRef!==pin.sourceRef||signature.keyId!==pin.keyId||
    typeof signature.signatureBase64!=='string'||
    !B64.test(signature.signatureBase64)||
    Buffer.from(signature.signatureBase64,'base64').toString('base64')!==signature.signatureBase64)
  return false;
 return edVerify(null,bytes,pub,Buffer.from(signature.signatureBase64,'base64'));
}
export function phase1BeFreezeSigningBytes(body){
 exact(body,FIELDS);
 if(body.schemaVersion!==1||body.purpose!==BE_FREEZE_PURPOSE||
    body.reason!=='SUSPECTED_WITNESS_KEY_COMPROMISE'||
    body.quarantineRequired!==true||body.outboundHeld!==true||
    body.releaseDecision!=='HOLD')
  throw Error('1BE revocation suspicion cannot authorize release or revoke silently');
 for(const k of ['logRef','incidentRef','revokedWitnessRef','survivingWitnessRef'])id(body[k]);
 for(const k of FIELDS.filter(k=>k.endsWith('Sha256')))hash(body[k]);
 if(body.revokedWitnessRef===body.survivingWitnessRef||
    body.revokedKeySpkiSha256===body.survivingKeySpkiSha256)
  throw Error('1BE cannot let suspect witness co-sign its own release');
 const detected=utc(body.detectedAt),effective=utc(body.freezeEffectiveAt),
  end=utc(body.expiresAt);
 if(effective<detected||effective-detected>300000||end<=effective||
    end-effective>3600000)
  throw Error('1BE invalid bounded incident freeze chronology');
 return Buffer.from('AADITECH-PHASE-1BE-KEY-FREEZE-V1\0'+
  JSON.stringify(FIELDS.map(k=>body[k])),'utf8');
}
export function assessPhase1BeRevocationFreeze({
 bdEvidence=null,body=null,survivingWitnessSignature=null,
 governanceSignatures=[],now=new Date()
}={}){
 const supplied=arguments[0];
 if(supplied!==undefined&&(!supplied||typeof supplied!=='object'||
    Array.isArray(supplied)||Object.getPrototypeOf(supplied)!==Object.prototype||
    Object.keys(supplied).some(k=>!['bdEvidence','body','survivingWitnessSignature',
     'governanceSignatures','now'].includes(k))))
  throw Error('1BE unrecognized freeze assessment field');
 const current=clock(now),blockers=new Set(OUTSTANDING);
 const deny=(extra={})=>Object.freeze({
  phase:'1BE',locallyCoSignedFreezeConsistent:false,
  incidentSha256:null,bdReviewSha256:null,azPacketSha256:null,
  witnessKeyExternallyRevoked:false,
  independentlyAuthenticatedRevocationSource:false,
  independentlyAuthenticatedWitnessQuorum:false,
  actualObjectLockEnforcementVerified:false,actualEncryptedDRVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',...extra,blockerCodes:Object.freeze([...blockers].sort())
 });
 if(!bdEvidence||!body||!survivingWitnessSignature||
    !Array.isArray(governanceSignatures)||governanceSignatures.length!==3){
  blockers.add('INCOMPLETE_EMERGENCY_FREEZE_EVIDENCE');
  return deny();
 }
 const dossierKeys=Object.keys(bdEvidence);
 if(dossierKeys.some(k=>!['azPacket','bbRecords','witnessEnrollments',
   'storageReceipt','recoveryAttestations','now'].includes(k)))
  throw Error('1BE unknown BD candidate review field');
 const envelope=phase1BeFreezeSigningBytes(body);
 const detected=utc(body.detectedAt),effective=utc(body.freezeEffectiveAt),
  expiry=utc(body.expiresAt);
 if(detected>current+300000||effective>current+300000||expiry<=current)
  blockers.add('STALE_FUTURE_OR_UNEFFECTIVE_FREEZE');
 const prior=assessPhase1BdEvidenceReview({
  azPacket:bdEvidence.azPacket,bbRecords:bdEvidence.bbRecords,
  witnessEnrollments:bdEvidence.witnessEnrollments,
  storageReceipt:bdEvidence.storageReceipt,
  recoveryAttestations:bdEvidence.recoveryAttestations,now
 });
 if(!prior.offlineEvidenceConsistent)
  blockers.add('UNVERIFIED_UPSTREAM_1BD_CANDIDATE_EVIDENCE');
 const a=bdEvidence.azPacket?.archive;
 const enrolled=bdEvidence.witnessEnrollments;
 const bad=enrolled?.find(x=>x.body.witnessRef===body.revokedWitnessRef);
 const good=enrolled?.find(x=>x.body.witnessRef===body.survivingWitnessRef);
 if(!Array.isArray(enrolled)||enrolled.length!==2||!good||!bad||
    body.logRef!==a.logRef||
    body.azPacketSha256!==bad.body.packetSha256||
    body.azPacketSha256!==good.body.packetSha256||
    body.bdReviewSha256!==prior.reviewDigestSha256||
    body.revokedKeySpkiSha256!==bad.pin.publicKeySha256||
    body.survivingKeySpkiSha256!==good.pin.publicKeySha256||
    body.checkpointReceiptSha256!==a.checkpointReceiptSha256||
    body.archiveObjectSha256!==a.archiveObjectSha256||
    body.storageObjectVersionSha256!==a.objectVersionIdSha256||
    body.previousRevocationSnapshotSha256!==
      bdEvidence.recoveryAttestations?.[0]?.body.revocationSnapshotSha256||
    body.claimedObjectLockDenialReceiptSha256!==
      bdEvidence.storageReceipt?.body.deleteDenialReceiptSha256||
    body.claimedEncryptedRestoreTelemetrySha256!==
      bdEvidence.recoveryAttestations?.[0]?.body.telemetryReceiptSha256)
  blockers.add('INCIDENT_BINDING_TO_AZ_BD_EVIDENCE_INVALID');
 if(body.revocationNoticeSha256===body.previousRevocationSnapshotSha256)
  blockers.add('STALE_REVOKED_KEY_NOTICE_REUSED');
 exact(survivingWitnessSignature,SIGNER);
 if(!good||survivingWitnessSignature.pin.role!=='WITNESS'||
    survivingWitnessSignature.pin.sourceRef!==good?.pin.sourceRef||
    survivingWitnessSignature.pin.authorityRef!==good?.pin.authorityRef||
    survivingWitnessSignature.pin.keyId!==good?.pin.keyId||
    survivingWitnessSignature.pin.publicKeySha256!==good?.pin.publicKeySha256||
    !signed(survivingWitnessSignature,envelope))
  blockers.add('SURVIVING_WITNESS_COSIGNATURE_INVALID');
 const reviewers=new Set(),administrators=new Set(),
  signingKeys=new Set([good?.pin?.publicKeySha256,bad?.pin?.publicKeySha256]);
 for(const expectedRole of ['SECURITY','OPERATIONS','OWNER']){
  const signature=governanceSignatures.find(x=>x?.pin?.role===expectedRole);
  const expected=bdEvidence.recoveryAttestations?.find(x=>x.pin.role===expectedRole);
  if(!signature||!expected){
   blockers.add('MISSING_INDEPENDENT_FREEZE_REVIEWER');continue;
  }
  const pin=signature.pin;
  if(reviewers.has(pin.sourceRef)||administrators.has(pin.authorityRef)||
     pin.authorityRef===good?.pin.authorityRef||
     pin.authorityRef===bad?.pin.authorityRef||
     pin.authorityRef===bdEvidence.storageReceipt?.pin.authorityRef)
   blockers.add('COMMON_CONTROL_OF_FREEZE_REVIEWERS');
  reviewers.add(pin.sourceRef);administrators.add(pin.authorityRef);
  if(signingKeys.has(pin.publicKeySha256))
   blockers.add('COMMON_SIGNING_KEY_ACROSS_WITNESSES_OR_REVIEWERS');
  signingKeys.add(pin.publicKeySha256);
  if(pin.sourceRef!==expected.pin.sourceRef||
     pin.authorityRef!==expected.pin.authorityRef||
     pin.keyId!==expected.pin.keyId||
     pin.publicKeySha256!==expected.pin.publicKeySha256||
     !signed(signature,envelope))
   blockers.add('INVALID_FREEZE_REVIEWER_SIGNATURE_OR_ENROLLMENT');
 }
 if(governanceSignatures.some(x=>!['SECURITY','OPERATIONS','OWNER'].includes(x?.pin?.role))||
    new Set(governanceSignatures.map(x=>x?.pin?.role)).size!==3)
  blockers.add('INVALID_FREEZE_ROLE_QUORUM');
 const incidentSha256=createHash('sha256')
  .update('AADITECH-PHASE-1BE-REVOCATION-EVIDENCE-V1\0').update(envelope)
  .update(JSON.stringify([
   [survivingWitnessSignature.pin.sourceRef,
    survivingWitnessSignature.pin.publicKeySha256,
    survivingWitnessSignature.signature.signatureBase64],
   governanceSignatures.map(x=>[x.pin.role,x.pin.sourceRef,
    x.pin.authorityRef,x.pin.publicKeySha256,
    x.signature.signatureBase64]).sort((a,b)=>a[0].localeCompare(b[0]))
  ])).digest('hex');
 const internal=[...blockers].every(x=>OUTSTANDING.includes(x));
 return deny({locallyCoSignedFreezeConsistent:internal,incidentSha256,
  bdReviewSha256:prior.reviewDigestSha256,
  azPacketSha256:body.azPacketSha256,
  frozenWitnessRef:body.revokedWitnessRef,
  frozenKeySpkiSha256:body.revokedKeySpkiSha256});
}
