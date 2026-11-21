import {createHash,createPublicKey,verify as verifyEd} from 'node:crypto';
import {assessPhase1BeRevocationFreeze} from './phase1BeRevocationFreeze.mjs';

// Phase 1BF: OFFLINE independently *claimed* revocation publisher admission.
// Candidate signatures, PEMs, CRL/OCSP hashes, WORM and DR hashes are NOT
// independently authenticated; a forged/applicant-controlled key is NOT a CA.
export const BF_PURPOSE='AADITECH_PHASE_1BF_REVOKED_WITNESS_PUBLICATION_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const SIGN=/^[A-Za-z0-9+/]{86}==$/;
const FIELDS=['schemaVersion','purpose','logRef','freezeIncidentSha256',
 'azPacketSha256','bdReviewSha256','revokedWitnessRef','revokedKeySpkiSha256',
 'survivingWitnessRef','survivingKeySpkiSha256','publicationSequence',
 'previousPublicationSha256','publisherRef','publisherAuthorityRef',
 'publisherPublicKeySha256','publisherPolicySha256',
 'claimedIssuedRevocationSha256','priorRevocationSnapshotSha256',
 'checkpointReceiptSha256','archiveObjectSha256','storageObjectVersionSha256',
 'claimedObjectLockDenialReceiptSha256','claimedEncryptedRestoreTelemetrySha256',
 'issuedAt','observedAt','expiresAt','revocationState','quarantineRequired',
 'outboundHeld','releaseDecision'];
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIG=['sourceRef','keyId','signatureBase64'];
const WRAP=['pin','signature'];
const EXTERNAL=['INDEPENDENT_REVOCATION_PUBLISHER_NOT_AUTHENTICATED',
 'RCAI_CCA_EMUDHRA_CRL_OCSP_HIERARCHY_NOT_VERIFIED',
 'ACTUAL_WITNESS_KEY_REVOCATION_NOT_VERIFIED',
 'PROVIDER_OBJECT_LOCK_NEGATIVE_DELETE_PROOF_NOT_VERIFIED',
 'ENCRYPTED_RECOVERY_INDEPENDENTLY_WITNESSED_NOT_VERIFIED',
 'MCA_PROVIDER_AGREEMENT_AND_SIGNATORY_PENDING'];
function exact(v,fields){
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.getPrototypeOf(v)!==Object.prototype||
    Object.keys(v).length!==fields.length||
    Object.keys(v).some(k=>!fields.includes(k)))
  throw Error('1BF exact bounded candidate evidence schema required');
}
function ref(s){if(typeof s!=='string'||!REF.test(s))throw Error('1BF invalid opaque reference');}
function sha(s){if(typeof s!=='string'||!SHA.test(s)||/^0{64}$/.test(s))
 throw Error('1BF invalid nonzero SHA256');}
function timestamp(s){
 if(typeof s!=='string'||!UTC.test(s)||!Number.isFinite(Date.parse(s))||
    new Date(s).toISOString()!==s)throw Error('1BF noncanonical UTC timestamp');
 return Date.parse(s);
}
function clock(d){if(!(d instanceof Date)||!Number.isFinite(d.getTime()))
 throw Error('1BF invalid now');return d.getTime();}
export function phase1BfPublicationSigningBytes(body){
 exact(body,FIELDS);
 if(body.schemaVersion!==1||body.purpose!==BF_PURPOSE||
    body.revocationState!=='REVOKED_CLAIMED'||
    body.quarantineRequired!==true||body.outboundHeld!==true||
    body.releaseDecision!=='HOLD')throw Error('1BF cannot promote candidate revocation');
 for(const k of ['logRef','revokedWitnessRef','survivingWitnessRef',
   'publisherRef','publisherAuthorityRef'])ref(body[k]);
 for(const k of FIELDS.filter(k=>k.endsWith('Sha256')&&k!=='previousPublicationSha256'))
  sha(body[k]);
 if(!Number.isSafeInteger(body.publicationSequence)||
    body.publicationSequence<1||body.publicationSequence>1000000||
    (body.publicationSequence===1&&body.previousPublicationSha256!==null)||
    (body.publicationSequence>1&&
      (typeof body.previousPublicationSha256!=='string'||
       !SHA.test(body.previousPublicationSha256)||
       /^0{64}$/.test(body.previousPublicationSha256))))
  throw Error('1BF invalid publication predecessor or sequence');
 if(body.revokedWitnessRef===body.survivingWitnessRef||
    body.revokedKeySpkiSha256===body.survivingKeySpkiSha256||
    body.publisherPublicKeySha256===body.revokedKeySpkiSha256||
    body.publisherPublicKeySha256===body.survivingKeySpkiSha256)
  throw Error('1BF suspect cannot become a publisher/surviving cosigner');
 const i=timestamp(body.issuedAt),o=timestamp(body.observedAt),e=timestamp(body.expiresAt);
 if(o<i||o-i>300000||e<=o||e-i>3600000)
  throw Error('1BF invalid revocation observation freshness/expiry');
 return Buffer.from('AADITECH-PHASE-1BF-PUBLICATION-V1\0'+
  JSON.stringify(FIELDS.map(k=>body[k])),'utf8');
}
function verifySignature(wrapper,role,message){
 exact(wrapper,WRAP);exact(wrapper.pin,PIN);exact(wrapper.signature,SIG);
 const p=wrapper.pin,s=wrapper.signature;
 if(p.role!==role||s.sourceRef!==p.sourceRef||s.keyId!==p.keyId)
  return false;
 for(const k of ['sourceRef','authorityRef','keyId'])ref(p[k]);
 sha(p.publicKeySha256);
 if(typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>1024||
    !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(p.publicKeyPem))
  throw Error('1BF bounded Ed25519 public SPKI required');
 if(typeof s.signatureBase64!=='string'||!SIGN.test(s.signatureBase64)||
    Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
  return false;
 const key=createPublicKey(p.publicKeyPem);
 if(key.asymmetricKeyType!=='ed25519'||
    createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex')!==p.publicKeySha256)
  throw Error('1BF self-supplied pin fingerprint mismatch');
 return verifyEd(null,message,key,Buffer.from(s.signatureBase64,'base64'));
}
export function assessPhase1BfPublication({
 freezeEvidence=null,body=null,publisher=null,survivingWitness=null,
 securityReviewer=null,now=new Date()
}={}){
 const supplied=arguments[0];
 if(supplied!==undefined&&(!supplied||typeof supplied!=='object'||
    Array.isArray(supplied)||Object.getPrototypeOf(supplied)!==Object.prototype||
    Object.keys(supplied).some(k=>!['freezeEvidence','body','publisher',
     'survivingWitness','securityReviewer','now'].includes(k))))
  throw Error('1BF unknown publication assessment field');
 const n=clock(now),blockers=new Set(EXTERNAL);
 const deny=(extra={})=>Object.freeze({phase:'1BF',
  locallySignedPublicationConsistent:false,publicationSha256:null,
  freezeIncidentSha256:null,publicationSequence:null,
  independentlyAuthenticatedRevocationPublisher:false,
  actualExternalWitnessRevocationVerified:false,
  realProviderWormRetentionVerified:false,realEncryptedDrAcceptanceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',...extra,blockerCodes:Object.freeze([...blockers].sort())});
 if(!freezeEvidence||!body||!publisher||!survivingWitness||!securityReviewer){
  blockers.add('INCOMPLETE_REVOCATION_PUBLICATION');
  return deny();
 }
 if(Buffer.byteLength(JSON.stringify({freezeEvidence,body,publisher,survivingWitness,
   securityReviewer}),'utf8')>55000)
  throw Error('1BF overlarge candidate publication');
 const bytes=phase1BfPublicationSigningBytes(body);
 const freeze=assessPhase1BeRevocationFreeze({
  bdEvidence:freezeEvidence.bdEvidence,body:freezeEvidence.body,
  survivingWitnessSignature:freezeEvidence.survivingWitnessSignature,
  governanceSignatures:freezeEvidence.governanceSignatures,now
 });
 if(!freeze.locallyCoSignedFreezeConsistent)
  blockers.add('UPSTREAM_1BE_FREEZE_SIGNATURE_OR_EVIDENCE_INVALID');
 const original=freezeEvidence.body;
 if(body.logRef!==original.logRef||
    body.freezeIncidentSha256!==freeze.incidentSha256||
    body.azPacketSha256!==original.azPacketSha256||
    body.bdReviewSha256!==original.bdReviewSha256||
    body.revokedWitnessRef!==original.revokedWitnessRef||
    body.revokedKeySpkiSha256!==original.revokedKeySpkiSha256||
    body.survivingWitnessRef!==original.survivingWitnessRef||
    body.survivingKeySpkiSha256!==original.survivingKeySpkiSha256||
    body.claimedIssuedRevocationSha256!==original.revocationNoticeSha256||
    body.priorRevocationSnapshotSha256!==original.previousRevocationSnapshotSha256||
    body.checkpointReceiptSha256!==original.checkpointReceiptSha256||
    body.archiveObjectSha256!==original.archiveObjectSha256||
    body.storageObjectVersionSha256!==original.storageObjectVersionSha256||
    body.claimedObjectLockDenialReceiptSha256!==
      original.claimedObjectLockDenialReceiptSha256||
    body.claimedEncryptedRestoreTelemetrySha256!==
      original.claimedEncryptedRestoreTelemetrySha256)
  blockers.add('PUBLICATION_FREEZE_ARCHIVE_AND_DR_BINDING_MISMATCH');
 const i=timestamp(body.issuedAt),o=timestamp(body.observedAt),e=timestamp(body.expiresAt);
 if(i<timestamp(original.freezeEffectiveAt)||i>n+300000||o>n+300000||e<=n)
  blockers.add('PUBLICATION_EXPIRED_FUTURE_OR_PREDATES_FREEZE');
 for(const [wrapper,role] of [[publisher,'REVOCATION_PUBLISHER'],
   [survivingWitness,'WITNESS'],[securityReviewer,'SECURITY']]){
  if(!verifySignature(wrapper,role,bytes))
   blockers.add('INVALID_PUBLICATION_COSIGNATURE');
 }
 const p=publisher.pin,w=survivingWitness.pin,s=securityReviewer.pin;
 const witness=freezeEvidence.bdEvidence.witnessEnrollments.find(
  x=>x.body.witnessRef===body.survivingWitnessRef);
 const security=freezeEvidence.bdEvidence.recoveryAttestations.find(
  x=>x.pin.role==='SECURITY');
 if(p.sourceRef!==body.publisherRef||p.authorityRef!==body.publisherAuthorityRef||
    p.publicKeySha256!==body.publisherPublicKeySha256||
    !witness||w.sourceRef!==witness.pin.sourceRef||
    w.authorityRef!==witness.pin.authorityRef||
    w.keyId!==witness.pin.keyId||
    w.publicKeySha256!==witness.pin.publicKeySha256||
    !security||s.sourceRef!==security.pin.sourceRef||
    s.authorityRef!==security.pin.authorityRef||
    s.keyId!==security.pin.keyId||
    s.publicKeySha256!==security.pin.publicKeySha256)
  blockers.add('REPLACED_PUBLISHER_WITNESS_OR_SECURITY_PIN');
 const refs=[p.sourceRef,w.sourceRef,s.sourceRef],
  admins=[p.authorityRef,w.authorityRef,s.authorityRef],
  keys=[p.publicKeySha256,w.publicKeySha256,s.publicKeySha256],
  otherAdmins=[
   ...freezeEvidence.bdEvidence.witnessEnrollments.map(x=>x.pin.authorityRef),
   ...freezeEvidence.bdEvidence.recoveryAttestations.map(x=>x.pin.authorityRef),
   freezeEvidence.bdEvidence.storageReceipt.pin.authorityRef
  ];
 if(new Set(refs).size!==3||new Set(admins).size!==3||
    new Set(keys).size!==3||otherAdmins.includes(p.authorityRef))
  blockers.add('PUBLISHER_COMMON_CONTROL_OR_KEY_REUSE');
 const publicationSha256=createHash('sha256')
  .update('AADITECH-PHASE-1BF-PUBLICATION-EVIDENCE-V1\0')
  .update(bytes)
  .update(JSON.stringify([
   [p.role,p.sourceRef,p.authorityRef,p.publicKeySha256,
    publisher.signature.signatureBase64],
   [w.role,w.sourceRef,w.authorityRef,w.publicKeySha256,
    survivingWitness.signature.signatureBase64],
   [s.role,s.sourceRef,s.authorityRef,s.publicKeySha256,
    securityReviewer.signature.signatureBase64]
  ])).digest('hex');
 return deny({locallySignedPublicationConsistent:
  [...blockers].every(x=>EXTERNAL.includes(x)),
  publicationSha256,freezeIncidentSha256:freeze.incidentSha256,
  publicationSequence:body.publicationSequence,
  publisherPublicKeySha256:body.publisherPublicKeySha256});
}
