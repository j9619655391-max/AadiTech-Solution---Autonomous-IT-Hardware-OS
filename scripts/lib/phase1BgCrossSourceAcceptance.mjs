import {createHash,createPublicKey,verify as verifyEd} from 'node:crypto';
import {assessPhase1BfPublication} from './phase1BfRevocationPublication.mjs';

// Phase 1BG verifies only an OFFLINE, applicant-supplied candidate audit
// quorum. Keys/CRLs/OCSP/provider receipts remain UNAUTHENTICATED. NO RELEASE.
export const BG_PURPOSE='AADITECH_PHASE_1BG_CROSS_SOURCE_EVIDENCE_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const MANIFEST=['schemaVersion','purpose','logRef','publicationSha256',
 'publicationSequence','freezeIncidentSha256','publisherPinSha256',
 'reviewRevision','previousReviewSha256','auditorPinSetSha256',
 'crlIssuerSha256','crlSnapshotSha256','crlNumber','crlThisUpdate',
 'crlNextUpdate','ocspResponseSha256','ocspProducedAt','ocspNextUpdate',
 'ocspStatus','revokedKeySpkiSha256','wormVersionSha256',
 'wormRetentionPolicySha256','wormDeleteDenialSha256',
 'wormOverwriteDenialSha256','wormReadbackSha256','wormRetentionUntil',
 'restoreReceiptSha256','restoreTelemetrySha256','restoredManifestSha256',
 'rtoObservedMs','rpoObservedMs','reviewedAt','expiresAt',
 'outboundHeld','releaseDecision'];
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIG=['sourceRef','keyId','signatureBase64'];
const REVIEW=['pin','signature'];
const ROLES=['REVOCATION_AUDITOR','STORAGE_AUDITOR','DR_AUDITOR'];
const BASE=[
 'EXTERNAL_REVOCATION_AUTHORITY_NOT_AUTHENTICATED',
 'REAL_SIGNED_CRL_AND_OCSP_NOT_INDEPENDENTLY_RETRIEVED',
 'AUDITOR_KEY_CUSTODY_OUT_OF_BAND_NOT_VERIFIED',
 'PROVIDER_WORM_OBJECT_LOCK_NOT_VERIFIED',
 'GENUINE_ENCRYPTED_RESTORE_NOT_INDEPENDENTLY_WITNESSED',
 'LEGAL_MCA_EMUDHRA_CCA_AND_FINAL_APPROVAL_PENDING'
];
function exact(x,fields){
 if(!x||typeof x!=='object'||Array.isArray(x)||
  Object.getPrototypeOf(x)!==Object.prototype||
  Object.keys(x).length!==fields.length||
  Object.keys(x).some(k=>!fields.includes(k)))
  throw Error('1BG exact bounded input schema required');
}
function sha(x){if(typeof x!=='string'||!SHA.test(x)||/^0{64}$/.test(x))
 throw Error('1BG invalid nonzero SHA256');}
function ref(x){if(typeof x!=='string'||!REF.test(x))throw Error('1BG invalid ref');}
function time(x){
 if(typeof x!=='string'||!UTC.test(x)||!Number.isFinite(Date.parse(x))||
    new Date(x).toISOString()!==x)throw Error('1BG invalid canonical UTC');
 return Date.parse(x);
}
function clock(x){if(!(x instanceof Date)||!Number.isFinite(x.getTime()))
 throw Error('1BG invalid now');return x.getTime();}
function signatureOK(row,role,bytes){
 exact(row,REVIEW);exact(row.pin,PIN);exact(row.signature,SIG);
 const p=row.pin,s=row.signature;
 if(p.role!==role||s.sourceRef!==p.sourceRef||s.keyId!==p.keyId)return false;
 for(const k of ['sourceRef','authorityRef','keyId'])ref(p[k]);
 sha(p.publicKeySha256);
 if(typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>1024||
  !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(p.publicKeyPem))
  throw Error('1BG bounded Ed25519 PEM required');
 if(typeof s.signatureBase64!=='string'||!B64.test(s.signatureBase64)||
    Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
  return false;
 const k=createPublicKey(p.publicKeyPem);
 if(k.asymmetricKeyType!=='ed25519'||
    createHash('sha256').update(k.export({format:'der',type:'spki'})).digest('hex')!==p.publicKeySha256)
  throw Error('1BG Ed25519 SPKI substitution');
 return verifyEd(null,bytes,k,Buffer.from(s.signatureBase64,'base64'));
}
const digest=x=>createHash('sha256').update('AADITECH-PHASE-1BG-COMMITMENT-V1\0')
 .update(JSON.stringify(x)).digest('hex');
export function phase1BgAuditorPinsetSha256(auditors){
 if(!Array.isArray(auditors)||auditors.length!==3)
  throw Error('1BG three separate candidate auditor pins required');
 const pins=auditors.map(x=>{
  exact(x,REVIEW);exact(x.pin,PIN);
  if(!ROLES.includes(x.pin.role))throw Error('1BG invalid auditor role');
  return [x.pin.role,x.pin.sourceRef,x.pin.authorityRef,x.pin.keyId,
   x.pin.publicKeySha256];
 }).sort((a,b)=>a[0].localeCompare(b[0]));
 if(new Set(pins.map(x=>x[0])).size!==3)throw Error('1BG duplicate auditor role');
 return digest(['AUDITOR_PIN_CANDIDATES',pins]);
}
export function phase1BgSigningBytes(body){
 exact(body,MANIFEST);
 if(body.schemaVersion!==1||body.purpose!==BG_PURPOSE||
    body.releaseDecision!=='HOLD'||body.outboundHeld!==true||
    body.ocspStatus!=='REVOKED_CLAIMED')
  throw Error('1BG cannot authorize revocation or production');
 ref(body.logRef);
 for(const k of MANIFEST.filter(k=>k.endsWith('Sha256')&&
    k!=='previousReviewSha256'))sha(body[k]);
 if(!Number.isSafeInteger(body.publicationSequence)||body.publicationSequence<1||
    body.publicationSequence>1000000||
    !Number.isSafeInteger(body.reviewRevision)||body.reviewRevision<1||
    body.reviewRevision>1000000||
    (body.reviewRevision===1&&body.previousReviewSha256!==null)||
    (body.reviewRevision>1&&
     (typeof body.previousReviewSha256!=='string'||!SHA.test(body.previousReviewSha256))))
  throw Error('1BG invalid local review predecessor');
 if(!Number.isSafeInteger(body.crlNumber)||body.crlNumber<1||
    body.crlNumber>1000000000)
  throw Error('1BG invalid CRL sequence');
 for(const k of ['rtoObservedMs','rpoObservedMs'])
  if(!Number.isSafeInteger(body[k])||body[k]<0||body[k]>1209600000)
   throw Error('1BG invalid objective measurement');
 const thisUpdate=time(body.crlThisUpdate),nextUpdate=time(body.crlNextUpdate),
  produced=time(body.ocspProducedAt),ocspNext=time(body.ocspNextUpdate),
  reviewed=time(body.reviewedAt),expiry=time(body.expiresAt),retention=time(body.wormRetentionUntil);
 if(nextUpdate<=thisUpdate||nextUpdate-thisUpdate>86400000||
    produced<thisUpdate||ocspNext<=produced||
    ocspNext-produced>86400000||reviewed<produced||reviewed>=nextUpdate||
    reviewed>=ocspNext||expiry<=reviewed||expiry>nextUpdate||
    expiry>ocspNext||expiry-reviewed>3600000||retention<=expiry)
  throw Error('1BG candidate CRL/OCSP, WORM and review timestamps incoherent');
 return Buffer.from('AADITECH-PHASE-1BG-CROSS-SOURCE-V1\0'+
  JSON.stringify(MANIFEST.map(k=>body[k])),'utf8');
}
export function assessPhase1BgEvidenceQuorum({
 publication=null,manifest=null,auditors=[],now=new Date()
}={}){
 const supplied=arguments[0];
 if(supplied!==undefined&&(!supplied||typeof supplied!=='object'||
  Array.isArray(supplied)||Object.getPrototypeOf(supplied)!==Object.prototype||
  Object.keys(supplied).some(k=>!['publication','manifest','auditors','now'].includes(k))))
  throw Error('1BG unknown cross-source assessor field');
 const observed=clock(now),blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({phase:'1BG',
  locallyConsistentAuditQuorum:false,reviewSha256:null,
  previousPublicationSha256:null,auditorPinSetSha256:null,
  externallyAuthenticatedIssuer:false,liveCrlOcspRevocationVerified:false,
  independentlyAuthenticatedAuditKeys:false,
  realCloudWormComplianceVerified:false,realEncryptedDrVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',...extra,blockerCodes:Object.freeze([...blockers].sort())});
 if(!publication||!manifest||!Array.isArray(auditors)||auditors.length!==3){
  blockers.add('INCOMPLETE_THREE_SOURCE_CANDIDATE_REVIEW');
  return deny();
 }
 if(Buffer.byteLength(JSON.stringify({publication,manifest,auditors}),'utf8')>65000)
  throw Error('1BG oversized candidate payload');
 const bytes=phase1BgSigningBytes(manifest);
 const pub=assessPhase1BfPublication({
  freezeEvidence:publication.freezeEvidence,body:publication.body,
  publisher:publication.publisher,survivingWitness:publication.survivingWitness,
  securityReviewer:publication.securityReviewer,now
 });
 if(!pub.locallySignedPublicationConsistent)
  blockers.add('INVALID_UPSTREAM_PUBLICATION_SIGNATURE_OR_FREEZE');
 const body=publication.body,
  dossier=publication.freezeEvidence.bdEvidence,
  storage=dossier.storageReceipt.body,
  recovery=dossier.recoveryAttestations[0].body;
 if(manifest.logRef!==body.logRef||
    manifest.publicationSha256!==pub.publicationSha256||
    manifest.publicationSequence!==body.publicationSequence||
    manifest.freezeIncidentSha256!==body.freezeIncidentSha256||
    manifest.publisherPinSha256!==body.publisherPublicKeySha256||
    manifest.revokedKeySpkiSha256!==body.revokedKeySpkiSha256||
    manifest.crlIssuerSha256!==body.publisherPublicKeySha256||
    manifest.crlSnapshotSha256!==body.claimedIssuedRevocationSha256||
    manifest.wormVersionSha256!==body.storageObjectVersionSha256||
    manifest.wormRetentionPolicySha256!==storage.retentionPolicySha256||
    manifest.wormDeleteDenialSha256!==body.claimedObjectLockDenialReceiptSha256||
    manifest.wormOverwriteDenialSha256!==storage.overwriteDenialReceiptSha256||
    manifest.wormReadbackSha256!==storage.readbackReceiptSha256||
    manifest.wormRetentionUntil!==storage.retentionUntil||
    manifest.restoreReceiptSha256!==recovery.isolatedRestoreReceiptSha256||
    manifest.restoreTelemetrySha256!==body.claimedEncryptedRestoreTelemetrySha256||
    manifest.restoredManifestSha256!==recovery.restoredManifestSha256||
    manifest.rtoObservedMs!==Date.parse(recovery.completedAt)-Date.parse(recovery.failureAt)||
    manifest.rpoObservedMs!==Date.parse(recovery.failureAt)-Date.parse(recovery.latestRecoveredAt))
  blockers.add('CROSS_SOURCE_PUBLICATION_STORAGE_DR_SCOPE_MISMATCH');
 if(manifest.crlSnapshotSha256===body.priorRevocationSnapshotSha256||
    manifest.ocspResponseSha256===manifest.crlSnapshotSha256||
    manifest.ocspResponseSha256===body.priorRevocationSnapshotSha256)
  blockers.add('STALE_OR_REUSED_CRL_OCSP_DIGEST');
 if(manifest.rtoObservedMs>recovery.rtoObjectiveMs||
    manifest.rpoObservedMs>recovery.rpoObjectiveMs||
    !storage.complianceLock||!storage.deleteDenied||!storage.overwriteDenied||
    !recovery.isolatedStaging||!recovery.mfaReverified||!recovery.revocationRechecked)
  blockers.add('CLAIMED_WORM_DR_OBJECTIVES_NOT_INTERNALLY_MET');
 if(time(manifest.crlThisUpdate)<time(body.issuedAt)||
    time(manifest.reviewedAt)<time(body.observedAt)||
    time(manifest.reviewedAt)>observed+300000||
    time(manifest.expiresAt)<=observed||
    time(manifest.expiresAt)>time(body.expiresAt))
  blockers.add('STALE_FUTURE_OR_EXPIRED_SOURCE_REVIEW');
 const pins=phase1BgAuditorPinsetSha256(auditors);
 if(manifest.auditorPinSetSha256!==pins)
  blockers.add('AUDITOR_PINSET_MISMATCH');
 const seen=new Set(),admins=new Set(),keys=new Set();
 const ineligible=[publication.publisher.pin,publication.survivingWitness.pin,
   publication.securityReviewer.pin,dossier.storageReceipt.pin,
   ...dossier.witnessEnrollments.map(x=>x.pin),
   ...dossier.recoveryAttestations.map(x=>x.pin)];
 for(const role of ROLES){
  const a=auditors.find(x=>x.pin.role===role);
  if(!a){blockers.add('MISSING_AUDITOR_ROLE');continue;}
  const pin=a.pin;
  if(!signatureOK(a,role,bytes))
   blockers.add('INVALID_INDEPENDENT_CANDIDATE_SIGNATURE');
  if(seen.has(pin.sourceRef)||admins.has(pin.authorityRef)||keys.has(pin.publicKeySha256)||
    ineligible.some(x=>x.sourceRef===pin.sourceRef||x.authorityRef===pin.authorityRef||
      x.publicKeySha256===pin.publicKeySha256))
   blockers.add('COMMON_CONTROL_OR_KEY_REUSE_ACROSS_AUDITORS');
  seen.add(pin.sourceRef);admins.add(pin.authorityRef);keys.add(pin.publicKeySha256);
 }
 const reviewSha256=digest(['CROSS_SOURCE_SIGNED_CANDIDATE',bytes.toString('base64'),
  auditors.map(x=>[x.pin.role,x.pin.sourceRef,x.pin.authorityRef,x.pin.publicKeySha256,
   x.signature.signatureBase64]).sort((a,b)=>a[0].localeCompare(b[0]))]);
 return deny({locallyConsistentAuditQuorum:
  [...blockers].every(x=>BASE.includes(x)),
  reviewSha256,previousPublicationSha256:pub.publicationSha256,
  auditorPinSetSha256:pins,
  reviewRevision:manifest.reviewRevision,crlNumber:manifest.crlNumber,
  crlSnapshotSha256:manifest.crlSnapshotSha256,
  crlThisUpdate:manifest.crlThisUpdate,
  publisherPinSha256:manifest.publisherPinSha256});
}
