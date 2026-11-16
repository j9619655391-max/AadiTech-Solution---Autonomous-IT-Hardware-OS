import {createHash,createPublicKey,verify} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {assessPhase1AyArchiveWitnesses,assessPhase1AyRecovery} from './phase1AyWitnessArchiveRecovery.mjs';

// Phase 1BA combines independently scoped *claims*, not authentic authority.
// No credentials, remote clients, storage mutation or release path exist here.
export const BA_PROBE_PURPOSE='AADITECH_PHASE_1BA_ARCHIVE_DENIAL_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const PROBE=['schemaVersion','purpose','logRef','checkpointReceiptSha256',
 'archiveObjectSha256','objectVersionIdSha256','retentionPolicySha256',
 'probeEvidenceSha256','retentionUntil','startedAt','completedAt',
 'deleteAttempt','overwriteAttempt','releaseDecision'];
const PIN=['role','reviewerRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIGNATURE=['reviewerRef','keyId','signatureBase64'];
const FATAL=['EXTERNAL_WITNESS_KEYS_UNAUTHENTICATED','EXTERNAL_WORM_OPERATION_NOT_VERIFIED',
 'INDEPENDENT_ENCRYPTED_RESTORE_NOT_VERIFIED','EXTERNAL_PROVIDER_LEGAL_AUTHORIZATION_PENDING'];
function exact(o,fields){
 if(!o||typeof o!=='object'||Array.isArray(o)||Object.getPrototypeOf(o)!==Object.prototype||
   Object.keys(o).length!==fields.length||Object.keys(o).some(k=>!fields.includes(k)))
  throw Error('1BA exact schema required');
}
function sha(v){if(typeof v!=='string'||!SHA.test(v))throw Error('1BA invalid SHA-256');}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1BA invalid opaque identity');}
function utc(v){
 if(typeof v!=='string'||!TIME.test(v)||!Number.isFinite(Date.parse(v))||
  new Date(v).toISOString()!==v)throw Error('1BA invalid canonical UTC');
 return Date.parse(v);
}
function time(now){if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('1BA invalid clock');return now.getTime();}
export function phase1BaProbeSigningBytes(probe){
 exact(probe,PROBE);
 if(probe.schemaVersion!==1||probe.purpose!==BA_PROBE_PURPOSE||
    probe.releaseDecision!=='HOLD'||probe.deleteAttempt!=='DENIED_CLAIMED'||
    probe.overwriteAttempt!=='DENIED_CLAIMED')throw Error('1BA cannot claim verified WORM or release');
 id(probe.logRef);
 for(const k of ['checkpointReceiptSha256','archiveObjectSha256','objectVersionIdSha256',
  'retentionPolicySha256','probeEvidenceSha256'])sha(probe[k]);
 const started=utc(probe.startedAt),completed=utc(probe.completedAt),expires=utc(probe.retentionUntil);
 if(started>completed||completed-started>3600000||completed>=expires)
  throw Error('1BA invalid probe/retention chronology');
 return Buffer.from('AADITECH-PHASE-1BA-DENIAL-CLAIM-V1\0'+
  JSON.stringify(PROBE.map(k=>probe[k])),'utf8');
}
function publicPin(p){
 exact(p,PIN);
 if(!['STORAGE_AUDITOR','SECURITY_AUDITOR'].includes(p.role))
  throw Error('1BA requires archive and independent security audit roles');
 id(p.reviewerRef);id(p.authorityRef);id(p.keyId);sha(p.publicKeySha256);
 if(typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(p.publicKeyPem))
   throw Error('1BA public SPKI required');
 const k=createPublicKey(p.publicKeyPem);
 if(k.asymmetricKeyType!=='ed25519'||
  createHash('sha256').update(k.export({format:'der',type:'spki'})).digest('hex')!==p.publicKeySha256)
   throw Error('1BA public SPKI fingerprint not valid');
 return k;
}
function signed(sig,msg,p){
 exact(sig,SIGNATURE);
 if(sig.reviewerRef!==p.reviewerRef||sig.keyId!==p.keyId||
  typeof sig.signatureBase64!=='string'||!B64.test(sig.signatureBase64)||
  Buffer.from(sig.signatureBase64,'base64').toString('base64')!==sig.signatureBase64)
  return false;
 return verify(null,msg,publicPin(p),Buffer.from(sig.signatureBase64,'base64'));
}
export function assessPhase1BaIndependentAcceptance({
 azPacket=null,azExpectedDigest=null,
 anchors=[],witnessPins=[],wormProbe=null,wormPins=[],wormSignatures=[],
 drRehearsal=null,drPins=[],drSignatures=[],now=new Date()
}={}){
 const nowMs=time(now),blockers=new Set(FATAL);
 const denial=(partial={})=>Object.freeze({phase:'1BA',...partial,
  independentlyAuthenticatedWitnesses:false,immutableRetentionEnforced:false,
  encryptedDRWitnessed:false,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
 if(!azPacket||!wormProbe||!drRehearsal){
  blockers.add('INCOMPLETE_CROSS_BOUND_EVIDENCE');return denial({internalClaimsConsistent:false});
 }
 sha(azExpectedDigest);
 const az=phase1AzAssessReadiness(azPacket,{now});
 if(!az.packetInspected||az.packetSha256!==azExpectedDigest||
    !az.internalEvidenceConsistent)blockers.add('AZ_DIGEST_OR_CONTENT_MISMATCH');
 const archived=azPacket.archive,dr=azPacket.recovery;
 const witness=assessPhase1AyArchiveWitnesses({
  logRef:archived.logRef,checkpointReceiptSha256:archived.checkpointReceiptSha256,
  archiveObjectSha256:archived.archiveObjectSha256,
  anchors,pins:witnessPins,minimumWitnesses:2,now});
 if(!witness.cryptographicallyConsistent||witness.validProofs<2)
  blockers.add('WITNESS_CRYPTO_OR_QUORUM_MISMATCH');
 if(witnessPins.length!==azPacket.witnesses.length||
   witnessPins.some(pin=>!azPacket.witnesses.some(w=>
    w.publicKeySpkiSha256===pin.publicKeySha256&&
    w.administrativeAuthorityRef===pin.authorityRef)))
  blockers.add('WITNESS_KEY_NOT_BOUND_TO_AZ_ENROLLMENT');
 const signing=phase1BaProbeSigningBytes(wormProbe);
 if(wormProbe.logRef!==archived.logRef||
    wormProbe.checkpointReceiptSha256!==archived.checkpointReceiptSha256||
    wormProbe.archiveObjectSha256!==archived.archiveObjectSha256||
    wormProbe.objectVersionIdSha256!==archived.objectVersionIdSha256||
    wormProbe.retentionPolicySha256!==archived.retentionPolicySha256||
    wormProbe.retentionUntil!==archived.retentionUntil)
  blockers.add('ARCHIVE_PROBE_NOT_BOUND_TO_AZ');
 if(utc(wormProbe.startedAt)>nowMs+300000||
    utc(wormProbe.completedAt)>nowMs+300000)
  blockers.add('FUTURE_ARCHIVE_PROBE');
 if(!Array.isArray(wormPins)||wormPins.length!==2||
    !Array.isArray(wormSignatures)||wormSignatures.length!==2)
  blockers.add('ARCHIVE_TWO_AUDITOR_ATTESTATIONS_MISSING');
 else{
  const roles=['STORAGE_AUDITOR','SECURITY_AUDITOR'],authors=new Set(),keys=new Set(),people=new Set();
  for(let i=0;i<2;i++){
   const pin=wormPins[i],sig=wormSignatures[i];
   publicPin(pin);
   if(pin.role!==roles[i]||authors.has(pin.authorityRef)||people.has(pin.reviewerRef)||
      keys.has(pin.keyId))blockers.add('ARCHIVE_AUDITOR_NOT_INDEPENDENT');
   authors.add(pin.authorityRef);people.add(pin.reviewerRef);keys.add(pin.keyId);
   if(!signed(sig,signing,pin))blockers.add('ARCHIVE_ATTESTATION_INVALID');
  }
  for(const wp of witnessPins){
   if(authors.has(wp.authorityRef)||keys.has(wp.keyId)||people.has(wp.reviewerRef))
    blockers.add('WITNESS_AND_STORAGE_AUDITOR_COLLISION');
  }
 }
 const recovery=assessPhase1AyRecovery({
  rehearsal:drRehearsal,signatures:drSignatures,pins:drPins,now});
 if(!recovery.internalRehearsalCryptographicallyConsistent)
  blockers.add('DR_ATTESTATION_OR_OBJECTIVE_MISMATCH');
 if(drRehearsal.checkpointReceiptSha256!==dr.sourceCheckpointReceiptSha256||
    drRehearsal.restoredCheckpointReceiptSha256!==dr.restoredCheckpointReceiptSha256||
    drRehearsal.backupManifestSha256!==dr.sourceManifestSha256||
    drRehearsal.restoredManifestSha256!==dr.restoredManifestSha256||
    drRehearsal.revocationSnapshotSha256!==dr.revocationSnapshotSha256||
    drRehearsal.startedAt!==dr.startedAt||drRehearsal.completedAt!==dr.completedAt||
    drRehearsal.measuredRpoMs!==dr.measuredRpoMs||
    drRehearsal.rtoTargetMs!==dr.rtoObjectiveMs||
    drRehearsal.rpoTargetMs!==dr.rpoObjectiveMs||
    archived.checkpointReceiptSha256!==drRehearsal.checkpointReceiptSha256||
    wormProbe.archiveObjectSha256!==dr.archiveObjectSha256)
  blockers.add('DR_NOT_BOUND_TO_AZ_ARCHIVE_AND_PROBE');
 if(!Array.isArray(drPins)||drPins.length!==3)
  blockers.add('DR_REVIEWER_INDEPENDENCE_UNVERIFIED');
 else{
  const witnessOrg=new Set(witnessPins.map(w=>w.authorityRef));
  for(let i=0;i<drPins.length;i++){
   const pin=drPins[i],review=azPacket.approvers[i];
   if(!review||review.role!==pin.role||review.reviewerRef!==pin.reviewerRef||
      review.authorityRef!==pin.authorityRef)
    blockers.add('RECOVERY_SIGNER_NOT_BOUND_TO_AZ_REVIEW');
   if(witnessOrg.has(pin.authorityRef)||
      wormPins.some(w=>w.authorityRef===pin.authorityRef))
    blockers.add('RECOVERY_AND_WITNESS_AUDITOR_COLLISION');
  }
 }
 const internal=[...blockers].every(b=>FATAL.includes(b));
 return denial({internalClaimsConsistent:internal,azDigestMatch:az.packetSha256===azExpectedDigest,
  witnessClaimsConsistent:!!witness.cryptographicallyConsistent,
  archiveDenialClaimSignaturesConsistent:!([...blockers].some(b=>b.startsWith('ARCHIVE_'))),
  recoveryClaimSignaturesConsistent:!!recovery.internalRehearsalCryptographicallyConsistent});
}
