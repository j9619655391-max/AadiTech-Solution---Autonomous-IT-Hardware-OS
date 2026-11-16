import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {assessPhase1BcWitnessCustody} from './phase1BcWitnessCustody.mjs';

// Phase 1BD: OFFLINE candidate key-rotation and archive/DR digest governance.
// No independently authenticated keys, licensed provider, WORM storage or
// encrypted recovery can be asserted by this library or its CI fixtures.
export const BD_ROTATION_PURPOSE='AADITECH_PHASE_1BD_WITNESS_ROTATION_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const FIELDS=['schemaVersion','purpose','logRef','previousPacketSha256',
 'replacementPacketSha256','previousEvidenceSha256','replacementEvidenceSha256',
 'previousPinSetSha256','replacementPinSetSha256',
 'handoverTreeSize','handoverRootSha256','replacementTreeSize','replacementRootSha256',
 'archiveObjectSha256','claimedObjectLockAuditSha256','claimedEncryptedDrAuditSha256',
 'issuedAt','effectiveAt','expiresAt','reason','releaseDecision'];
const PIN=['role','reviewerRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIGNATURE=['reviewerRef','keyId','signatureBase64'];
const ATTESTATION=['witnessRef','signature'];
const REVIEW=['pin','signature'];
const BASE=['OUT_OF_BAND_WITNESS_KEY_OWNERSHIP_NOT_VERIFIED',
 'INDEPENDENT_ORGANIZATIONAL_AUTHORITY_NOT_VERIFIED',
 'CLOUD_OBJECT_LOCK_AUDIT_NOT_AUTHENTICATED',
 'REAL_ENCRYPTED_DR_AND_RTO_RPO_NOT_WITNESSED',
 'LEGAL_PROVIDER_RCAI_CCA_EMUDHRA_MCA_APPROVAL_PENDING'];
function exact(o,fields){
 if(!o||typeof o!=='object'||Array.isArray(o)||Object.getPrototypeOf(o)!==Object.prototype||
  Object.keys(o).length!==fields.length||Object.keys(o).some(k=>!fields.includes(k)))
  throw Error('1BD exact evidence schema required');
}
function sha(x){if(typeof x!=='string'||!SHA.test(x)||/^0{64}$/.test(x))throw Error('1BD invalid digest');}
function ref(x){if(typeof x!=='string'||!REF.test(x))throw Error('1BD invalid opaque reference');}
function time(s){
 if(typeof s!=='string'||!UTC.test(s)||!Number.isFinite(Date.parse(s))||
  new Date(s).toISOString()!==s)throw Error('1BD noncanonical UTC timestamp');
 return Date.parse(s);
}
function checkedNow(now){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('1BD invalid assessment clock');
 return now.getTime();
}
function publicPin(pin){
 exact(pin,PIN);
 for(const k of ['reviewerRef','authorityRef','keyId'])ref(pin[k]);
 sha(pin.publicKeySha256);
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('1BD bounded public SPKI required');
 const key=createPublicKey(pin.publicKeyPem);
 if(key.asymmetricKeyType!=='ed25519'||
  createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
  throw Error('1BD public SPKI mismatch');
 return key;
}
function signed(sig,pin,msg){
 exact(sig,SIGNATURE);
 if(sig.reviewerRef!==pin.reviewerRef||sig.keyId!==pin.keyId||
  typeof sig.signatureBase64!=='string'||!SIG.test(sig.signatureBase64)||
  Buffer.from(sig.signatureBase64,'base64').toString('base64')!==sig.signatureBase64)
  return false;
 return edVerify(null,msg,publicPin(pin),Buffer.from(sig.signatureBase64,'base64'));
}
export function phase1BdRotationSigningBytes(envelope){
 exact(envelope,FIELDS);
 if(envelope.schemaVersion!==1||envelope.purpose!==BD_ROTATION_PURPOSE||
    envelope.releaseDecision!=='HOLD'||envelope.reason!=='KEY_ROTATION_CANDIDATE')
  throw Error('1BD cannot authorize production or arbitrary rotation');
 ref(envelope.logRef);
 for(const k of FIELDS.filter(x=>x.endsWith('Sha256')))sha(envelope[k]);
 if(!Number.isSafeInteger(envelope.handoverTreeSize)||!Number.isSafeInteger(envelope.replacementTreeSize)||
    envelope.handoverTreeSize<1||envelope.replacementTreeSize<=envelope.handoverTreeSize||
    envelope.replacementTreeSize>1_000_000_000)
  throw Error('1BD requires append-only head growth');
 const issued=time(envelope.issuedAt),effective=time(envelope.effectiveAt),expiry=time(envelope.expiresAt);
 if(expiry<=issued||expiry-issued>3600000||effective<issued||effective>=expiry)
  throw Error('1BD bounded effective/expiry chronology required');
 return Buffer.from('AADITECH-PHASE-1BD-ROTATION-V1\0'+
  JSON.stringify(FIELDS.map(k=>envelope[k])),'utf8');
}
export function assessPhase1BdRotation({
 previous=null,replacement=null,envelope=null,
 previousWitnessSignatures=[],replacementWitnessSignatures=[],
 reviews=[],now=new Date()
}={}){
 const current=checkedNow(now),blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({phase:'1BD',
  locallySignedHandoverConsistent:false,handoverSha256:null,
  previousWitnessPinSetSha256:null,replacementWitnessPinSetSha256:null,
  independentSourceOfTruthAuthenticated:false,
  independentKeyCustodyVerified:false,realObjectLockAuditVerified:false,
  realEncryptedDrVerified:false,externalSignatoryVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',...extra,
  blockerCodes:Object.freeze([...blockers].sort())});
 if(!previous||!replacement||!envelope){
  blockers.add('INCOMPLETE_ROTATION_EVIDENCE');
  return deny();
 }
 const msg=phase1BdRotationSigningBytes(envelope);
 const issued=time(envelope.issuedAt),expiry=time(envelope.expiresAt);
 if(issued>current+300000||expiry<=current)
  blockers.add('STALE_OR_FUTURE_ROTATION_CLAIM');
 const oldAz=phase1AzAssessReadiness(previous.azPacket,{now});
 const newAz=phase1AzAssessReadiness(replacement.azPacket,{now});
 const oldHead=assessPhase1BcWitnessCustody(previous);
 const newHead=assessPhase1BcWitnessCustody(replacement);
 if(!oldAz.internalEvidenceConsistent||!newAz.internalEvidenceConsistent||
    !oldHead.claimCryptographicallyConsistent||!newHead.claimCryptographicallyConsistent)
  blockers.add('UNVERIFIED_CANDIDATE_MERKLE_CONTINUITY');
 if(newAz.revision!==oldAz.revision+1||
    replacement.azPacket.previousPacketSha256!==oldAz.packetSha256)
  blockers.add('INVALID_AZ_ROTATION_PREDECESSOR');
 const oldCandidates=previous.azPacket.witnesses,newCandidates=replacement.azPacket.witnesses;
 if(!Array.isArray(oldCandidates)||!Array.isArray(newCandidates)||
    oldCandidates.length!==2||newCandidates.length!==2)
  blockers.add('ROTATION_REQUIRES_TWO_EXISTING_WITNESS_ORGANIZATIONS');
 else{
  for(const old of oldCandidates){
   const currentWitness=newCandidates.find(w=>w.witnessRef===old.witnessRef);
   if(!currentWitness||old.organizationRef!==currentWitness.organizationRef||
     old.administrativeAuthorityRef!==currentWitness.administrativeAuthorityRef)
    blockers.add('ROTATION_REPLACED_AUTHORITY_WITHOUT_ENROLLMENT');
   else if(old.publicKeySpkiSha256===currentWitness.publicKeySpkiSha256)
    blockers.add('WITNESS_KEY_WAS_NOT_ROTATED');
  }
  const allKeys=[...oldCandidates,...newCandidates].map(w=>w.publicKeySpkiSha256);
  if(new Set(allKeys).size!==4)
   blockers.add('ROTATION_KEY_REUSE_ACROSS_AUTHORITIES');
 }
 if(JSON.stringify(previous.azPacket.archive)!==JSON.stringify(replacement.azPacket.archive)||
    JSON.stringify(previous.azPacket.recovery)!==JSON.stringify(replacement.azPacket.recovery)||
    JSON.stringify(previous.azPacket.approvers)!==JSON.stringify(replacement.azPacket.approvers))
  blockers.add('ARCHIVE_RECOVERY_OR_REVIEW_SCOPE_CHANGED');
 if(oldHead.newRootSha256!==newHead.oldRootSha256||
    oldHead.newTreeSize!==newHead.oldTreeSize)
  blockers.add('ROTATION_FORKED_HISTORICAL_TREE_HEAD');
 if(envelope.logRef!==previous.azPacket.archive.logRef||
    envelope.logRef!==replacement.azPacket.archive.logRef||
    envelope.previousPacketSha256!==oldAz.packetSha256||
    envelope.replacementPacketSha256!==newAz.packetSha256||
    envelope.previousEvidenceSha256!==oldHead.evidenceSha256||
    envelope.replacementEvidenceSha256!==newHead.evidenceSha256||
    envelope.previousPinSetSha256!==oldHead.pinSetSha256||
    envelope.replacementPinSetSha256!==newHead.pinSetSha256||
    envelope.handoverTreeSize!==oldHead.newTreeSize||
    envelope.handoverRootSha256!==oldHead.newRootSha256||
    envelope.replacementTreeSize!==newHead.newTreeSize||
    envelope.replacementRootSha256!==newHead.newRootSha256||
    envelope.archiveObjectSha256!==previous.azPacket.archive.archiveObjectSha256)
  blockers.add('ROTATION_ENVELOPE_PROOF_BINDING_MISMATCH');
 function witnessQuorum(records,proof){
  if(!Array.isArray(records)||records.length!==2||
     !Array.isArray(proof.observations)||proof.observations.length!==2){
   blockers.add('MISSING_DUAL_WITNESS_COSIGNATURES');return;
  }
  const seen=new Set(),administrators=new Set(),identities=new Set();
  for(const entry of records){
   exact(entry,ATTESTATION);ref(entry.witnessRef);
   if(seen.has(entry.witnessRef))blockers.add('WITNESS_COSIGNATURE_REPLAY');
   seen.add(entry.witnessRef);
   const witness=proof.observations.find(w=>w.current.body.witnessRef===entry.witnessRef);
   if(!witness){blockers.add('UNENROLLED_WITNESS_COSIGNER');continue;}
   const pin=witness.pin;
   if(pin.role!=='WITNESS'||administrators.has(pin.authorityRef)||
      identities.has(pin.reviewerRef))blockers.add('COMMON_CONTROL_OF_COSIGNERS');
   administrators.add(pin.authorityRef);identities.add(pin.reviewerRef);
   if(!signed(entry.signature,pin,msg))
    blockers.add('INVALID_WITNESS_COSIGNATURE');
  }
 }
 witnessQuorum(previousWitnessSignatures,previous);
 witnessQuorum(replacementWitnessSignatures,replacement);
 if(!Array.isArray(reviews)||reviews.length!==3){
  blockers.add('MISSING_SECURITY_OPERATIONS_OWNER_REVIEW');
 }else{
  const roles=['SECURITY','OPERATIONS','OWNER'],reviewers=new Set(),admins=new Set();
  for(let i=0;i<3;i++){
   const r=reviews[i];exact(r,REVIEW);const pin=r.pin;
   const expected=previous.azPacket.approvers[i];
   if(pin.role!==roles[i]||!expected||
     pin.reviewerRef!==expected.reviewerRef||
     pin.authorityRef!==expected.authorityRef)
    blockers.add('UNENROLLED_GOVERNANCE_REVIEWER');
   if(reviewers.has(pin.reviewerRef)||admins.has(pin.authorityRef)||
      [...previous.observations,...replacement.observations].some(w=>
       w.pin.authorityRef===pin.authorityRef))
    blockers.add('NONINDEPENDENT_GOVERNANCE_REVIEWER');
   reviewers.add(pin.reviewerRef);admins.add(pin.authorityRef);
   if(!signed(r.signature,pin,msg))
    blockers.add('INVALID_GOVERNANCE_REVIEW_SIGNATURE');
  }
 }
 const problems=[...blockers].filter(x=>!BASE.includes(x));
 const handoverSha256=createHash('sha256').update(
  'AADITECH-PHASE-1BD-ACCEPTANCE-COMMIT-V1\0').update(msg)
  .update(JSON.stringify([
   previousWitnessSignatures,replacementWitnessSignatures,reviews.map(r=>r.signature)
  ])).digest('hex');
 return deny({
  locallySignedHandoverConsistent:problems.length===0,
  handoverSha256,previousWitnessPinSetSha256:oldHead.pinSetSha256,
  replacementWitnessPinSetSha256:newHead.pinSetSha256,
  independentlyVerifiedAuditEvidence:false
 });
}
