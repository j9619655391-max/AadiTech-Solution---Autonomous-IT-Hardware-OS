import {createHash, createPublicKey, verify} from 'node:crypto';
import {phase1AwCheckpointReceiptSha256, phase1AwCheckpointSigningBytes} from './phase1AwSignedCheckpoint.mjs';

// Offline, deny-only governance. Inputs are never evidence of independently
// authenticated reviewer authority, external witnesses or production release.
const HASH=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const PREFIX='AADITECH-PHASE-1AX-REVIEWER-ROLLOVER-V1\0';
function ensure(value,keys){
 if(!value||typeof value!=='object'||Array.isArray(value)||
   Object.getPrototypeOf(value)!==Object.prototype||
   Object.keys(value).length!==keys.length||
   Object.keys(value).some(k=>!keys.includes(k))) throw Error('1AX invalid exact schema');
}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1AX invalid reference');}
function hash(v){if(typeof v!=='string'||!HASH.test(v))throw Error('1AX invalid digest');}
function instant(v){
 if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v)||
   !Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)throw Error('1AX invalid timestamp');
 return Date.parse(v);
}
function key(pin){
 ensure(pin,['reviewerRef','keyId','publicKeyPem','publicKeySha256','authorityRef']);
 id(pin.reviewerRef);id(pin.keyId);id(pin.authorityRef);hash(pin.publicKeySha256);
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
   throw Error('1AX requires public SPKI');
 const k=createPublicKey(pin.publicKeyPem);
 if(k.asymmetricKeyType!=='ed25519'||createHash('sha256').update(k.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
   throw Error('1AX public key pin mismatch');
 return k;
}
function signature(sig,message,pin){
 ensure(sig,['reviewerRef','keyId','signatureBase64']);
 if(sig.reviewerRef!==pin.reviewerRef||sig.keyId!==pin.keyId||
   typeof sig.signatureBase64!=='string'||!B64.test(sig.signatureBase64)||
   Buffer.from(sig.signatureBase64,'base64').toString('base64')!==sig.signatureBase64)
   return false;
 return verify(null,message,key(pin),Buffer.from(sig.signatureBase64,'base64'));
}
const ROLLOVER_FIELDS=['schemaVersion','purpose','organizationRef','generation','predecessorDigest','oldKeyId','newKeyId','newPublicKeySha256','proposedAt','activateAt','expiresAt','releaseDecision'];
export const ROLLOVER_PURPOSE='AADITECH_REVIEWER_ROLLOVER_HOLD_V1';
export function phase1AxRolloverSigningBytes(proposal){
 ensure(proposal,ROLLOVER_FIELDS);
 if(proposal.schemaVersion!==1||proposal.purpose!==ROLLOVER_PURPOSE||
   proposal.releaseDecision!=='HOLD'||!Number.isSafeInteger(proposal.generation)||proposal.generation<2||
   proposal.generation>1_000_000)throw Error('1AX invalid rollover purpose/generation');
 id(proposal.organizationRef);id(proposal.oldKeyId);id(proposal.newKeyId);
 if(proposal.oldKeyId===proposal.newKeyId)throw Error('1AX reused old key');
 hash(proposal.predecessorDigest);hash(proposal.newPublicKeySha256);
 const a=instant(proposal.proposedAt),b=instant(proposal.activateAt),c=instant(proposal.expiresAt);
 if(!(a<=b&&b<c&&c-a<=365*86400000))throw Error('1AX invalid rollover window');
 return Buffer.from(PREFIX+JSON.stringify(ROLLOVER_FIELDS.map(k=>proposal[k])));
}
export function assessPhase1AxKeyRollover({proposal=null,predecessor=null,replacement=null,oldSigner=null,independentApprover=null,oldSignature=null,approvalSignature=null,compromised=false,now=new Date()}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('1AX invalid clock');
 const blockers=['EXTERNAL_REVIEWER_AUTHORITY_UNVERIFIED'];
 if(!proposal||!predecessor||!replacement||!oldSigner||!independentApprover||!oldSignature||!approvalSignature)
  return Object.freeze({phase:'1AX',cryptographicRolloverValid:false,quarantined:true,productionReleaseAuthorized:false,releaseDecision:'HOLD',blockerCodes:Object.freeze([...blockers,'MISSING_ROLLOVER_EVIDENCE'].sort())});
 const message=phase1AxRolloverSigningBytes(proposal);
 ensure(predecessor,['organizationRef','generation','digest','keyId','status']);
 ensure(replacement,['keyId','publicKeySha256']);
 id(predecessor.organizationRef);id(predecessor.keyId);hash(predecessor.digest);
 id(replacement.keyId);hash(replacement.publicKeySha256);
 if(!Number.isSafeInteger(predecessor.generation)||predecessor.generation<1)throw Error('1AX invalid predecessor generation');
 if(predecessor.organizationRef!==proposal.organizationRef||
   predecessor.generation+1!==proposal.generation||
   predecessor.digest!==proposal.predecessorDigest||
   predecessor.keyId!==proposal.oldKeyId||
   replacement.keyId!==proposal.newKeyId||
   replacement.publicKeySha256!==proposal.newPublicKeySha256||
   oldSigner.keyId!==predecessor.keyId)blockers.push('ROLLOVER_CHAIN_MISMATCH');
 if(oldSigner.reviewerRef===independentApprover.reviewerRef||
   oldSigner.keyId===independentApprover.keyId||
   oldSigner.authorityRef===independentApprover.authorityRef)
  blockers.push('APPROVER_NOT_INDEPENDENT');
 if(predecessor.status!=='ACTIVE'||compromised)blockers.push('PREDECESSOR_UNSAFE');
 if(now.getTime()<instant(proposal.activateAt)||now.getTime()>=instant(proposal.expiresAt))
  blockers.push('ROLLOVER_OUTSIDE_VALIDITY');
 if(instant(proposal.proposedAt)>now.getTime()+300000)blockers.push('FUTURE_PROPOSAL');
 if(!signature(oldSignature,message,oldSigner)||!signature(approvalSignature,message,independentApprover))
  blockers.push('ROLLOVER_SIGNATURE_INVALID');
 return Object.freeze({phase:'1AX',cryptographicRolloverValid:blockers.length===1,
  quarantined:blockers.length!==1,independentlyAuthenticatedApprovers:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD',blockerCodes:Object.freeze(blockers.sort())});
}
// Compare independently obtained signed checkpoints, not a mutable "latest"
// pointer. A conflicting valid same-sequence receipt must never win by arrival.
export function assessPhase1AxCheckpointWitnesses({observations=[],trustedPins=[],now=new Date(),minimumIndependentWitnesses=2}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('1AX invalid clock');
 if(!Array.isArray(observations)||observations.length>64||!Array.isArray(trustedPins)||trustedPins.length>16||
   !Number.isSafeInteger(minimumIndependentWitnesses)||minimumIndependentWitnesses<2||minimumIndependentWitnesses>16)
  throw Error('1AX invalid witness inventory');
 const approved=new Map();
 for(const pin of trustedPins){
  key(pin);
  if(approved.has(pin.keyId))throw Error('1AX duplicate witness key');
  approved.set(pin.keyId,pin);
 }
 const sameSequence=new Map(),bySequence=new Map(),groups=new Map();
 const authorities=new Set(),blockers=new Set(['EXTERNAL_WITNESSES_UNVERIFIED']);
 let valid=0;
 for(const entry of observations){
  ensure(entry,['checkpoint','witnessPinId','witnessSignature','observedAt']);
  id(entry.witnessPinId);const when=instant(entry.observedAt);
  if(when>now.getTime()+300000){blockers.add('FUTURE_WITNESS');continue;}
  const p=approved.get(entry.witnessPinId);
  if(!p){blockers.add('UNKNOWN_WITNESS');continue;}
  const receipt=phase1AwCheckpointReceiptSha256(entry.checkpoint);
  const msg=Buffer.from('AADITECH-PHASE-1AX-WITNESS-V1\0'+receipt);
  if(!signature(entry.witnessSignature,msg,p)){blockers.add('INVALID_WITNESS_SIGNATURE');continue;}
  const cp=entry.checkpoint;
  if(when<instant(cp.issuedAt)||when>instant(cp.expiresAt)){
   blockers.add('WITNESS_OUTSIDE_CHECKPOINT_WINDOW');continue;
  }
  valid++;authorities.add(p.authorityRef);
  const {signatures: ignoredSignatures,...checkpointBody}=cp;
  const claimDigest=createHash('sha256').update(phase1AwCheckpointSigningBytes(checkpointBody)).digest('hex');
  const locus=cp.providerCode+'|'+cp.requestedScope+'|'+cp.sequence;
  const previous=sameSequence.get(locus);
  if(previous&&previous!==claimDigest)blockers.add('SIGNED_CHECKPOINT_EQUIVOCATION');
  else sameSequence.set(locus,claimDigest);
  const groupKey=locus+'|'+claimDigest;
  let group=groups.get(groupKey);
  if(!group){group={checkpoint:cp,authorities:new Set(),receipts:new Set()};
    groups.set(groupKey,group);}
  if(group.authorities.has(p.authorityRef))blockers.add('WITNESS_AUTHORITY_COLLISION');
  group.authorities.add(p.authorityRef);group.receipts.add(receipt);
  if(!bySequence.has(locus))bySequence.set(locus,[]);
  bySequence.get(locus).push({receipt,checkpoint:cp});
 }
 if(!groups.size||[...groups.values()].some(x=>x.authorities.size<minimumIndependentWitnesses))
  blockers.add('WITNESS_QUORUM_UNAVAILABLE');
 for(const group of groups.values()){
  const cp=group.checkpoint;
  if(cp.sequence===1)continue;
  const earlier=bySequence.get(cp.providerCode+'|'+cp.requestedScope+'|'+(cp.sequence-1));
  if(!earlier?.length){blockers.add('MISSING_WITNESSED_PREDECESSOR');continue;}
  const linked=earlier.filter(x=>x.receipt===cp.priorCheckpointSha256);
  if(!linked.length){blockers.add('WITNESS_PREDECESSOR_MISMATCH');continue;}
  if(linked.every(x=>instant(cp.issuedAt)<instant(x.checkpoint.issuedAt)||
      instant(cp.issuedAt)>instant(x.checkpoint.expiresAt)))
   blockers.add('SIGNED_CHECKPOINT_CONTINUITY_GAP');
 }
 if(valid!==observations.length)blockers.add('UNVERIFIED_WITNESS_OBSERVATION');
 return Object.freeze({phase:'1AX',validWitnessObservations:valid,distinctWitnessAuthorities:authorities.size,
  witnessedCheckpointClaims:groups.size,
  claimedWitnessContinuityConsistent:![...blockers].some(c=>[
   'MISSING_WITNESSED_PREDECESSOR','WITNESS_PREDECESSOR_MISMATCH',
   'SIGNED_CHECKPOINT_CONTINUITY_GAP','SIGNED_CHECKPOINT_EQUIVOCATION'
  ].includes(c)),
  equivocationDetected:blockers.has('SIGNED_CHECKPOINT_EQUIVOCATION'),
  quarantined:true,checkpointSignaturesAuthenticated:false,
  independentExternalWitnessesAuthenticated:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
}
export function assessPhase1AxRecoveryRehearsal({baselineDigest=null,restoredDigest=null,revocationChecked=false,securityReviewerRef=null,operationsReviewerRef=null,measuredRtoMs=null,measuredRpoMs=null}={}){
 const blockers=['EXTERNAL_RECOVERY_APPROVAL_PENDING'];
 if(!baselineDigest||!restoredDigest){blockers.push('RESTORE_EVIDENCE_MISSING');}
 else {hash(baselineDigest);hash(restoredDigest);if(baselineDigest!==restoredDigest)blockers.push('RESTORE_CHECKPOINT_DIVERGENCE');}
 if(!revocationChecked)blockers.push('REVOCATION_RECHECK_MISSING');
 if(!securityReviewerRef||!operationsReviewerRef)blockers.push('INDEPENDENT_RECOVERY_REVIEW_MISSING');
 else {id(securityReviewerRef);id(operationsReviewerRef);if(securityReviewerRef===operationsReviewerRef)blockers.push('RECOVERY_SELF_REVIEW');}
 if(!Number.isSafeInteger(measuredRtoMs)||measuredRtoMs<0||
   !Number.isSafeInteger(measuredRpoMs)||measuredRpoMs<0)blockers.push('RTO_RPO_NOT_MEASURED');
 return Object.freeze({phase:'1AX',syntheticRecoveryInputsChecked:blockers.length===1,
   realRestoreWitnessed:false,quarantined:blockers.length>1,
   productionReleaseAuthorized:false,releaseDecision:'HOLD',blockerCodes:Object.freeze(blockers.sort())});
}
