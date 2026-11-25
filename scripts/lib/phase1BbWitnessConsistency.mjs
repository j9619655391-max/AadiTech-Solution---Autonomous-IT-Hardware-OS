import {createHash,createPublicKey,verify as verifyEd} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {BA_WITNESS_PURPOSE,phase1BaWitnessBytes} from './phase1BaAcceptanceEvidence.mjs';
import {ANCHOR_PURPOSE,phase1AyVerifyInclusion} from './phase1AyWitnessArchiveRecovery.mjs';

// Phase 1BB append-only consistency: OFFLINE, synthetic-key cryptographic
// verification. Caller-supplied pins are never independently authenticated.
// No network access, trust-root enrollment, persistent writes, GO or deployment.
const SHA=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const OBS=['pin','previous','current','consistencyProofSha256'];
const SNAP=['body','signature','inclusionProofSha256'];
const PIN=['role','reviewerRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIGNATURE=['reviewerRef','keyId','signatureBase64'];
const BASE=['INDEPENDENT_WITNESS_SOURCE_NOT_AUTHENTICATED',
 'PUBLISHED_LOG_HEAD_NOT_EXTERNALLY_AUTHENTICATED',
 'INDEPENDENT_WORM_AND_DR_NOT_VERIFIED',
 'PROVIDER_RCAI_CCA_EMUDHRA_MCA_AUTHORIZATION_PENDING'];
const node=(l,r)=>createHash('sha256').update(Buffer.from([1])).update(l).update(r).digest();
function exact(v,fields){
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.getPrototypeOf(v)!==Object.prototype||
    Object.keys(v).length!==fields.length||Object.keys(v).some(k=>!fields.includes(k)))
  throw Error('1BB consistency exact evidence schema required');
}
function hash(v){if(typeof v!=='string'||!SHA.test(v))throw Error('1BB invalid SHA-256 proof hash');}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1BB invalid witness ref');}
function stamp(v){
 if(typeof v!=='string'||!UTC.test(v)||!Number.isFinite(Date.parse(v))||
   new Date(v).toISOString()!==v)throw Error('1BB invalid canonical timestamp');
 return Date.parse(v);
}
function validClock(now){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('1BB invalid clock');
 return now.getTime();
}
// RFC 6962, 2.1.2: verify a supplied minimal Merkle consistency audit path.
// No access to original leaves is needed; it proves only append-only tree
// arithmetic against the caller-provided old/new roots.
export function phase1BbVerifyConsistencyProof({
 oldSize,newSize,oldRootSha256,newRootSha256,proofSha256
}={}){
 if(!Number.isSafeInteger(oldSize)||!Number.isSafeInteger(newSize)||
    oldSize<1||newSize<oldSize||newSize>1_000_000_000||
    !Array.isArray(proofSha256)||proofSha256.length>64)
  throw Error('1BB invalid consistency sizes or bounded proof');
 hash(oldRootSha256);hash(newRootSha256);
 for(const p of proofSha256)hash(p);
 if(oldSize===newSize)
  return proofSha256.length===0&&oldRootSha256===newRootSha256;
 let fn=oldSize-1,sn=newSize-1;
 while(fn%2===1){
  fn=Math.floor(fn/2);sn=Math.floor(sn/2);
 }
 let first=0,fr,sr;
 if(fn===0){
  fr=Buffer.from(oldRootSha256,'hex');sr=Buffer.from(oldRootSha256,'hex');
 }else{
  if(proofSha256.length===0)return false;
  fr=Buffer.from(proofSha256[0],'hex');sr=Buffer.from(proofSha256[0],'hex');first=1;
 }
 for(let i=first;i<proofSha256.length;i++){
  if(sn===0)return false;
  const p=Buffer.from(proofSha256[i],'hex');
  if(fn%2===1||fn===sn){
   fr=node(p,fr);sr=node(p,sr);
   while(fn!==0&&fn%2===0){
    fn=Math.floor(fn/2);sn=Math.floor(sn/2);
   }
  }else sr=node(sr,p);
  fn=Math.floor(fn/2);sn=Math.floor(sn/2);
 }
 return sn===0&&fr.toString('hex')===oldRootSha256&&sr.toString('hex')===newRootSha256;
}
function verifiedSignature(snap,pin){
 exact(snap,SNAP);exact(pin,PIN);exact(snap.signature,SIGNATURE);
 id(pin.reviewerRef);id(pin.authorityRef);id(pin.keyId);hash(pin.publicKeySha256);
 if(pin.role!=='WITNESS')throw Error('1BB witness signature role required');
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
    !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('1BB requires bounded Ed25519 SPKI pin');
 const pub=createPublicKey(pin.publicKeyPem);
 if(pub.asymmetricKeyType!=='ed25519'||
   createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
  throw Error('1BB unpinned Ed25519 public key');
 const sig=snap.signature;
 if(sig.reviewerRef!==pin.reviewerRef||sig.keyId!==pin.keyId||
    typeof sig.signatureBase64!=='string'||!SIG.test(sig.signatureBase64)||
    Buffer.from(sig.signatureBase64,'base64').toString('base64')!==sig.signatureBase64)return false;
 return verifyEd(null,phase1BaWitnessBytes(snap.body),pub,Buffer.from(sig.signatureBase64,'base64'));
}
function validInclusion(body,proof){
 if(body.purpose!==BA_WITNESS_PURPOSE)throw Error('1BB wrong witness purpose');
 return phase1AyVerifyInclusion({
  schemaVersion:1,purpose:ANCHOR_PURPOSE,logRef:body.logRef,
  checkpointReceiptSha256:body.checkpointReceiptSha256,
  archiveObjectSha256:body.archiveObjectSha256,
  treeSize:body.treeSize,leafIndex:body.leafIndex,rootSha256:body.rootSha256,
  issuedAt:body.observedAt,expiresAt:body.expiresAt,releaseDecision:'HOLD'
 },proof);
}
export function assessPhase1BbWitnessConsistency({
 azPacket=null,observations=[],now=new Date()
}={}){
 const nowMs=validClock(now),blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({
  phase:'1BB',...extra,externallyAuthenticatedPublisher:false,
  independentWitnessKeyCustodyVerified:false,immutableExternalStorageVerified:false,
  independentEncryptedRestoreVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',blockerCodes:Object.freeze([...blockers].sort())
 });
 if(!Array.isArray(observations)||observations.length>8)
  throw Error('1BB bounded consistency witness inventory required');
 if(!azPacket||observations.length<2){
  blockers.add('MISSING_CONSISTENCY_WITNESSES');
  return deny({internalAppendOnlyConsistent:false,distinctClaimedAuthorities:0});
 }
 const az=phase1AzAssessReadiness(azPacket,{now});
 if(!az.packetInspected||!az.internalEvidenceConsistent)
  blockers.add('AZ_READINESS_PACKET_INVALID');
 if(observations.length!==azPacket.witnesses.length)
  blockers.add('INCOMPLETE_ENROLLED_WITNESS_SET');
 const admins=new Set(),keys=new Set(),refs=new Set(),orgs=new Set();
 let valid=0,oldHead=null,newHead=null;
 for(const entry of observations){
  exact(entry,OBS);exact(entry.previous,SNAP);exact(entry.current,SNAP);
  const pin=entry.pin,a=entry.previous.body,b=entry.current.body;
  // Strict schemas, signed scopes and bounds are checked by canonicalizers.
  phase1BaWitnessBytes(a);phase1BaWitnessBytes(b);
  const candidate=azPacket.witnesses.find(w=>w.witnessRef===b.witnessRef);
  if(!candidate||candidate.state!=='CANDIDATE_UNVERIFIED'||
     candidate.scope!=='CHECKPOINT_WITNESS_ONLY'||
     candidate.publicKeySpkiSha256!==pin.publicKeySha256||
     candidate.organizationRef!==b.organizationRef||
     candidate.administrativeAuthorityRef!==pin.authorityRef||
     candidate.administrativeAuthorityRef!==b.administrativeAuthorityRef)
   blockers.add('WITNESS_SOURCE_ENROLLMENT_MISMATCH');
  if(admins.has(pin.authorityRef)||keys.has(pin.keyId)||
     refs.has(b.witnessRef)||orgs.has(b.organizationRef))
   blockers.add('WITNESS_COMMON_ADMIN_OR_DUPLICATE_ENROLLMENT');
  admins.add(pin.authorityRef);keys.add(pin.keyId);
  refs.add(b.witnessRef);orgs.add(b.organizationRef);
  if(a.packetSha256!==az.packetSha256||b.packetSha256!==az.packetSha256||
     a.logRef!==azPacket.archive.logRef||b.logRef!==azPacket.archive.logRef||
     a.checkpointReceiptSha256!==azPacket.archive.checkpointReceiptSha256||
     b.checkpointReceiptSha256!==azPacket.archive.checkpointReceiptSha256||
     a.archiveObjectSha256!==azPacket.archive.archiveObjectSha256||
     b.archiveObjectSha256!==azPacket.archive.archiveObjectSha256||
     a.witnessRef!==b.witnessRef||a.organizationRef!==b.organizationRef||
     a.administrativeAuthorityRef!==b.administrativeAuthorityRef||
     a.leafIndex!==b.leafIndex)
   blockers.add('HISTORICAL_AND_CURRENT_SCOPE_MISMATCH');
  const oldObserved=stamp(a.observedAt),newObserved=stamp(b.observedAt);
  if(newObserved<=oldObserved||newObserved>nowMs+300000||
     stamp(a.expiresAt)<=oldObserved||stamp(b.expiresAt)<=nowMs||
     stamp(b.expiresAt)<=newObserved)
   blockers.add('STALE_OR_REORDERED_WITNESS_CHECKPOINT');
  if(!verifiedSignature(entry.previous,pin)||!verifiedSignature(entry.current,pin))
   blockers.add('INVALID_SIGNED_WITNESS_HEAD');
  if(!validInclusion(a,entry.previous.inclusionProofSha256)||
     !validInclusion(b,entry.current.inclusionProofSha256))
   blockers.add('INVALID_ARCHIVE_INCLUSION_IN_HEAD');
  if(!phase1BbVerifyConsistencyProof({
   oldSize:a.treeSize,newSize:b.treeSize,
   oldRootSha256:a.rootSha256,newRootSha256:b.rootSha256,
   proofSha256:entry.consistencyProofSha256
  }))blockers.add('APPEND_ONLY_CONSISTENCY_PROOF_INVALID');
  const oldLocus=a.treeSize+'|'+a.rootSha256,newLocus=b.treeSize+'|'+b.rootSha256;
  if(oldHead!==null&&oldHead!==oldLocus)blockers.add('OLD_HEAD_WITNESS_EQUIVOCATION');
  if(newHead!==null&&newHead!==newLocus)blockers.add('NEW_HEAD_WITNESS_EQUIVOCATION');
  oldHead=oldLocus;newHead=newLocus;
  valid++;
 }
 if(admins.size<2||refs.size<2)blockers.add('INDEPENDENT_WITNESS_QUORUM_UNAVAILABLE');
 const problems=[...blockers].filter(code=>!BASE.includes(code));
 return deny({internalAppendOnlyConsistent:problems.length===0,
  distinctClaimedAuthorities:admins.size,cryptographicallyCheckedPairs:valid,
  oldTreeHead:oldHead,newTreeHead:newHead});
}
