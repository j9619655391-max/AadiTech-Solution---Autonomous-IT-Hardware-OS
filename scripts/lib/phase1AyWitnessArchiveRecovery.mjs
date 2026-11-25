import {createHash,createPublicKey,verify as cryptoVerify} from 'node:crypto';

// Phase 1AY: OFFLINE interoperability of publicly pinned signature and
// transparency inclusion proofs. The caller supplying a pin is NOT evidence of
// independent source authentication, immutable retention or real restoration.
export const ANCHOR_PURPOSE='AADITECH_PHASE_1AY_WITNESS_ARCHIVE_HOLD_V1';
export const RECOVERY_PURPOSE='AADITECH_PHASE_1AY_RECOVERY_REHEARSAL_HOLD_V1';
const SHA=/^[0-9a-f]{64}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const ANCHOR_FIELDS=['schemaVersion','purpose','logRef','checkpointReceiptSha256',
 'archiveObjectSha256','treeSize','leafIndex','rootSha256','issuedAt','expiresAt','releaseDecision'];
const RECOVERY_FIELDS=['schemaVersion','purpose','incidentRef','checkpointReceiptSha256',
 'restoredCheckpointReceiptSha256','backupManifestSha256','restoredManifestSha256',
 'revocationSnapshotSha256','startedAt','completedAt','measuredRpoMs',
 'rtoTargetMs','rpoTargetMs','outboundHeld','releaseDecision'];
const PIN_FIELDS=['role','reviewerRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const SIG_FIELDS=['reviewerRef','keyId','signatureBase64'];
const ENTRY_FIELDS=['body','signature','inclusionProofSha256'];
const HOLD=['EXTERNAL_WITNESS_PROVENANCE_NOT_AUTHENTICATED',
 'IMMUTABLE_ARCHIVE_RETENTION_NOT_INDEPENDENTLY_VERIFIED'];
function exact(o,keys){
 if(!o||typeof o!=='object'||Array.isArray(o)||Object.getPrototypeOf(o)!==Object.prototype||
   Object.keys(o).length!==keys.length||Object.keys(o).some(k=>!keys.includes(k)))
  throw Error('Phase 1AY exact schema required');
}
function ref(v){if(typeof v!=='string'||!REF.test(v))throw Error('Invalid opaque 1AY ref');}
function sha(v){if(typeof v!=='string'||!SHA.test(v))throw Error('Invalid SHA-256');}
function utc(v){
 if(typeof v!=='string'||!TIME.test(v)||!Number.isFinite(Date.parse(v))||
    new Date(v).toISOString()!==v)throw Error('Invalid canonical UTC');
 return Date.parse(v);
}
function evaluation(now){if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('Invalid clock');return now.getTime();}
const hashBytes=x=>createHash('sha256').update(x).digest();
const hashNode=(a,b)=>hashBytes(Buffer.concat([Buffer.from([1]),a,b]));
export function phase1AyAnchorSigningBytes(body){
 exact(body,ANCHOR_FIELDS);
 if(body.schemaVersion!==1||body.purpose!==ANCHOR_PURPOSE||body.releaseDecision!=='HOLD')
  throw Error('Phase 1AY anchor must remain HOLD');
 ref(body.logRef);sha(body.checkpointReceiptSha256);sha(body.archiveObjectSha256);sha(body.rootSha256);
 if(!Number.isSafeInteger(body.treeSize)||body.treeSize<1||body.treeSize>1_000_000_000||
   !Number.isSafeInteger(body.leafIndex)||body.leafIndex<0||body.leafIndex>=body.treeSize)
  throw Error('Invalid transparency tree coordinates');
 const start=utc(body.issuedAt),end=utc(body.expiresAt);
 if(end<=start||end-start>86400000)throw Error('Invalid anchor lifetime');
 // Root hash is signature-bound; the actual inclusion leaf must be independent
 // of root to avoid a circular signed statement.
 return Buffer.from('AADITECH-PHASE-1AY-ANCHOR-V1\0'+
  JSON.stringify(ANCHOR_FIELDS.map(k=>body[k])),'utf8');
}
export function phase1AyInclusionLeafHash(body){
 exact(body,ANCHOR_FIELDS);phase1AyAnchorSigningBytes(body);
 return hashBytes(Buffer.from('AADITECH-PHASE-1AY-INCLUSION-V1\0'+
  JSON.stringify([body.logRef,body.checkpointReceiptSha256,body.archiveObjectSha256]),'utf8'));
}
// RFC 6962-style SHA-256 Merkle audit path, with leaf 0x00 and node 0x01.
// This validates a supplied tree head; it does not authenticate its publisher.
export function phase1AyVerifyInclusion(body,proof){
 phase1AyAnchorSigningBytes(body);
 if(!Array.isArray(proof)||proof.length>32)throw Error('Invalid bounded audit path');
 let index=body.leafIndex,last=body.treeSize-1;
 let h=hashBytes(Buffer.concat([Buffer.from([0]),phase1AyInclusionLeafHash(body)]));
 for(const p of proof){
  sha(p);
  if(last===0) return false;
  const sibling=Buffer.from(p,'hex');
  if(index%2===1||index===last){
   h=hashNode(sibling,h);
   while(index%2===0&&index!==0){index=Math.floor(index/2);last=Math.floor(last/2);}
  }else h=hashNode(h,sibling);
  index=Math.floor(index/2);last=Math.floor(last/2);
 }
 return last===0&&h.toString('hex')===body.rootSha256;
}
function publicKey(pin){
 exact(pin,PIN_FIELDS);
 ref(pin.reviewerRef);ref(pin.authorityRef);ref(pin.keyId);sha(pin.publicKeySha256);
 if(typeof pin.role!=='string'||!['WITNESS','SECURITY','OPERATIONS','OWNER'].includes(pin.role))
  throw Error('Unexpected 1AY reviewer role');
 if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
   !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(pin.publicKeyPem))
  throw Error('Only bounded public SPKI is allowed');
 const k=createPublicKey(pin.publicKeyPem);
 if(k.asymmetricKeyType!=='ed25519'||
   createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex')!==pin.publicKeySha256)
  throw Error('Unmatched or non-Ed25519 witness pin');
 return k;
}
function verifyDetached(sig,bytes,pin){
 exact(sig,SIG_FIELDS);
 ref(sig.reviewerRef);ref(sig.keyId);
 if(typeof sig.signatureBase64!=='string'||!B64.test(sig.signatureBase64)||
   Buffer.from(sig.signatureBase64,'base64').toString('base64')!==sig.signatureBase64)
  throw Error('Invalid canonical Ed25519 signature');
 return sig.reviewerRef===pin.reviewerRef&&sig.keyId===pin.keyId&&
  cryptoVerify(null,bytes,publicKey(pin),Buffer.from(sig.signatureBase64,'base64'));
}
export function assessPhase1AyArchiveWitnesses({
 logRef=null,checkpointReceiptSha256=null,archiveObjectSha256=null,
 anchors=[],pins=[],minimumWitnesses=2,now=new Date()
}={}){
 const time=evaluation(now), blockers=new Set(HOLD),groups=new Map();
 if(!Array.isArray(anchors)||anchors.length>32||!Array.isArray(pins)||pins.length>16||
   !Number.isSafeInteger(minimumWitnesses)||minimumWitnesses<2||minimumWitnesses>16)
  throw Error('Invalid anchor/witness limit');
 if(logRef===null||checkpointReceiptSha256===null||archiveObjectSha256===null||
   anchors.length===0) return Object.freeze({phase:'1AY',validProofs:0,
    independentlyAuthenticatedWitnesses:false,immutableExternalArchiveVerified:false,
    incidentQuarantineRequired:true,productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
    blockerCodes:Object.freeze([...blockers,'MISSING_ANCHOR_EVIDENCE'].sort())});
 ref(logRef);sha(checkpointReceiptSha256);sha(archiveObjectSha256);
 const keys=new Map(),authorities=new Set();
 for(const pin of pins){
  publicKey(pin);
  if(pin.role!=='WITNESS')throw Error('Witness role required');
  if(keys.has(pin.keyId))throw Error('Duplicate witness key');
  keys.set(pin.keyId,pin);
 }
 let valid=0;
 for(const entry of anchors){
  exact(entry,ENTRY_FIELDS);
  phase1AyAnchorSigningBytes(entry.body);
  const body=entry.body;
  if(body.logRef!==logRef||body.checkpointReceiptSha256!==checkpointReceiptSha256||
     body.archiveObjectSha256!==archiveObjectSha256){
   blockers.add('ANCHOR_SCOPE_OR_DIGEST_MISMATCH');continue;
  }
  if(utc(body.issuedAt)>time+300000||utc(body.expiresAt)<=time){
   blockers.add('ANCHOR_EXPIRED_OR_FUTURE');continue;
  }
  const pin=keys.get(entry.signature?.keyId);
  if(!pin){blockers.add('UNKNOWN_WITNESS_KEY');continue;}
  if(!verifyDetached(entry.signature,phase1AyAnchorSigningBytes(body),pin)){
   blockers.add('INVALID_ANCHOR_SIGNATURE');continue;
  }
  if(!phase1AyVerifyInclusion(body,entry.inclusionProofSha256)){
   blockers.add('INVALID_MERKLE_INCLUSION');continue;
  }
  valid++;
  // A valid fixture pin never establishes independent administrative control.
  if(authorities.has(pin.authorityRef))blockers.add('REUSED_WITNESS_AUTHORITY');
  authorities.add(pin.authorityRef);
  const previous=groups.get(pin.authorityRef+'|'+body.treeSize);
  if(previous&&previous!==body.rootSha256)blockers.add('WITNESS_TREE_EQUIVOCATION');
  groups.set(pin.authorityRef+'|'+body.treeSize,body.rootSha256);
 }
 if(valid!==anchors.length)blockers.add('INCOMPLETE_ANCHOR_VALIDATION');
 if(authorities.size<minimumWitnesses)blockers.add('WITNESS_QUORUM_UNAVAILABLE');
 const critical=[...blockers].some(x=>!HOLD.includes(x));
 return Object.freeze({phase:'1AY',validProofs:valid,distinctClaimedWitnessAuthorities:authorities.size,
  cryptographicallyConsistent:!critical,independentlyAuthenticatedWitnesses:false,
  immutableExternalArchiveVerified:false,incidentQuarantineRequired:critical,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
}
export function phase1AyRecoverySigningBytes(body){
 exact(body,RECOVERY_FIELDS);
 if(body.schemaVersion!==1||body.purpose!==RECOVERY_PURPOSE||body.releaseDecision!=='HOLD'||
   body.outboundHeld!==true)throw Error('Recovery must keep dispatch and release held');
 ref(body.incidentRef);
 for(const field of ['checkpointReceiptSha256','restoredCheckpointReceiptSha256',
  'backupManifestSha256','restoredManifestSha256','revocationSnapshotSha256'])sha(body[field]);
 const start=utc(body.startedAt),end=utc(body.completedAt);
 if(start>=end||end-start>7*86400000)throw Error('Invalid rehearsal chronology');
 for(const k of ['measuredRpoMs','rtoTargetMs','rpoTargetMs'])
  if(!Number.isSafeInteger(body[k])||body[k]<0||body[k]>7*86400000)throw Error('Invalid RTO/RPO measurements');
 return Buffer.from('AADITECH-PHASE-1AY-DR-REHEARSAL-V1\0'+
  JSON.stringify(RECOVERY_FIELDS.map(k=>body[k])),'utf8');
}
export function assessPhase1AyRecovery({
 rehearsal=null,signatures=[],pins=[],now=new Date()
}={}){
 const nowMs=evaluation(now),blockers=new Set(['EXTERNAL_DR_EVIDENCE_AND_SIGNOFF_PENDING']);
 if(rehearsal===null) return Object.freeze({phase:'1AY',
  internalRehearsalCryptographicallyConsistent:false,realEncryptedRestoreVerified:false,
  independentRecoverySignoffVerified:false,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD',blockerCodes:Object.freeze([...blockers,'NO_REHEARSAL_EVIDENCE'].sort())});
 const msg=phase1AyRecoverySigningBytes(rehearsal);
 if(utc(rehearsal.completedAt)>nowMs+300000)blockers.add('FUTURE_RESTORE');
 if(rehearsal.checkpointReceiptSha256!==rehearsal.restoredCheckpointReceiptSha256||
    rehearsal.backupManifestSha256!==rehearsal.restoredManifestSha256)
  blockers.add('RESTORED_EVIDENCE_MISMATCH');
 if(utc(rehearsal.completedAt)-utc(rehearsal.startedAt)>rehearsal.rtoTargetMs||
    rehearsal.measuredRpoMs>rehearsal.rpoTargetMs)
  blockers.add('RECOVERY_TARGET_EXCEEDED');
 if(!Array.isArray(signatures)||signatures.length!==3||!Array.isArray(pins)||pins.length!==3)
  blockers.add('MISSING_SEPARATE_RECOVERY_SIGNERS');
 else{
  const roles=['SECURITY','OPERATIONS','OWNER'],authority=new Set();
  for(let i=0;i<3;i++){
   const p=pins[i],s=signatures[i];publicKey(p);
   if(p.role!==roles[i])blockers.add('RECOVERY_ROLE_MISMATCH');
   if(authority.has(p.authorityRef))blockers.add('RECOVERY_APPROVER_COLLISION');
   authority.add(p.authorityRef);
   if(!verifyDetached(s,msg,p))blockers.add('RECOVERY_SIGNATURE_INVALID');
  }
 }
 const local=[...blockers].every(x=>x==='EXTERNAL_DR_EVIDENCE_AND_SIGNOFF_PENDING');
 return Object.freeze({phase:'1AY',internalRehearsalCryptographicallyConsistent:local,
  realEncryptedRestoreVerified:false,independentRecoverySignoffVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
}
