import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {V2_ROLES} from './phase1dr-offline-keyid-bound-witness-v2.mjs';

// Phase 1DS: candidate-only cross-signed handover, NEVER a key-enrollment API.
export const ROTATION_DOMAIN='aaditech/phase1ds/cross-signed-witness-rotation/v1/';
export const ROTATION_STEPS=Object.freeze(['previous','next']);
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/,SIG=/^[A-Za-z0-9+/]{86}==$/;
const MF=['schemaVersion','kind','repository','organizationId',
 'sourceHeadSha','mainBaseSha','previousSequence','nextSequence',
 'previousCheckpointSha256','nextCandidateCheckpointSha256',
 'rotationNonce','reason','issuedAt','expiresAt','decision'];
const EXPECT=['organizationId','sourceHeadSha','mainBaseSha',
 'previousSequence','previousCheckpointSha256',
 'nextCandidateCheckpointSha256'];
const IDENTITY=['keyId','spkiSha256'],PAIR=ROTATION_STEPS,
 ATTEST=['publicKeyPem','signature'];
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const hex=x=>createHash('sha256').update(x).digest('hex');
const wellIdentity=x=>exact(x,IDENTITY)&&
 typeof x.keyId==='string'&&ID.test(x.keyId)&&
 typeof x.spkiSha256==='string'&&HASH.test(x.spkiSha256);
const wellIdentitySet=x=>exact(x,V2_ROLES)&&V2_ROLES.every(role=>
 exact(x[role],PAIR)&&PAIR.every(step=>wellIdentity(x[role][step])));
const bounded=(x,max)=>{try{
 const s=JSON.stringify(x);return typeof s==='string'&&
 Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}};
function utc(t){
 if(typeof t!=='string'||
  !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(t))return NaN;
 const n=Date.parse(t);
 return Number.isFinite(n)&&new Date(n).toISOString()===t?n:NaN;
}
function detachedPinsValid(pins){
 if(!exact(pins,V2_ROLES)||!V2_ROLES.every(role=>
  wellIdentity(pins[role])))return false;
 return pins.LEGAL_WITNESS.keyId!==pins.REGISTRY_WITNESS.keyId&&
 pins.LEGAL_WITNESS.spkiSha256!==pins.REGISTRY_WITNESS.spkiSha256;
}
/** Each of the four parties attests the SAME two-role transition. */
export function rotationSigningBytes(role,step,manifest,identities){
 if(!V2_ROLES.includes(role)||!ROTATION_STEPS.includes(step)||
  !exact(manifest,MF)||manifest.schemaVersion!==1||
  !wellIdentitySet(identities)||!bounded(manifest,8192))
  throw Error('DS_INVALID_SIGNING_SCOPE');
 return Buffer.from(ROTATION_DOMAIN+'attest/'+role+'/'+step+'\n'+
  canonical({schemaVersion:1,role,step,manifest,identities}),'utf8');
}
/** Only verified signature bytes are hashed; untrusted PEM formatting is not an identity. */
export function rotationDigest(manifest,identities,attestations){
 if(!exact(manifest,MF)||!wellIdentitySet(identities)||
  !exact(attestations,V2_ROLES)||!V2_ROLES.every(role=>
   exact(attestations[role],PAIR)&&PAIR.every(step=>
    exact(attestations[role][step],ATTEST))))
  throw Error('DS_INVALID_DIGEST_SCOPE');
 const signatures=V2_ROLES.flatMap(role=>ROTATION_STEPS.map(step=>({
  role,step,signature:attestations[role][step].signature
 })));
 return hex(Buffer.from(ROTATION_DOMAIN+'transition\n'+
  canonical({manifest,identities,signatures}),'utf8'));
}
function verifyAttestation(role,step,manifest,identities,attestation){
 try{
  if(!exact(attestation,ATTEST)||
   typeof attestation.publicKeyPem!=='string'||
   attestation.publicKeyPem.length>4096||
   typeof attestation.signature!=='string'||
   !SIG.test(attestation.signature))return false;
  const key=createPublicKey(attestation.publicKeyPem);
  const signature=Buffer.from(attestation.signature,'base64');
  if(key.asymmetricKeyType!=='ed25519'||signature.length!==64||
   signature.toString('base64')!==attestation.signature||
   hex(key.export({format:'der',type:'spki'}))!==
    identities[role][step].spkiSha256)return false;
  return verify(null,rotationSigningBytes(role,step,manifest,identities),
   key,signature);
 }catch{return false;}
}
function validContext(expected){
 return exact(expected,EXPECT)&&
  typeof expected.organizationId==='string'&&ID.test(expected.organizationId)&&
  typeof expected.sourceHeadSha==='string'&&SHA.test(expected.sourceHeadSha)&&
  typeof expected.mainBaseSha==='string'&&SHA.test(expected.mainBaseSha)&&
  Number.isSafeInteger(expected.previousSequence)&&
  expected.previousSequence>=0&&
  expected.previousSequence<Number.MAX_SAFE_INTEGER&&
  ['previousCheckpointSha256','nextCandidateCheckpointSha256']
   .every(k=>typeof expected[k]==='string'&&HASH.test(expected[k]))&&
  (expected.previousSequence!==0||
   expected.previousCheckpointSha256==='0'.repeat(64));
}
/**
 * Compare 2-8 offline packets against caller-supplied previous keys,
 * expected source/sequence and explicit time. None is externally authenticated.
 * Full four-signature mathematical success NEVER constitutes an authorized
 * rollover, approved incident recovery, independent observation or release.
 */
export function assessCrossSignedWitnessRolloverCandidate({
 candidates=null,expected=null,previousIdentityPins=null,now=null
}={}){
 const errors=new Set();
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('DS_EXPLICIT_CLOCK_REQUIRED');
 const context=validContext(expected);
 if(!context)errors.add('DS_EXPECTED_SOURCE_SEQUENCE_REQUIRED');
 const pins=detachedPinsValid(previousIdentityPins);
 if(!pins)errors.add('DS_PREVIOUS_IDENTITY_PINS_REQUIRED');
 const range=Array.isArray(candidates)&&candidates.length>=2&&
  candidates.length<=8;
 if(!range)errors.add('DS_TWO_TO_EIGHT_CANDIDATES_REQUIRED');
 const accepted=[];
 if(range)for(const packet of candidates){
  if(!exact(packet,['manifest','identities','attestations',
    'claimedTransitionSha256'])||!bounded(packet,32768)){
   errors.add('DS_PACKET_SCHEMA_OR_SIZE_INVALID');continue;
  }
  const {manifest:m,identities:i,attestations:a}=packet;
  const mf=exact(m,MF)&&m.schemaVersion===1&&
   m.kind==='UNTRUSTED_WITNESS_ROTATION_CANDIDATE'&&
   m.repository===REPO&&m.decision==='HOLD'&&
   typeof m.organizationId==='string'&&ID.test(m.organizationId)&&
   typeof m.rotationNonce==='string'&&HASH.test(m.rotationNonce)&&
   m.rotationNonce!=='0'.repeat(64)&&
   Number.isSafeInteger(m.previousSequence)&&
   Number.isSafeInteger(m.nextSequence)&&
   typeof m.previousCheckpointSha256==='string'&&
   HASH.test(m.previousCheckpointSha256)&&
   typeof m.nextCandidateCheckpointSha256==='string'&&
   HASH.test(m.nextCandidateCheckpointSha256)&&
   ['PLANNED_ROLLOVER','INCIDENT_RECOVERY'].includes(m.reason)&&
   bounded(m,8192);
  if(!(mf&&context&&
   m.organizationId===expected.organizationId&&
   m.sourceHeadSha===expected.sourceHeadSha&&
   m.mainBaseSha===expected.mainBaseSha&&
   m.previousSequence===expected.previousSequence&&
   m.nextSequence===expected.previousSequence+1&&
   m.previousCheckpointSha256===expected.previousCheckpointSha256&&
   m.nextCandidateCheckpointSha256===expected.nextCandidateCheckpointSha256)){
   errors.add('DS_SIGNED_SOURCE_OR_SEQUENCE_INVALID');continue;
  }
  const issued=utc(m.issuedAt),expiry=utc(m.expiresAt);
  if(!(Number.isFinite(clock)&&Number.isFinite(issued)&&
   Number.isFinite(expiry)&&issued>=clock-900000&&
   issued<=clock+300000&&expiry>clock&&
   expiry>issued&&expiry<=issued+900000)){
   errors.add('DS_EXPLICIT_TIME_OR_EXPIRY_INVALID');continue;
  }
  if(!wellIdentitySet(i)||!pins){
   errors.add('DS_IDENTITY_SET_OR_PREVIOUS_PINS_INVALID');continue;
  }
  const all=V2_ROLES.flatMap(role=>ROTATION_STEPS.map(step=>
   i[role][step]));
  const distinct= new Set(all.map(x=>x.keyId)).size===4&&
   new Set(all.map(x=>x.spkiSha256)).size===4;
  if(!distinct||!V2_ROLES.every(role=>
   i[role].previous.keyId===previousIdentityPins[role].keyId&&
   i[role].previous.spkiSha256===previousIdentityPins[role].spkiSha256)){
   errors.add('DS_KEY_REUSE_COLLISION_OR_UNPINNED_PREDECESSOR');continue;
  }
  if(!exact(a,V2_ROLES)||!V2_ROLES.every(role=>
   exact(a[role],PAIR)&&PAIR.every(step=>
    verifyAttestation(role,step,m,i,a[role][step])))){
   errors.add('DS_FOUR_ROLE_STEP_SIGNATURES_INVALID');continue;
  }
  let digest;
  try{digest=rotationDigest(m,i,a);}catch{
   errors.add('DS_TRANSITION_DIGEST_ENCODING_INVALID');continue;
  }
  if(typeof packet.claimedTransitionSha256!=='string'||
   !HASH.test(packet.claimedTransitionSha256)||
   packet.claimedTransitionSha256!==digest){
   errors.add('DS_CLAIMED_TRANSITION_DIGEST_INVALID');continue;
  }
  if(m.reason==='INCIDENT_RECOVERY')
   errors.add('DS_INCIDENT_RECOVERY_NEEDS_INDEPENDENT_AUTHORITY');
  accepted.push({digest,nonce:m.rotationNonce,reason:m.reason});
 }
 const unique=new Set(accepted.map(x=>x.digest)).size;
 const fork=unique>1;
 const nonceFork=fork&&new Set(accepted.map(x=>x.nonce)).size===1;
 if(fork)errors.add('DS_CROSS_SIGNED_TRANSITION_FORK_QUARANTINE');
 if(nonceFork)errors.add('DS_NONCE_REUSE_ACROSS_SIGNED_FORK');
 if(accepted.length>1&&unique===1)
  errors.add('DS_DUPLICATE_NOT_INDEPENDENT_PUBLICATION');
 if(range&&accepted.length!==candidates.length)
  errors.add('DS_INCOMPLETE_VALID_CANDIDATE_SET');
 return Object.freeze({
  phase:'1DS',schemaVersion:1,
  kind:'UNTRUSTED_CROSS_SIGNED_WITNESS_ROLLOVER_CANDIDATE_HARD_HOLD',
  repository:REPO,
  sourceHeadSha:context?expected.sourceHeadSha:null,
  mathematicallyVerifiedFourSignatureCandidatesOnly:accepted.length,
  distinctCrossSignedTransitionDigestsOnly:unique,
  candidateTransitionForkObservedOnly:fork,
  candidateNonceReuseForkObservedOnly:nonceFork,
  historicalV1AndV2SignaturesNeverMigrated:true,
  oldAndNewKeysDoNotBecomeExternallyAuthorized:true,
  nextV2CheckpointOrIndependentObserverVerified:false,
  previousPinsAndClockExternallyAuthenticated:false,
  incidentRecoveryMandateVerified:false,
  trustedRevocationOrRolloverRegistryVerified:false,
  originalOfficerSessionReverified:false,
  realMcaCcaEmudhraWormDrStagingVerified:false,
  noKeyEnrollmentOrProductionMutation:true,
  rawKeysNonceOrSignaturesExcludedFromOutput:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
