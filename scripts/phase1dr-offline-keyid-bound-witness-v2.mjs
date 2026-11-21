import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';

// Phase 1DR: versioned v2 candidate-only witness signing contract.
// The historic v1 signing bytes are immutable and remain untrusted.
export const V2_ROLES=Object.freeze(['LEGAL_WITNESS','REGISTRY_WITNESS']);
export const V2_DOMAIN='aaditech/phase1dr/key-id-bound-registrar-witness/v2/';
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/,SIG=/^[A-Za-z0-9+/]{86}==$/;
const M=['schemaVersion','kind','repository','organizationId',
 'sourceHeadSha','mainBaseSha','registrarSpkiSha256',
 'registryEvidenceSha256','appointmentDigestSha256','nonce',
 'sequence','previousCheckpointSha256','issuedAt','expiresAt','decision'];
const CTX=['organizationId','sourceHeadSha','mainBaseSha',
 'registrarSpkiSha256','registryEvidenceSha256','appointmentDigestSha256','nonce'];
const KEY=['keyId','publicKeyPem','spkiSha256','signature'];
const IDENT=['keyId','spkiSha256'];
const PINS=['legalWitnessSpkiSha256','registryWitnessSpkiSha256'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const digest=x=>createHash('sha256').update(x).digest('hex');
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function bounded(x,limit){
 try{const json=JSON.stringify(x);
  return typeof json==='string'&&Buffer.byteLength(json,'utf8')<=limit;
 }catch{return false;}
}
function validKey(k){
 if(!EXACT(k,KEY)||!ID.test(k.keyId??'')||
  !HASH.test(k.spkiSha256??'')||!SIG.test(k.signature??'')||
  typeof k.publicKeyPem!=='string'||k.publicKeyPem.length>4096)
  return false;
 try{
  const pub=createPublicKey(k.publicKeyPem);
  const sig=Buffer.from(k.signature,'base64');
  return pub.asymmetricKeyType==='ed25519'&&
   digest(pub.export({format:'der',type:'spki'}))===k.spkiSha256&&
   sig.length===64&&sig.toString('base64')===k.signature;
 }catch{return false;}
}
/** Both witness identity fields are inside EACH role-separated v2 signature. */
export function witnessSigningBytesV2(role,manifest,identity){
 if(!V2_ROLES.includes(role)||!EXACT(identity,IDENT)||
  !ID.test(identity.keyId??'')||!HASH.test(identity.spkiSha256??'')||
  !OWN(manifest)||manifest.schemaVersion!==2||!bounded(manifest,8192))
  throw Error('DR_INVALID_VERSIONED_SIGNING_ENVELOPE');
 return Buffer.from(V2_DOMAIN+'witness/'+role+'\n'+canonical({
  schemaVersion:2,role,keyId:identity.keyId,
  spkiSha256:identity.spkiSha256,manifest
 }),'utf8');
}
function verifyWitness(role,k,m){
 try{
  return verify(null,witnessSigningBytesV2(role,m,{
   keyId:k.keyId,spkiSha256:k.spkiSha256
  }),createPublicKey(k.publicKeyPem),Buffer.from(k.signature,'base64'));
 }catch{return false;}
}
export function checkpointDigestV2(m,w){
 if(!EXACT(w,V2_ROLES)||!OWN(m)||m.schemaVersion!==2)
  throw Error('DR_INVALID_CHECKPOINT_ENVELOPE');
 return digest(Buffer.from(V2_DOMAIN+'checkpoint\n'+canonical({
  schemaVersion:2,manifest:m,witnesses:V2_ROLES.map(role=>({
   role,keyId:w[role].keyId,spkiSha256:w[role].spkiSha256,
   signature:w[role].signature
  }))
 }),'utf8'));
}
/**
 * Offline dual-signed observations (2-8). Caller-supplied pins, clock,
 * preceding digest and observation origins are NOT authenticated.
 * This does NOT enroll a key, validate real issuer provenance or write state.
 */
export function assessKeyIdBoundWitnessV2Candidate({
 observations=null,comparisonPins=null,witnessPins=null,
 previousCheckpoint=null,now=null
}={}){
 const errors=new Set(),add=(ok,code)=>{if(!ok)errors.add(code);};
 const clock=utc(now);
 add(Number.isFinite(clock),'DR_EXPLICIT_CLOCK_REQUIRED');
 const context=EXACT(comparisonPins,CTX)&&
  ID.test(comparisonPins.organizationId??'')&&
  SHA.test(comparisonPins.sourceHeadSha??'')&&
  SHA.test(comparisonPins.mainBaseSha??'')&&
  ['registrarSpkiSha256','registryEvidenceSha256',
   'appointmentDigestSha256','nonce']
   .every(k=>HASH.test(comparisonPins[k]??''))&&
  comparisonPins.nonce!=='0'.repeat(64);
 add(context,'DR_EXACT_SOURCE_AND_ORGANIZATION_PINS_REQUIRED');
 const pins=EXACT(witnessPins,PINS)&&
  PINS.every(k=>HASH.test(witnessPins[k]??''))&&
  witnessPins.legalWitnessSpkiSha256!==witnessPins.registryWitnessSpkiSha256&&
  witnessPins.legalWitnessSpkiSha256!==comparisonPins?.registrarSpkiSha256&&
  witnessPins.registryWitnessSpkiSha256!==comparisonPins?.registrarSpkiSha256;
 add(pins,'DR_TWO_DISTINCT_WITNESS_PINS_REQUIRED');
 const prev=EXACT(previousCheckpoint,['sequence','checkpointSha256'])&&
  Number.isSafeInteger(previousCheckpoint.sequence)&&
  previousCheckpoint.sequence>=0&&
  previousCheckpoint.sequence<Number.MAX_SAFE_INTEGER&&
  HASH.test(previousCheckpoint.checkpointSha256??'')&&
  (previousCheckpoint.sequence!==0||
   previousCheckpoint.checkpointSha256==='0'.repeat(64));
 add(prev,'DR_PREVIOUS_CHECKPOINT_INVALID');
 const array=Array.isArray(observations)&&
  observations.length>=2&&observations.length<=8;
 add(array,'DR_TWO_TO_EIGHT_OBSERVATIONS_REQUIRED');
 const checkpoints=[],manifestHashes=[],identityHashes=[];
 if(array)for(const o of observations){
  if(!EXACT(o,['manifest','witnesses','claimedCheckpointSha256'])||
   !bounded(o,24576)){
   errors.add('DR_OBSERVATION_SCHEMA_OR_SIZE_INVALID');continue;
  }
  const m=o.manifest,w=o.witnesses;
  const schema=EXACT(m,M)&&m.schemaVersion===2&&
   m.kind==='UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE_V2'&&
   m.repository===REPO&&m.decision==='HOLD'&&
   ID.test(m.organizationId??'')&&
   SHA.test(m.sourceHeadSha??'')&&SHA.test(m.mainBaseSha??'')&&
   ['registrarSpkiSha256','registryEvidenceSha256',
    'appointmentDigestSha256','nonce','previousCheckpointSha256']
    .every(k=>HASH.test(m[k]??''))&&m.nonce!=='0'.repeat(64)&&
   Number.isSafeInteger(m.sequence)&&m.sequence>0&&bounded(m,8192);
  if(!(schema&&context&&prev&&
   CTX.every(k=>m[k]===comparisonPins[k])&&
   m.sequence===previousCheckpoint.sequence+1&&
   m.previousCheckpointSha256===previousCheckpoint.checkpointSha256)){
   errors.add('DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');continue;
  }
  const issued=utc(m.issuedAt),expires=utc(m.expiresAt);
  if(!(Number.isFinite(clock)&&Number.isFinite(issued)&&
   Number.isFinite(expires)&&issued>=clock-900000&&
   issued<=clock+300000&&expires>clock&&expires>issued&&
   expires<=issued+900000)){
   errors.add('DR_EXPLICIT_CLOCK_OR_EXPIRY_INVALID');continue;
  }
  const keys=EXACT(w,V2_ROLES)&&
   V2_ROLES.every(role=>validKey(w[role]))&&
   w.LEGAL_WITNESS.keyId!==w.REGISTRY_WITNESS.keyId&&
   w.LEGAL_WITNESS.spkiSha256===witnessPins?.legalWitnessSpkiSha256&&
   w.REGISTRY_WITNESS.spkiSha256===witnessPins?.registryWitnessSpkiSha256&&
   w.LEGAL_WITNESS.spkiSha256!==m.registrarSpkiSha256&&
   w.REGISTRY_WITNESS.spkiSha256!==m.registrarSpkiSha256;
  if(!(keys&&pins)){
   errors.add('DR_WITNESS_KEY_ROLE_OR_PIN_INVALID');continue;
  }
  if(!V2_ROLES.every(role=>verifyWitness(role,w[role],m))){
   errors.add('DR_V2_SIGNED_IDENTITY_OR_MANIFEST_INVALID');continue;
  }
  let h;
  try{h=checkpointDigestV2(m,w);}catch{
   errors.add('DR_CHECKPOINT_ENCODING_INVALID');continue;
  }
  if(!HASH.test(o.claimedCheckpointSha256??'')||
    o.claimedCheckpointSha256!==h){
   errors.add('DR_CHECKPOINT_CLAIM_MISMATCH');continue;
  }
  checkpoints.push(h);
  manifestHashes.push(digest(Buffer.from(
   V2_DOMAIN+'manifest\n'+canonical(m),'utf8')));
  identityHashes.push(digest(Buffer.from(
   V2_DOMAIN+'signed-identities\n'+canonical(V2_ROLES.map(role=>({
    role,keyId:w[role].keyId,spkiSha256:w[role].spkiSha256
   }))),'utf8')));
 }
 const manifestFork=new Set(manifestHashes).size>1;
 const signedIdentityFork=new Set(identityHashes).size>1;
 const duplicate=checkpoints.length>1&&new Set(checkpoints).size===1;
 if(manifestFork)errors.add('DR_DUAL_SIGNED_MANIFEST_FORK_QUARANTINE');
 if(signedIdentityFork)errors.add('DR_SIGNED_WITNESS_IDENTITY_FORK_QUARANTINE');
 if(duplicate)errors.add('DR_DUPLICATE_IS_NOT_INDEPENDENT_PUBLICATION');
 if(array&&checkpoints.length!==observations.length)
  errors.add('DR_INCOMPLETE_VALID_OBSERVATION_QUORUM');
 return Object.freeze({
  phase:'1DR',schemaVersion:2,
  kind:'UNTRUSTED_KEYID_BOUND_DUAL_WITNESS_V2_CANDIDATE_HARD_HOLD',
  repository:REPO,
  checkedSourceHeadSha:context?comparisonPins.sourceHeadSha:null,
  verifiedV2DualSignedPacketsMathematicallyOnly:checkpoints.length,
  distinctSignedManifestDigestsOnly:new Set(manifestHashes).size,
  distinctSignedWitnessIdentityDigestsOnly:new Set(identityHashes).size,
  distinctV2CheckpointDigestsOnly:new Set(checkpoints).size,
  witnessKeyIdAndSpkiBoundByRoleSignatureV2Only:true,
  signedManifestForkObservedOnly:manifestFork,
  signedWitnessIdentityForkObservedOnly:signedIdentityFork,
  legacyV1SignaturesNotReinterpretedOrMigrated:true,
  duplicateReceiptsCannotProveIndependentPublication:true,
  previousCheckpointAndClockExternallyAuthenticated:false,
  independentWitnessKeyRegistryAndLegalMandatesAuthenticated:false,
  originalInMemoryOfficerGithubSessionReverified:false,
  externalWormCasRevocationMcaCcaProviderOrStagingVerified:false,
  productionOrReviewerStateChangesPossible:false,
  rawNoncePemSignaturesAndKeyIdExcludedFromOutput:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
