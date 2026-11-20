import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DOMAIN,WITNESS_ROLES,witnessSigningBytes}
 from './phase1do-offline-registrar-witness-enrollment.mjs';

// Phase 1DP: signed offline fork detector, not an externally published
// checkpoint. All inputs, witness pins and time may be applicant-controlled.
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/;
const ID=/^[a-z][a-z0-9._-]{5,79}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const M=['schemaVersion','kind','repository','organizationId',
 'sourceHeadSha','mainBaseSha','registrarSpkiSha256',
 'registryEvidenceSha256','appointmentDigestSha256','nonce',
 'sequence','previousCheckpointSha256','issuedAt','expiresAt','decision'];
const CTX=['organizationId','sourceHeadSha','mainBaseSha',
 'registrarSpkiSha256','registryEvidenceSha256','appointmentDigestSha256','nonce'];
const KEY=['keyId','publicKeyPem','spkiSha256','signature'];
const WITNESS_PINS=['legalWitnessSpkiSha256','registryWitnessSpkiSha256'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,names)=>OWN(x)&&Object.keys(x).length===names.length&&
 names.every(k=>Object.hasOwn(x,k));
const digest=b=>createHash('sha256').update(b).digest('hex');
function utc(x){
 if(typeof x!=='string'||
  !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function validKey(k){
 if(!EXACT(k,KEY)||!ID.test(k.keyId??'')||
  !HASH.test(k.spkiSha256??'')||
  typeof k.publicKeyPem!=='string'||k.publicKeyPem.length>4096||
  !SIG.test(k.signature??''))return false;
 try{
  const pub=createPublicKey(k.publicKeyPem),sig=Buffer.from(k.signature,'base64');
  return pub.asymmetricKeyType==='ed25519'&&
   digest(pub.export({format:'der',type:'spki'}))===k.spkiSha256&&
   sig.length===64&&sig.toString('base64')===k.signature;
 }catch{return false;}
}
function signed(role,k,m){
 try{
  return verify(null,witnessSigningBytes(role,m),
   createPublicKey(k.publicKeyPem),Buffer.from(k.signature,'base64'));
 }catch{return false;}
}
function checkpoint(m,w){
 return digest(Buffer.from(DOMAIN+'checkpoint/v1\n'+canonical({
  manifest:m,signatures:WITNESS_ROLES.map(role=>
   [role,w[role].keyId,w[role].signature])
 }),'utf8'));
}
function bounded(o){
 try{const s=JSON.stringify(o);
  return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=24576;
 }catch{return false;}
}
/**
 * Requires 2-8 fully signed candidate observations at the SAME next
 * sequence. A different signed head is equivocation; a copied head
 * is not independently witnessed. No live external source is read.
 */
export function assessRegistrarWitnessEquivocationCandidate({
 observations=null,comparisonPins=null,witnessPins=null,
 previousCheckpoint=null,now=null
}={}){
 const errors=new Set();
 const add=(ok,code)=>{if(!ok)errors.add(code);};
 const clock=utc(now);
 add(Number.isFinite(clock),'DP_EXPLICIT_VERIFICATION_CLOCK_REQUIRED');
 const context=EXACT(comparisonPins,CTX)&&
  ID.test(comparisonPins.organizationId??'')&&
  SHA.test(comparisonPins.sourceHeadSha??'')&&
  SHA.test(comparisonPins.mainBaseSha??'')&&
  ['registrarSpkiSha256','registryEvidenceSha256',
   'appointmentDigestSha256','nonce']
    .every(k=>HASH.test(comparisonPins[k]??''))&&
  comparisonPins.nonce!=='0'.repeat(64);
 add(context,'DP_EXACT_SOURCE_AND_REGISTRAR_PINS_REQUIRED');
 const pins=EXACT(witnessPins,WITNESS_PINS)&&
  WITNESS_PINS.every(k=>HASH.test(witnessPins[k]??''))&&
  witnessPins.legalWitnessSpkiSha256!==witnessPins.registryWitnessSpkiSha256&&
  witnessPins.legalWitnessSpkiSha256!==comparisonPins?.registrarSpkiSha256&&
  witnessPins.registryWitnessSpkiSha256!==comparisonPins?.registrarSpkiSha256;
 add(pins,'DP_TWO_SEPARATE_WITNESS_PINS_REQUIRED');
 const prev=EXACT(previousCheckpoint,['sequence','checkpointSha256'])&&
  Number.isSafeInteger(previousCheckpoint.sequence)&&
  previousCheckpoint.sequence>=0&&
  previousCheckpoint.sequence<Number.MAX_SAFE_INTEGER&&
  HASH.test(previousCheckpoint.checkpointSha256??'')&&
  (previousCheckpoint.sequence!==0||
   previousCheckpoint.checkpointSha256==='0'.repeat(64));
 add(prev,'DP_PREVIOUS_CHECKPOINT_INVALID');
 const array=Array.isArray(observations)&&observations.length>=2&&
  observations.length<=8;
 add(array,'DP_TWO_TO_EIGHT_OBSERVATIONS_REQUIRED');
 const heads=[];
 if(array)for(const o of observations){
  if(!EXACT(o,['manifest','witnesses','claimedCheckpointSha256'])||
     !bounded(o)){
   errors.add('DP_OBSERVATION_SCHEMA_OR_SIZE_INVALID');continue;
  }
  const m=o.manifest,w=o.witnesses;
  const schema=EXACT(m,M)&&m.schemaVersion===1&&
   m.kind==='UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE'&&
   m.repository===REPO&&m.decision==='HOLD'&&
   ID.test(m.organizationId??'')&&
   SHA.test(m.sourceHeadSha??'')&&SHA.test(m.mainBaseSha??'')&&
   ['registrarSpkiSha256','registryEvidenceSha256',
    'appointmentDigestSha256','nonce','previousCheckpointSha256']
    .every(k=>HASH.test(m[k]??''))&&
   Number.isSafeInteger(m.sequence)&&m.sequence>0;
  if(!(schema&&context&&prev&&
    CTX.every(k=>m[k]===comparisonPins[k])&&
    m.sequence===previousCheckpoint.sequence+1&&
    m.previousCheckpointSha256===previousCheckpoint.checkpointSha256)){
   errors.add('DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');continue;
  }
  const issued=utc(m.issuedAt),expiry=utc(m.expiresAt);
  if(!(Number.isFinite(clock)&&Number.isFinite(issued)&&
   Number.isFinite(expiry)&&issued>=clock-900000&&
   issued<=clock+300000&&expiry>clock&&expiry>issued&&
   expiry<=issued+900000)){
   errors.add('DP_EXPLICIT_CLOCK_WITNESS_EXPIRY_INVALID');continue;
  }
  const keys=EXACT(w,WITNESS_ROLES)&&
   WITNESS_ROLES.every(role=>validKey(w[role]))&&
   w.LEGAL_WITNESS.keyId!==w.REGISTRY_WITNESS.keyId&&
   w.LEGAL_WITNESS.spkiSha256===witnessPins?.legalWitnessSpkiSha256&&
   w.REGISTRY_WITNESS.spkiSha256===witnessPins?.registryWitnessSpkiSha256&&
   w.LEGAL_WITNESS.spkiSha256!==m.registrarSpkiSha256&&
   w.REGISTRY_WITNESS.spkiSha256!==m.registrarSpkiSha256;
  if(!(keys&&pins)){
   errors.add('DP_TWO_DISTINCT_PINNED_WITNESS_KEYS_INVALID');continue;
  }
  if(!WITNESS_ROLES.every(role=>signed(role,w[role],m))){
   errors.add('DP_INVALID_SIGNED_WITNESS_OBSERVATION');continue;
  }
  const h=checkpoint(m,w);
  if(!HASH.test(o.claimedCheckpointSha256??'')||
     o.claimedCheckpointSha256!==h){
   errors.add('DP_CLAIMED_CHECKPOINT_DIGEST_MISMATCH');continue;
  }
  heads.push(h);
 }
 const fork=new Set(heads).size>1;
 if(fork)errors.add('DP_DUAL_SIGNED_SAME_SEQUENCE_EQUIVOCATION');
 if(heads.length>1&&!fork)
  errors.add('DP_DUPLICATE_RECEIPT_NOT_INDEPENDENT_PUBLICATION');
 if(array&&heads.length!==observations.length)
  errors.add('DP_INCOMPLETE_VALID_OBSERVATION_QUORUM');
 return Object.freeze({
  phase:'1DP',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_REGISTRAR_WITNESS_EQUIVOCATION_QUARANTINE',
  repository:REPO,
  checkedSourceHeadSha:context?comparisonPins.sourceHeadSha:null,
  verifiedDualSignedPacketsMathematicallyOnly:heads.length,
  distinctNextCheckpointDigestsOnly:new Set(heads).size,
  sameSequenceConflictingDualSignedHeadsObservedOnly:fork,
  duplicateCopiesCannotProveIndependentPublication:true,
  suppliedObserverOriginsAuthenticated:false,
  suppliedClockAndPreviousHeadExternallyAuthenticated:false,
  externalAtomicCasOrImmutableWormContinuityVerified:false,
  actualLegalMcaAndProviderAuthorityVerified:false,
  independentSecurityBusinessOfficerAndGithubApprovalsVerified:false,
  productionChangeOrReviewerRequestPossible:false,
  rawManifestNonceKeyPemsAndWitnessSignaturesExcluded:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
