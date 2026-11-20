import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {candidateSigningBytes}
 from './phase1dm-corporate-appointment-challenge-handoff.mjs';
import {assessInProcessAppointmentReviewerBinding}
 from './phase1dn-corporate-role-session-reconciliation.mjs';

// Phase 1DO: TWO-CANDIDATE-WITNESS, SEQUENCE-BOUND OFFLINE ROOT
// ENROLLMENT CONTRACT. Pinned witnesses, prior checkpoint and legal
// registry can be supplied by an attacker. None is independently
// authenticated here; all results stay production HARD HOLD.
export const WITNESS_ROLES=Object.freeze(['LEGAL_WITNESS','REGISTRY_WITNESS']);
export const DOMAIN='aaditech/phase1do/offline-registrar-enrollment/v1/';
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/,
 SIGNATURE=/^[A-Za-z0-9+/]{86}==$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/;
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const HE={productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'};
const M=['schemaVersion','kind','repository','organizationId','sourceHeadSha',
 'mainBaseSha','registrarSpkiSha256','registryEvidenceSha256',
 'appointmentDigestSha256','nonce','sequence','previousCheckpointSha256',
 'issuedAt','expiresAt','decision'];
const W=['keyId','publicKeyPem','spkiSha256','signature'];
const P=['legalWitnessSpkiSha256','registryWitnessSpkiSha256',
 'expectedOrganizationId','previousCheckpointSha256'];
const Q=['sequence','checkpointSha256'];
const digest=x=>createHash('sha256').update(x).digest('hex');
const bytes=x=>Buffer.byteLength(JSON.stringify(x),'utf8');
function utc(s){
 if(typeof s!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s))return NaN;
 const n=Date.parse(s);
 return Number.isFinite(n)&&new Date(n).toISOString()===s?n:NaN;
}
function validEd25519(w){
 if(!EXACT(w,W)||!ID.test(w.keyId??'')||
  !HASH.test(w.spkiSha256??'')||
  typeof w.publicKeyPem!=='string'||w.publicKeyPem.length>4096)
  return false;
 try{
  const pub=createPublicKey(w.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   digest(pub.export({format:'der',type:'spki'}))===w.spkiSha256;
 }catch{return false;}
}
export function witnessSigningBytes(role,manifest){
 if(!WITNESS_ROLES.includes(role)||!OWN(manifest)||
  bytes(manifest)>8192)
  throw Error('DO_UNBOUNDED_OR_INVALID_WITNESS_CLAIM');
 return Buffer.from(DOMAIN+role+'/v1\n'+canonical(manifest),'utf8');
}
function witnessValid(role,w,manifest){
 if(!validEd25519(w)||!SIGNATURE.test(w.signature??''))return false;
 try{
  const signature=Buffer.from(w.signature,'base64');
  return signature.length===64&&signature.toString('base64')===w.signature&&
   verify(null,witnessSigningBytes(role,manifest),
    createPublicKey(w.publicKeyPem),signature);
 }catch{return false;}
}
function result(errors,manifest,localJoin,verifiedCount,pinsMatch,sequenceMatched,checkpoint){
 const head=manifest?.sourceHeadSha,main=manifest?.mainBaseSha;
 const consistent=errors.size===0&&localJoin&&verifiedCount===2&&
  pinsMatch&&sequenceMatched&&HASH.test(checkpoint??'');
 return Object.freeze({
  phase:'1DO',schemaVersion:1,
  kind:'DUAL_UNTRUSTED_REGISTRAR_WITNESS_ENROLLMENT_CANDIDATE_HARD_HOLD',
  repository:REPO,checkedSourceHeadSha:SHA.test(head??'')?head:null,
  checkedBaseMainSha:SHA.test(main??'')?main:null,
  originalGithubNomineesToOfficerSignaturesRecheckedInProcessOnly:localJoin,
  localLegalAndRegistryWitnessSignaturesVerifiedOnly:verifiedCount,
  suppliedComparisonWitnessPinsMatchOnly:pinsMatch,
  callerSuppliedSequenceAndPriorCheckpointMatchOnly:sequenceMatched,
  unsignedNextEnrollmentCheckpointSha256:consistent?checkpoint:null,
  candidateRegistrarRootEnrollmentChainMathematicallyConsistentOnly:consistent,
  independentRootOrLegalRegistryChannelAuthenticated:false,
  independentlyAppointedSecurityBusinessOfficerMandatesVerified:false,
  externallyDurableAntiReplayCheckpointOrCasVerified:false,
  liveMcaLegalSignatoryOrRcaiCcaEmudhraTrustVerified:false,
  auditedRevocationWormDrOidcAndStagingSignoffsVerified:false,
  cannotVerifySourceIndependenceOrPromoteToProduction:true,
  operatorSessionKeysRawNamesWitnessPemsAndSignaturesExcludedFromOutput:true,
  canWriteMainRequestReviewsActivateProvidersOrDeploy:false,
  anomalyCodes:Object.freeze([...errors].sort()),...HE
 });
}
/**
 * Re-verifies original in-process 1DN operator session, not a forgeable
 * public status boolean. Two separately pinned untrusted witness keys
 * must sign the same source-bound registrar digest and previous anchor.
 *
 * No network/storage IO. Caller must provide explicit current time;
 * caller-supplied time is NOT authenticated trusted wall clock.
 */
export function assessRegistrarEnrollmentWitnessCandidate({
 candidatePacket=null,expectedExternalPins=null,operatorSession=null,
 manifest=null,witnesses=null,witnessComparisonPins=null,
 previousCheckpoint=null,now=null
}={}){
 const errors=new Set(),add=(ok,code)=>{if(!ok)errors.add(code);};
 let manifestBytes=Infinity;
 try{manifestBytes=bytes(manifest);}catch{}
 add(manifestBytes>=1&&manifestBytes<=8192,
  'DO_MALFORMED_OR_OVERSIZED_WITNESS_MANIFEST');
 const n=utc(now),issue=utc(manifest?.issuedAt),expiry=utc(manifest?.expiresAt);
 add(Number.isFinite(n),'DO_EXPLICIT_CURRENT_VERIFICATION_CLOCK_REQUIRED');
 add(Number.isFinite(issue)&&Number.isFinite(expiry)&&
  Number.isFinite(n)&&issue>=n-900000&&issue<=n+300000&&
  expiry>n&&expiry>issue&&expiry<=issue+900000,
  'DO_WITNESS_MANIFEST_STALE_FUTURE_OR_TOO_LONG');
 const app=candidatePacket?.appointment;
 const keys=witnesses;
 const schema=EXACT(manifest,M)&&manifest.schemaVersion===1&&
  manifest.kind==='UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE'&&
  manifest.repository===REPO&&ID.test(manifest.organizationId??'')&&
  SHA.test(manifest.sourceHeadSha??'')&&SHA.test(manifest.mainBaseSha??'')&&
  HASH.test(manifest.registrarSpkiSha256??'')&&
  HASH.test(manifest.registryEvidenceSha256??'')&&
  HASH.test(manifest.appointmentDigestSha256??'')&&
  HASH.test(manifest.nonce??'')&&manifest.nonce!=='0'.repeat(64)&&
  Number.isSafeInteger(manifest.sequence)&&manifest.sequence>0&&
  HASH.test(manifest.previousCheckpointSha256??'')&&
  manifest.decision==='HOLD';
 add(schema,'DO_REGISTRAR_ENROLLMENT_SCOPE_OR_MANIFEST_SCHEMA_INVALID');
 let appDigest=null;
 try{appDigest=digest(candidateSigningBytes('ROOT',app));}catch{}
 const appBound=app?.organizationId===manifest?.organizationId&&
  app?.sourceHeadSha===manifest?.sourceHeadSha&&
  app?.mainBaseSha===manifest?.mainBaseSha&&
  app?.registryEvidenceSha256===manifest?.registryEvidenceSha256&&
  app?.nonce===manifest?.nonce&&
  candidatePacket?.registrarKey?.spkiSha256===manifest?.registrarSpkiSha256&&
  appDigest!==null&&appDigest===manifest?.appointmentDigestSha256;
 add(appBound,'DO_REGISTRAR_OR_SOURCE_NOT_EQUAL_SIGNED_APPOINTMENT');
 const p=EXACT(witnessComparisonPins,P)&&
  HASH.test(witnessComparisonPins.legalWitnessSpkiSha256??'')&&
  HASH.test(witnessComparisonPins.registryWitnessSpkiSha256??'')&&
  ID.test(witnessComparisonPins.expectedOrganizationId??'')&&
  HASH.test(witnessComparisonPins.previousCheckpointSha256??'');
 const witnessSchema=EXACT(keys,WITNESS_ROLES)&&
  WITNESS_ROLES.every(role=>validEd25519(keys[role]));
 add(witnessSchema,'DO_TWO_DISTINCT_PINNED_ED25519_WITNESS_KEYS_REQUIRED');
 const pinsMatch=Boolean(p&&witnessSchema&&
  manifest?.organizationId===witnessComparisonPins.expectedOrganizationId&&
  keys.LEGAL_WITNESS.spkiSha256===witnessComparisonPins.legalWitnessSpkiSha256&&
  keys.REGISTRY_WITNESS.spkiSha256===witnessComparisonPins.registryWitnessSpkiSha256&&
  keys.LEGAL_WITNESS.spkiSha256!==keys.REGISTRY_WITNESS.spkiSha256&&
  keys.LEGAL_WITNESS.keyId!==keys.REGISTRY_WITNESS.keyId&&
  keys.LEGAL_WITNESS.spkiSha256!==manifest?.registrarSpkiSha256&&
  keys.REGISTRY_WITNESS.spkiSha256!==manifest?.registrarSpkiSha256);
 add(pinsMatch,'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
 const sequenceMatched=Boolean(EXACT(previousCheckpoint,Q)&&
  Number.isSafeInteger(previousCheckpoint.sequence)&&
  previousCheckpoint.sequence>=0&&
  previousCheckpoint.sequence<Number.MAX_SAFE_INTEGER&&
  HASH.test(previousCheckpoint.checkpointSha256??'')&&p&&
  previousCheckpoint.checkpointSha256===
   witnessComparisonPins.previousCheckpointSha256&&
  manifest?.sequence===previousCheckpoint.sequence+1&&
  manifest?.previousCheckpointSha256===previousCheckpoint.checkpointSha256&&
  (previousCheckpoint.sequence!==0||
   previousCheckpoint.checkpointSha256==='0'.repeat(64)));
 add(sequenceMatched,'DO_MONOTONIC_PREVIOUS_CHECKPOINT_NOT_OBSERVED');
 const candidate=assessInProcessAppointmentReviewerBinding({
  candidatePacket,expectedExternalPins,operatorSession,now
 });
 const localJoin=candidate.inProcessCrossPhaseCandidateContractConsistentOnly===true&&
  candidate.checkedSourceHeadSha===manifest?.sourceHeadSha&&
  candidate.checkedBaseMainSha===manifest?.mainBaseSha&&
  candidate.anomalyCodes.length===0&&
  candidate.productionReleaseAuthorized===false;
 add(localJoin,'DO_ORIGINAL_1DN_OFFICER_GITHUB_SESSION_NOT_VERIFIED');
 let verifiedCount=0;
 if(schema&&appBound&&pinsMatch&&sequenceMatched&&
    manifestBytes<=8192){
  for(const role of WITNESS_ROLES){
   if(witnessValid(role,keys[role],manifest))verifiedCount++;
   else errors.add('DO_'+role+'_SIGNED_WITNESS_CLAIM_INVALID');
  }
 }else errors.add('DO_WITNESS_SIGNATURES_NOT_VALIDATED_AGAINST_ALL_PINS_AND_SOURCE');
 let checkpoint=null;
 if(verifiedCount===2&&schema&&sequenceMatched&&pinsMatch){
  try{
   checkpoint=digest(Buffer.from(DOMAIN+'checkpoint/v1\n'+
    canonical({manifest,signatures:WITNESS_ROLES.map(role=>[
     role,keys[role].keyId,keys[role].signature
    ])}),'utf8'));
  }catch{}
 }
 return result(errors,manifest,localJoin,verifiedCount,pinsMatch,
  sequenceMatched,checkpoint);
}
