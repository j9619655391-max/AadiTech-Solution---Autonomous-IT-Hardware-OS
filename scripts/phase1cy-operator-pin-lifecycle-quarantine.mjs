import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,ROLES as SOURCE_ROLES,canonical,signingBytes,validateSourceSpec,
 assessCandidateRemoteQuorum
} from './phase1cx-pinned-external-source-highwatermark.mjs';

// Phase 1CY: OPERATOR-ONLY signed *candidate* onboarding and pin continuity.
// Actual external key appointments, endpoint ownership, real remote retrieval,
// immutable cross-run checkpoint, incident response, CA or corporate trust
// remain unauthenticated. No offline fixture may ever authorize release.
export const OFFICERS=Object.freeze(['SECURITY_OFFICER','BUSINESS_OFFICER']);
export const HISTORICAL_ROLES=Object.freeze(['WITNESS_A','WITNESS_B']);
export const DOMAIN='aaditech/phase1cy/readonly-operator-handoff/v1/';
const HEX=/^[a-f0-9]{64}$/,SHA=/^[a-f0-9]{40}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 LOGIN=/^[A-Za-z0-9_-]{3,39}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>own(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const dig=x=>createHash('sha256').update(x).digest('hex');
const epoch=x=>Number.isSafeInteger(x)&&x>=0;
const stamp=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const STMT=['schemaVersion','kind','repository','sourceHeadSha',
 'mainBaseSha','policyFingerprintSha256','cvCandidateSha256','nonce',
 'previousEpoch','previousCheckpointDigest','previousRevocationVersion',
 'previousRevocationDigest','nextEpoch','nextCheckpointDigest',
 'nextRevocationVersion','nextRevocationDigest','previousSourceDigest',
 'nextSourceDigest','issuedAt','expiresAt','decision'];
const PREV=['anchor','sources','officers'];
const OFFICER=['role','organizationId','githubLogin','mandateDigest',
 'keyId','publicKeyPem','spkiSha256','validFrom','validUntil','revoked'];
const SIGREC=['role','keyId','algorithm','signature'];
const CHANGE=['role','previousSignature','successorSignature'];
const PRIOR=['schemaVersion','role','repository','sourceHeadSha',
 'epoch','checkpointDigest','revocationVersion','revocationDigest',
 'challengeNonce','observedAt'];
const INCIDENT=['status','forkReports','recoveryRequested'];
export function candidateBytes(type,statement){
 if(!['handoff','rotation','historical-anchor'].includes(type)||
    !own(statement)||JSON.stringify(statement).length>8192)
  throw Error('CY_UNKNOWN_OR_OVERSIZE_OPERATOR_CANDIDATE');
 return Buffer.from(DOMAIN+type+'/v1\n'+canonical(statement),'utf8');
}
function signedBytes(type,role,statement){
 if(typeof role!=='string'||![...OFFICERS,...SOURCE_ROLES].includes(role))
  throw Error('CY_UNREVIEWED_SIGNER_ROLE');
 return Buffer.from(DOMAIN+type+'/'+role+'/v1\n'+canonical(statement),'utf8');
}
function verifySignature(type,role,statement,record,key){
 if(!exact(record,SIGREC)||record.role!==role||
    record.keyId!==key?.keyId||record.algorithm!=='Ed25519'||
    !SIG.test(record.signature??'')||!key||typeof key.publicKeyPem!=='string')
  return false;
 try{
  const raw=Buffer.from(record.signature,'base64');
  if(raw.length!==64||raw.toString('base64')!==record.signature)return false;
  const pub=createPublicKey(key.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   dig(pub.export({type:'spki',format:'der'}))===key.spkiSha256&&
   verify(null,signedBytes(type,role,statement),pub,raw);
 }catch{return false;}
}
const publicKeyValid=key=>{
 if(typeof key?.publicKeyPem!=='string'||key.publicKeyPem.length>4096||
    !HEX.test(key.spkiSha256??'')||!ID.test(key.keyId??''))return false;
 try{
  const pub=createPublicKey(key.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   dig(pub.export({type:'spki',format:'der'}))===key.spkiSha256;
 }catch{return false;}
};
const fresh=(start,end,now)=>{
 const a=stamp(start),b=stamp(end);
 return Number.isFinite(a)&&Number.isFinite(b)&&Number.isFinite(now)&&
  a>=now-900000&&a<=now+300000&&b>a&&b>now&&b-a<=900000;
};
function normalRoster(roster){
 if(!exact(roster,SOURCE_ROLES))return null;
 const copy={};
 for(const role of SOURCE_ROLES){
  if(!validateSourceSpec(roster[role],role))return null;
  copy[role]=roster[role];
 }
 return copy;
}
function validOfficer(key,role,now){
 return exact(key,OFFICER)&&key.role===role&&
  ID.test(key.organizationId??'')&&LOGIN.test(key.githubLogin??'')&&
  key.githubLogin.toLowerCase()!=='j9619655391-max'&&
  HEX.test(key.mandateDigest??'')&&key.revoked===false&&
  publicKeyValid(key)&&Number.isFinite(stamp(key.validFrom))&&
  Number.isFinite(stamp(key.validUntil))&&
  stamp(key.validFrom)<=now&&stamp(key.validUntil)>now;
}
export function assessOperatorPinLifecycle({
 manifest=null,observations={},previous=null,statement=null,
 officerSignatures=[],rotations=[],historicalWitnesses=[],
 incidents=null,now='2026-11-20T00:00:00.000Z'
}={}){
 const errors=new Set();
 const add=(ok,code)=>{if(!ok)errors.add(code);};
 let current;
 try{current=assessCandidateRemoteQuorum({manifest,observations,now});}
 catch{current=null;}
 add(current?.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent===true&&
     current?.productionReleaseAuthorized===false&&current?.releaseDecision==='HOLD',
  'CY_PRECEDING_REMOTE_CANDIDATE_QUORUM_MISSING');
 const priorOk=exact(previous,PREV);
 const priorRoster=normalRoster(previous?.sources);
 const currentRoster=normalRoster(manifest?.sources);
 add(priorOk&&priorRoster!==null&&currentRoster!==null,
  'CY_MISSING_OPERATOR_PREVIOUS_OR_CURRENT_SOURCE_ROSTER');
 const anchor=previous?.anchor,base=manifest?.previousAnchor;
 const oldAnchorOk=own(anchor)&&own(base)&&
  JSON.stringify(anchor)===JSON.stringify(base)&&
  epoch(anchor.epoch)&&epoch(anchor.revocationVersion)&&
  HEX.test(anchor.checkpointDigest??'')&&
  HEX.test(anchor.revocationDigest??'')&&
  Number.isFinite(stamp(anchor.observedAt));
 add(oldAnchorOk,'CY_PREVIOUS_ANCHOR_NOT_EXACTLY_CURRENT_SOURCE_PREDECESSOR');
 const time=stamp(now);
 add(Number.isFinite(time),'CY_INVALID_VERIFICATION_CLOCK');
 const rev=observations?.REVOCATION?.data?.statement;
 const nextCheckpoint=rev?.checkpointDigest;
 const nextRevocation=rev?.version;
 const nextRevocationDigest=rev&&own(rev)?
  (()=>{try{return dig(signingBytes('REVOCATION',rev));}catch{return null;}})():null;
 const prevHash=priorRoster?dig(canonical(priorRoster)):null;
 const nextHash=currentRoster?dig(canonical(currentRoster)):null;
 const statementOk=exact(statement,STMT)&&
  statement.schemaVersion===1&&statement.kind==='CANDIDATE_OPERATOR_PIN_HANDOFF_HOLD'&&
  statement.repository===REPO&&SHA.test(statement.sourceHeadSha??'')&&
  SHA.test(statement.mainBaseSha??'')&&
  HEX.test(statement.policyFingerprintSha256??'')&&
  HEX.test(statement.cvCandidateSha256??'')&&
  HEX.test(statement.nonce??'')&&statement.nonce!=='0'.repeat(64)&&
  statement.decision==='HOLD'&&
  statement.sourceHeadSha===manifest?.currentHeadSha&&
  statement.mainBaseSha===manifest?.mainBaseSha&&
  statement.policyFingerprintSha256===manifest?.policyFingerprintSha256&&
  statement.cvCandidateSha256===manifest?.cvCandidateSha256&&
  statement.nonce===manifest?.nonce&&
  statement.previousEpoch===anchor?.epoch&&
  statement.previousCheckpointDigest===anchor?.checkpointDigest&&
  statement.previousRevocationVersion===anchor?.revocationVersion&&
  statement.previousRevocationDigest===anchor?.revocationDigest&&
  statement.nextEpoch===anchor?.epoch+1&&
  statement.nextEpoch===rev?.epoch&&
  statement.nextCheckpointDigest===nextCheckpoint&&
  statement.nextRevocationVersion===anchor?.revocationVersion+1&&
  statement.nextRevocationVersion===nextRevocation&&
  statement.nextRevocationDigest===nextRevocationDigest&&
  statement.previousSourceDigest===prevHash&&
  statement.nextSourceDigest===nextHash&&
  fresh(statement.issuedAt,statement.expiresAt,time)&&
  stamp(statement.issuedAt)>stamp(anchor?.observedAt);
 add(statementOk,'CY_TWO_EPOCH_SOURCE_BOUND_OPERATOR_HANDOFF_INVALID');
 const officers=previous?.officers;
 add(exact(officers,OFFICERS)&&OFFICERS.every(r=>validOfficer(officers?.[r],r,time))&&
  officers.SECURITY_OFFICER.githubLogin.toLowerCase()!==
   officers.BUSINESS_OFFICER.githubLogin.toLowerCase()&&
  officers.SECURITY_OFFICER.organizationId===
   officers.BUSINESS_OFFICER.organizationId&&
  officers.SECURITY_OFFICER.spkiSha256!==officers.BUSINESS_OFFICER.spkiSha256&&
  officers.SECURITY_OFFICER.keyId!==officers.BUSINESS_OFFICER.keyId,
  'CY_DISTINCT_NOMINATED_OFFICER_MANDATES_AND_KEYS_REQUIRED');
 let correctOfficers=0;
 if(!Array.isArray(officerSignatures)||officerSignatures.length!==2)
  errors.add('CY_EXACT_TWO_OPERATOR_SIGNED_ACKNOWLEDGMENTS_REQUIRED');
 const officerMap=new Map();
 for(const entry of Array.isArray(officerSignatures)?officerSignatures:[]){
  if(!OFFICERS.includes(entry?.role)||officerMap.has(entry.role)){
   errors.add('CY_OPERATOR_SIGNATURE_ROLE_DUPLICATED_OR_UNKNOWN');continue;
  }
  officerMap.set(entry.role,entry);
 }
 for(const role of OFFICERS){
  if(verifySignature('handoff',role,statement,officerMap.get(role),officers?.[role]))
   correctOfficers++;
  else errors.add('CY_OPERATOR_ACK_SIGNATURE_OR_PIN_INVALID_'+role);
 }
 const changed=[];
 for(const role of SOURCE_ROLES){
  const old=priorRoster?.[role],newValue=currentRoster?.[role];
  if(!old||!newValue)continue;
  if(canonical(old)!==canonical(newValue))changed.push(role);
 }
 const required=new Set(changed),rotationsMap=new Map();
 if(!Array.isArray(rotations)||rotations.length!==changed.length)
  errors.add('CY_EXACT_ROTATION_COUNT_NOT_MATCHING_CHANGED_ROLES');
 for(const item of Array.isArray(rotations)?rotations:[]){
  if(!exact(item,CHANGE)||!SOURCE_ROLES.includes(item.role)||
     rotationsMap.has(item.role)||!required.has(item.role)){
   errors.add('CY_UNKNOWN_DUPLICATE_OR_UNCHANGED_ROTATION');continue;
  }
  rotationsMap.set(item.role,item);
 }
 let verifiedRotations=0;
 for(const role of changed){
  const item=rotationsMap.get(role),old=priorRoster?.[role],next=currentRoster?.[role];
  const rotationStatement={schemaVersion:1,repository:REPO,role,
   handoffDigest:statementOk?dig(candidateBytes('handoff',statement)):null,
   previousKeyId:old?.keyId??null,nextKeyId:next?.keyId??null,
   previousTlsPin:old?.tlsSpkiSha256??null,nextTlsPin:next?.tlsSpkiSha256??null,
   previousSignerPin:old?.signerSpkiSha256??null,
   nextSignerPin:next?.signerSpkiSha256??null,
   previousHost:old?.host??null,nextHost:next?.host??null,
   previousPath:old?.path??null,nextPath:next?.path??null};
  if(item&&verifySignature('rotation',role,rotationStatement,
     item.previousSignature,
     {keyId:old.keyId,publicKeyPem:old.publicKeyPem,spkiSha256:old.signerSpkiSha256})&&
     verifySignature('rotation',role,rotationStatement,
     item.successorSignature,
     {keyId:next.keyId,publicKeyPem:next.publicKeyPem,spkiSha256:next.signerSpkiSha256}))
   verifiedRotations++;
  else errors.add('CY_OLD_NEW_SIGNER_ROTATION_COSIGN_MISSING_'+role);
 }
 const revoked=Array.isArray(rev?.revokedKeyIds)?rev.revokedKeyIds:[];
 for(const role of SOURCE_ROLES){
  const old=priorRoster?.[role],next=currentRoster?.[role];
  if(old&&revoked.includes(old.keyId))
   errors.add('CY_PREVIOUS_SIGNER_REVOKED_BREAK_GLASS_REQUIRED_'+role);
  if(next&&revoked.includes(next.keyId))
   errors.add('CY_SUCCESSOR_SIGNER_REVOKED_'+role);
 }
 const roleSpkis=[...SOURCE_ROLES.map(r=>priorRoster?.[r]?.signerSpkiSha256),
  ...SOURCE_ROLES.map(r=>currentRoster?.[r]?.signerSpkiSha256),
  ...OFFICERS.map(r=>officers?.[r]?.spkiSha256)];
 for(let i=0;i<roleSpkis.length;i++){
  if(typeof roleSpkis[i]!=='string')continue;
  for(let j=i+1;j<roleSpkis.length;j++){
   if(roleSpkis[i]===roleSpkis[j]&&
      !(i<3&&j===i+3&&priorRoster?.[SOURCE_ROLES[i]]?.keyId===
        currentRoster?.[SOURCE_ROLES[i]]?.keyId))
    errors.add('CY_CROSS_ROLE_GENERATION_OR_OFFICER_KEY_COLLISION');
  }
 }
 const witnessMap=new Map();
 if(!Array.isArray(historicalWitnesses)||historicalWitnesses.length!==2)
  errors.add('CY_EXACT_TWO_PREVIOUS_WITNESS_ANCHOR_RECEIPTS_REQUIRED');
 for(const packet of Array.isArray(historicalWitnesses)?historicalWitnesses:[]){
  const role=packet?.statement?.role;
  if(!HISTORICAL_ROLES.includes(role)||witnessMap.has(role)){
   errors.add('CY_DUPLICATE_OR_UNKNOWN_PREVIOUS_WITNESS');continue;
  }
  witnessMap.set(role,packet);
 }
 let previousWitnessCount=0;
 for(const role of HISTORICAL_ROLES){
  const p=witnessMap.get(role),s=p?.statement,priorKey=priorRoster?.[role];
  const valid=exact(p,['statement','signature'])&&exact(s,PRIOR)&&
   s.schemaVersion===1&&s.role===role&&s.repository===REPO&&
   s.sourceHeadSha===manifest?.currentHeadSha&&
   s.epoch===anchor?.epoch&&s.checkpointDigest===anchor?.checkpointDigest&&
   s.revocationVersion===anchor?.revocationVersion&&
   s.revocationDigest===anchor?.revocationDigest&&
   s.challengeNonce===manifest?.nonce&&
   Number.isFinite(stamp(s.observedAt))&&
   stamp(s.observedAt)>=stamp(anchor?.observedAt)&&
   stamp(s.observedAt)<=stamp(statement?.issuedAt)&&
   stamp(s.observedAt)>=time-900000&&
   verifySignature('historical-anchor',role,s,p.signature,{
    keyId:priorKey?.keyId,publicKeyPem:priorKey?.publicKeyPem,
    spkiSha256:priorKey?.signerSpkiSha256
   });
  if(valid)previousWitnessCount++;
  else errors.add('CY_SIGNED_PREVIOUS_HIGHWATERMARK_NOT_CORROBORATED_'+role);
 }
 const incidentOk=exact(incidents,INCIDENT)&&
  incidents.status==='CLEAR'&&
  Array.isArray(incidents.forkReports)&&incidents.forkReports.length===0&&
  incidents.recoveryRequested==='NONE';
 add(incidentOk,'CY_INCIDENT_FORK_OR_UNAUTHORIZED_UNQUARANTINE_QUARANTINE');
 const operatorCandidateConsistent=errors.size===0&&correctOfficers===2&&
  previousWitnessCount===2&&verifiedRotations===changed.length;
 const snapshot={head:manifest?.currentHeadSha??null,
  previousEpoch:anchor?.epoch??null,nextEpoch:rev?.epoch??null,
  previousSourceDigest:prevHash,nextSourceDigest:nextHash,
  rotationCount:verifiedRotations,previousAnchorWitnessCount:previousWitnessCount,
  transitionDigest:statementOk?dig(candidateBytes('handoff',statement)):null,
  latestCheckpointDigest:nextCheckpoint??null};
 return Object.freeze({
  phase:'1CY',schemaVersion:1,
  kind:'OFFLINE_OPERATOR_PIN_ROTATION_PREVIOUS_WITNESS_QUARANTINE_CANDIDATE_HOLD',
  repository:REPO,
  priorThreeSourceCandidateVerified:current?.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent===true,
  twoClaimedOfficerAcknowledgmentsMathematicallyVerified:correctOfficers===2,
  twoPriorWitnessCheckpointSignaturesVerified:previousWitnessCount===2,
  requiredRotationsCount:changed.length,verifiedRotationsCount:verifiedRotations,
  operatorPinLifecycleCandidateMathematicallyConsistent:operatorCandidateConsistent,
  quarantineRequired:errors.size>0||!incidentOk,
  automaticRecoveryOrUnquarantineAllowed:false,
  candidateTransitionDigestSha256:dig(canonical(snapshot)),
  anomalyCodes:Object.freeze([...errors].sort()),
  authorizedCorporateOperatorMandatesIndependentlyAuthenticated:false,
  independentOldNewSourceKeyAndTlsPinEnrollmentVerified:false,
  independentlyRetrievedPriorWitnessHighWatermarkVerified:false,
  durableOffsiteReplayForkQuarantineStateVerified:false,
  incidentClearanceAndIndependentRecoveryApprovalVerified:false,
  currentHeadEnforcedGithubRulesetsCodeownersReviewVerified:false,
  genuineProviderCcaRcaiEmudhraMcaAndStagingVerified:false,
  independentOidcSlsaWormDrAttestationVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function localJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('CY_OPERATOR_FILE_PATH_INVALID');
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>262144)
  throw Error('CY_CANDIDATE_NOT_SAFE_BOUNDED_REGULAR_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    args[0]!=='--inspect-operator-handoff')
  throw Error('CY_ONLY_HUMAN_LOCAL_OFFLINE_INSPECTION');
 const receipt=assessOperatorPinLifecycle(localJson(args[1]));
 console.log(JSON.stringify(receipt,null,2));
 if(!receipt.operatorPinLifecycleCandidateMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(error){
  console.error('CY independent operator authorization still HOLD:',
   error instanceof Error?error.message:'Unknown');process.exitCode=1;
 }
}
