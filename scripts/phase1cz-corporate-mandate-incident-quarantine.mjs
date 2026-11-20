import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {assessOperatorPinLifecycle}
 from './phase1cy-operator-pin-lifecycle-quarantine.mjs';

// 1CZ: OFFLINE operator-submitted candidate mandate/incident/recovery intake.
// A mathematically valid applicant-controlled root and role signatures ARE
// NOT independently authenticated corporate mandates, source trust,
// immutable offsite evidence, real incident response, or release authority.
export const OFFICERS=Object.freeze([
 'SECURITY_OFFICER','BUSINESS_OFFICER',
 'INCIDENT_COMMANDER','RECOVERY_AUDITOR'
]);
export const WITNESSES=Object.freeze(['WITNESS_A','WITNESS_B']);
export const DOMAIN='aaditech/phase1cz/mandate-incident-quarantine/v1/';
const HEX=/^[0-9a-f]{64}$/,SHA=/^[0-9a-f]{40}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 LOGIN=/^[A-Za-z0-9_-]{3,39}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>own(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const hash=x=>createHash('sha256').update(x).digest('hex');
const epoch=x=>Number.isSafeInteger(x)&&x>=0;
const stamp=x=>{
 if(typeof x!=='string'||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const bounded=(since,until,now)=>{
 const a=stamp(since),b=stamp(until);
 return Number.isFinite(a)&&Number.isFinite(b)&&Number.isFinite(now)&&
  a>=now-900000&&a<=now+300000&&b>now&&b>a&&b-a<=900000;
};
const ROOT=['keyId','publicKeyPem','spkiSha256','organizationId',
 'enrollmentEvidenceSha256','enrolledAt','expiresAt','revoked'];
const OFF=['role','organizationId','githubLogin','mandateDigest','keyId',
 'publicKeyPem','spkiSha256','validFrom','validUntil','revoked'];
const MS=['schemaVersion','kind','repository','sourceHeadSha','mainBaseSha',
 'cyTransitionDigest','organizationId','officerRosterSha256','nonce',
 'issuedAt','expiresAt','decision'];
const INCIDENT=['schemaVersion','kind','incidentId','repository',
 'sourceHeadSha','previousCheckpointDigest','nextCheckpointDigest',
 'cyTransitionDigest','sourceRosterSha256','archiveEvidenceSha256',
 'nonce','issuedAt','expiresAt','decision'];
const WIT=['schemaVersion','role','incidentId','repository','sourceHeadSha',
 'previousCheckpointDigest','nextCheckpointDigest','nonce','observedAt',
 'decision'];
const REC=['schemaVersion','kind','incidentId','sourceHeadSha',
 'archiveEvidenceSha256','objectVersion','restoreRegion',
 'restoreObservedAt','restoreHashMatchesClaim','deleteDeniedClaim',
 'decision'];
const SIGREC=['role','keyId','algorithm','signature'];
const PACK=['statement','signature'];
const END=['statement','signatures'];
function safePublicKey(k){
 if(!k||typeof k.publicKeyPem!=='string'||k.publicKeyPem.length>4096||
    !HEX.test(k.spkiSha256??'')||!ID.test(k.keyId??''))
  return false;
 try{
  const p=createPublicKey(k.publicKeyPem);
  return p.asymmetricKeyType==='ed25519'&&
    hash(p.export({type:'spki',format:'der'}))===k.spkiSha256;
 }catch{return false;}
}
export function signedBytes(kind,role,claim){
 if(!['mandate','incident','fork','recovery'].includes(kind)||
    !['ROOT',...OFFICERS,...WITNESSES].includes(role)||
    !own(claim)||JSON.stringify(claim).length>8192)
  throw Error('CZ_UNKNOWN_OR_OVERSIZE_ROLE_SIGNED_CLAIM');
 return Buffer.from(DOMAIN+kind+'/'+role+'/v1\n'+canonical(claim),'utf8');
}
function signedBy(kind,role,claim,signature,key){
 if(!exact(signature,SIGREC)||signature.role!==role||
    signature.keyId!==key?.keyId||signature.algorithm!=='Ed25519'||
    !SIG.test(signature.signature??'')||!safePublicKey(key))
  return false;
 try{
  const buf=Buffer.from(signature.signature,'base64');
  return buf.length===64&&buf.toString('base64')===signature.signature&&
   verify(null,signedBytes(kind,role,claim),
    createPublicKey(key.publicKeyPem),buf);
 }catch{return false;}
}
function roleKey(key,role,org,now){
 return exact(key,OFF)&&key.role===role&&
  key.organizationId===org&&ID.test(org??'')&&
  LOGIN.test(key.githubLogin??'')&&
  key.githubLogin.toLowerCase()!=='j9619655391-max'&&
  HEX.test(key.mandateDigest??'')&&key.revoked===false&&
  safePublicKey(key)&&Number.isFinite(stamp(key.validFrom))&&
  Number.isFinite(stamp(key.validUntil))&&
  stamp(key.validFrom)<=now&&stamp(key.validUntil)>now;
}
const deny=(errors,matched,cy,mandateHash,incidentHash,recoveryHash)=>Object.freeze({
 phase:'1CZ',schemaVersion:1,
 kind:'UNTRUSTED_CORPORATE_MANDATE_FORK_INCIDENT_RECOVERY_HARD_HOLD',
 repository:REPO,
 prior1CYOperatorCandidateMathematicallyConsistent:cy===true,
 candidateMandateIncidentRecoveryMathematicallyConsistent:errors.size===0&&matched===8&&cy===true,
 candidateDetachedSignaturesVerified:matched,
 unsignedCandidateMandateDigestSha256:mandateHash,
 unsignedCandidateIncidentDigestSha256:incidentHash,
 unsignedCandidateRecoveryDigestSha256:recoveryHash,
 quarantineRequired:true,
 automaticRecoveryOrUnquarantineAllowed:false,
 anomalyCodes:Object.freeze([...errors].sort()),
 independentCorporateRootOrLegalKeyEnrollmentVerified:false,
 independentSecurityBusinessAndIncidentOfficerMandatesVerified:false,
 realNonauthorLatestHeadGithubApprovalsVerified:false,
 independentlyFetchedHistoricalWitnessAndForkLogsVerified:false,
 immutableCrossRunHighWatermarkOrExternallyEnforcedCasVerified:false,
 witnessedActualStorageObjectLockDeleteDenialAndDrRestoreVerified:false,
 genuineExternalProviderCaOcspCrlMcaSignatoryAuthorityVerified:false,
 signedOidcSlsaSupplyChainAndApprovedStagingVerified:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});
export function assessMandateForkRecoveryCandidate({
 cyEvidence=null,authority=null,mandate=null,mandateSignature=null,
 incident=null,officerApprovals=[],forkWitnesses=[],recovery=null,
 now='2026-11-20T00:00:00.000Z'
}={}){
 const errors=new Set();
 const add=(valid,code)=>{if(!valid)errors.add(code);};
 const nowMs=stamp(now);
 if(!Number.isFinite(nowMs))errors.add('CZ_INVALID_OPERATOR_VERIFICATION_CLOCK');
 let cy=null;
 try{cy=assessOperatorPinLifecycle({...cyEvidence,now});}catch{}
 const cyGood=cy?.operatorPinLifecycleCandidateMathematicallyConsistent===true&&
  cy?.quarantineRequired===false&&
  cy?.automaticRecoveryOrUnquarantineAllowed===false&&
  cy?.productionReleaseAuthorized===false&&cy?.releaseDecision==='HOLD';
 add(cyGood,'CZ_PRECEDING_1CY_CANDIDATE_REVALIDATION_FAILED');
 const man=cyEvidence?.manifest,prior=cyEvidence?.previous?.anchor;
 const cyStatement=cyEvidence?.statement;
 const sigHash=cy?.candidateTransitionDigestSha256;
 const root=authority?.root,officers=authority?.officers;
 const rootGood=exact(root,ROOT)&&root.revoked===false&&
  ID.test(root.organizationId??'')&&
  HEX.test(root.enrollmentEvidenceSha256??'')&&safePublicKey(root)&&
  Number.isFinite(stamp(root.enrolledAt))&&
  Number.isFinite(stamp(root.expiresAt))&&
  stamp(root.enrolledAt)<=nowMs&&stamp(root.expiresAt)>nowMs;
 add(rootGood,'CZ_SELF_SUPPLIED_ROOT_SCHEMA_OR_EXPIRY_INVALID');
 const rosterGood=exact(officers,OFFICERS);
 add(rosterGood,'CZ_FOUR_SEPARATE_CORPORATE_OPERATOR_ROLES_REQUIRED');
 const logins=new Set(),keys=new Set(),ids=new Set();
 for(const role of OFFICERS){
  const k=officers?.[role];
  if(!roleKey(k,role,root?.organizationId,nowMs))
   errors.add('CZ_NOMINATED_'+role+'_KEY_OR_MANDATE_INVALID');
  if(k){
   for(const [set,value] of [
    [logins,k.githubLogin?.toLowerCase()],
    [keys,k.spkiSha256],[ids,k.keyId]
   ]){
    if(value===undefined||set.has(value))
     errors.add('CZ_OFFICER_LOGIN_OR_KEY_ROLE_COLLISION');
    set.add(value);
   }
  }
 }
 const existing=cyEvidence?.previous?.officers;
 for(const role of ['SECURITY_OFFICER','BUSINESS_OFFICER']){
  if(!existing?.[role]||!officers?.[role]||
    canonical(officers[role])!==canonical(existing[role]))
   errors.add('CZ_EXISTING_SECURITY_BUSINESS_MANDATE_SUBSTITUTED_'+role);
 }
 const sourcePins=new Set(Object.values(man?.sources??{}).map(x=>x?.signerSpkiSha256));
 const historicalPins=new Set(Object.values(cyEvidence?.previous?.sources??{})
  .map(x=>x?.signerSpkiSha256));
 for(const role of OFFICERS)
  if(root?.spkiSha256===officers?.[role]?.spkiSha256)
   errors.add('CZ_CORPORATE_ROOT_REUSED_AS_OFFICER_KEY');
 if(sourcePins.has(root?.spkiSha256)||historicalPins.has(root?.spkiSha256))
  errors.add('CZ_CORPORATE_ROOT_REUSED_AS_SOURCE_KEY');
 for(const role of OFFICERS)
  if(sourcePins.has(officers?.[role]?.spkiSha256)||
     historicalPins.has(officers?.[role]?.spkiSha256))
   errors.add('CZ_OFFICER_AND_WITNESS_SOURCE_KEY_REUSE');
 const officerDigest=rosterGood?hash(canonical(officers)):null;
 const mandateGood=exact(mandate,MS)&&mandate.schemaVersion===1&&
  mandate.kind==='CANDIDATE_CORPORATE_MANDATE_HOLD'&&
  mandate.repository===REPO&&mandate.sourceHeadSha===man?.currentHeadSha&&
  SHA.test(mandate.sourceHeadSha??'')&&
  mandate.mainBaseSha===man?.mainBaseSha&&
  mandate.cyTransitionDigest===sigHash&&
  HEX.test(mandate.cyTransitionDigest??'')&&
  mandate.organizationId===root?.organizationId&&
  mandate.officerRosterSha256===officerDigest&&
  mandate.nonce===man?.nonce&&HEX.test(mandate.nonce??'')&&
  mandate.decision==='HOLD'&&
  bounded(mandate.issuedAt,mandate.expiresAt,nowMs)&&
  stamp(mandate.issuedAt)>stamp(prior?.observedAt);
 add(mandateGood,'CZ_ROOT_SIGNED_CORPORATE_MANDATE_SOURCE_INVALID');
 add(signedBy('mandate','ROOT',mandate,mandateSignature,root),
  'CZ_CANDIDATE_ROOT_MANDATE_SIGNATURE_INVALID');
 const archive=incident?.archiveEvidenceSha256;
 const incidentGood=exact(incident,INCIDENT)&&incident.schemaVersion===1&&
  incident.kind==='FORK_OR_COMPROMISE_REVIEW_ONLY'&&
  ID.test(incident.incidentId??'')&&incident.repository===REPO&&
  incident.sourceHeadSha===man?.currentHeadSha&&
  incident.previousCheckpointDigest===prior?.checkpointDigest&&
  incident.nextCheckpointDigest===
   cyEvidence?.observations?.REVOCATION?.data?.statement?.checkpointDigest&&
  incident.cyTransitionDigest===sigHash&&
  incident.sourceRosterSha256===cyStatement?.nextSourceDigest&&
  HEX.test(archive??'')&&incident.nonce===man?.nonce&&
  incident.decision==='QUARANTINE'&&
  bounded(incident.issuedAt,incident.expiresAt,nowMs)&&
  stamp(incident.issuedAt)>=stamp(mandate?.issuedAt);
 add(incidentGood,'CZ_INCIDENT_CUSTODY_BINDING_OR_QUARANTINE_INVALID');
 const approvals=new Map();
 if(!Array.isArray(officerApprovals)||officerApprovals.length!==4)
  errors.add('CZ_EXACT_FOUR_SEGREGATED_APPROVALS_REQUIRED');
 for(const r of Array.isArray(officerApprovals)?officerApprovals:[]){
  if(!OFFICERS.includes(r?.role)||approvals.has(r.role)){
   errors.add('CZ_DUPLICATE_UNAUTHENTICATED_OFFICER_APPROVAL');continue;
  }
  approvals.set(r.role,r);
 }
 let approved=0;
 for(const role of OFFICERS){
  if(signedBy('incident',role,incident,approvals.get(role),officers?.[role]))
   approved++;
  else errors.add('CZ_INVALID_'+role+'_DETACHED_QUARANTINE_SIGNATURE');
 }
 const witnessMap=new Map();
 if(!Array.isArray(forkWitnesses)||forkWitnesses.length!==2)
  errors.add('CZ_TWO_DISTINCT_PREVIOUS_WITNESS_FORK_STATEMENTS_REQUIRED');
 for(const packet of Array.isArray(forkWitnesses)?forkWitnesses:[]){
  const role=packet?.statement?.role;
  if(!WITNESSES.includes(role)||witnessMap.has(role)){
   errors.add('CZ_DUPLICATE_OR_UNKNOWN_FORK_WITNESS');continue;
  }
  witnessMap.set(role,packet);
 }
 let witnesses=0,latest=Number.NEGATIVE_INFINITY;
 for(const role of WITNESSES){
  const packet=witnessMap.get(role),s=packet?.statement,
   old=cyEvidence?.previous?.sources?.[role];
  const priorKey=old?{
   keyId:old.keyId,publicKeyPem:old.publicKeyPem,
   spkiSha256:old.signerSpkiSha256
  }:null;
  const observed=stamp(s?.observedAt);
  const valid=exact(packet,PACK)&&exact(s,WIT)&&
   s.schemaVersion===1&&s.role===role&&
   s.incidentId===incident?.incidentId&&s.repository===REPO&&
   s.sourceHeadSha===man?.currentHeadSha&&
   s.previousCheckpointDigest===prior?.checkpointDigest&&
   s.nextCheckpointDigest===incident?.nextCheckpointDigest&&
   s.nonce===man?.nonce&&
   Number.isFinite(observed)&&observed>=stamp(incident?.issuedAt)&&
   observed>=stamp(prior?.observedAt)&&observed<=nowMs+300000&&
   s.decision==='FORK_REVIEW_PENDING'&&
   signedBy('fork',role,s,packet?.signature,priorKey);
  if(valid)witnesses++;
  else errors.add('CZ_'+role+'_HISTORICAL_FORK_CORROBORATION_INVALID');
  latest=Math.max(latest,observed);
 }
 const rec=recovery?.statement,recs=recovery?.signatures;
 const recGood=exact(recovery,END)&&exact(rec,REC)&&
  rec.schemaVersion===1&&rec.kind==='READ_ONLY_REHEARSAL'&&
  rec.incidentId===incident?.incidentId&&
  rec.sourceHeadSha===man?.currentHeadSha&&
  rec.archiveEvidenceSha256===archive&&HEX.test(archive??'')&&
  ID.test(rec.objectVersion??'')&&
  rec.objectVersion===cyEvidence?.observations?.WITNESS_A?.data?.statement?.objectVersion&&
  rec.objectVersion===cyEvidence?.observations?.WITNESS_B?.data?.statement?.objectVersion&&
  /^[a-z]{2}-[a-z]+-\d$/.test(rec.restoreRegion??'')&&
  rec.restoreHashMatchesClaim===true&&rec.deleteDeniedClaim===true&&
  rec.decision==='HOLD'&&
  Number.isFinite(stamp(rec.restoreObservedAt))&&
  stamp(rec.restoreObservedAt)>=latest&&
  stamp(rec.restoreObservedAt)<=nowMs+300000;
 add(recGood,'CZ_RECOVERY_DRY_RUN_ARCHIVE_OR_TIME_INVALID');
 const recMap=new Map();
 if(!Array.isArray(recs)||recs.length!==2)
  errors.add('CZ_TWO_DISTINCT_RECOVERY_SEGREGATION_SIGNATURES_REQUIRED');
 for(const r of Array.isArray(recs)?recs:[]){
  if(!['INCIDENT_COMMANDER','RECOVERY_AUDITOR'].includes(r?.role)||
     recMap.has(r.role)){
   errors.add('CZ_DUPLICATE_OR_UNREVIEWED_RECOVERY_SIGNER');continue;
  }
  recMap.set(r.role,r);
 }
 let recoveryCount=0;
 for(const role of ['INCIDENT_COMMANDER','RECOVERY_AUDITOR']){
  if(signedBy('recovery',role,rec,recMap.get(role),officers?.[role]))
   recoveryCount++;
  else errors.add('CZ_INVALID_'+role+'_RECOVERY_DRY_RUN_SIGNATURE');
 }
 const crossSource={
  head:man?.currentHeadSha??null,main:man?.mainBaseSha??null,
  previousCheckpoint:prior?.checkpointDigest??null,
  latestCheckpoint:incident?.nextCheckpointDigest??null,
  cyDigest:sigHash??null,mandateDigest:mandateGood?
   hash(signedBytes('mandate','ROOT',mandate)):null,
  incidentDigest:incidentGood?
   hash(signedBytes('incident','SECURITY_OFFICER',incident)):null,
  witnesses,recoveryCount
 };
 return deny(errors,approved+witnesses+recoveryCount,cyGood,
  mandateGood?crossSource.mandateDigest:null,
  incidentGood?crossSource.incidentDigest:null,
  recGood?hash(signedBytes('recovery','RECOVERY_AUDITOR',rec)):null);
}
function localJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('CZ_OPERATOR_FILE_PATH_INVALID');
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>262144)
  throw Error('CZ_OPERATOR_PACKET_NOT_SAFE_REGULAR_BOUNDED_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    args[0]!=='--inspect-candidate-quarantine')
  throw Error('CZ_OPERATOR_ONLY_READONLY_QUARANTINE_INSPECTION');
 const packet=localJson(args[1]);
 const result=assessMandateForkRecoveryCandidate({
  ...packet,now:new Date().toISOString()
 });
 console.log(JSON.stringify(result,null,2));
 if(!result.candidateMandateIncidentRecoveryMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main()}catch(error){
  console.error('CZ corporate roots/witnesses remain UNAUTHENTICATED:',
   error instanceof Error?error.message:'Unknown');process.exitCode=1;
 }
}
