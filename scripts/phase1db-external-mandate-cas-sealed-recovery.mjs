import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,canonical} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {assessAppendOnlyIncidentReplay}
 from './phase1da-appendonly-incident-replay-ledger.mjs';

// Phase 1DB: offline applicant-supplied external mandate / dual-source
// conditional-CAS and sealed recovery provenance *candidate* only.
// Provider-backed writes, external key enrollment, CAS/retention verification,
// fork publication, independent legal acceptance and production are NOT done.
export const ROLES=Object.freeze([
 'MANDATE_REGISTRAR','JOURNAL_PRIMARY','JOURNAL_REPLICA','ARCHIVE_AUDITOR'
]);
export const DOMAIN='aaditech/phase1db/offline-cas-and-sealed-recovery/v1/';
const H=/^[a-f0-9]{64}$/,SHA=/^[a-f0-9]{40}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/,ID=/^[a-z][a-z0-9._-]{5,79}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const sha=x=>createHash('sha256').update(x).digest('hex');
const age=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const validWithin=(when,now)=>Number.isFinite(age(when))&&
 Number.isFinite(now)&&age(when)>=now-900000&&age(when)<=now+300000;
const publicHost=h=>typeof h==='string'&&h.length<=253&&h.length>=8&&
 /^[a-z0-9.-]+$/.test(h)&&!h.includes('..')&&
 h.split('.').every(s=>s.length>0&&s.length<=63&&
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s))&&
 /\.[a-z]{2,15}$/.test(h)&&
 !/\.(?:local|localhost|internal|invalid|example|test)$/.test(h);
const F={
 source:['role','organizationId','host','keyId','publicKeyPem','spkiSha256',
  'tlsSpkiSha256','authorityEvidenceSha256','validFrom','validUntil','revoked'],
 authorization:['schemaVersion','kind','repository','sourceHeadSha','mainBaseSha',
  'incidentId','mandateDigest','officerRosterDigest','rootSpkiSha256',
  'issuerEvidenceSha256','challengeNonce','issuedAt','expiresAt','decision'],
 cas:['schemaVersion','kind','role','repository','sourceHeadSha',
  'incidentId','storeId','challengeNonce','expectedVersion',
  'expectedDigest','committedVersion','committedDigest','archiveDigest',
  'objectVersion','precondition','outcome','observedAt','decision'],
 seal:['schemaVersion','kind','repository','sourceHeadSha','incidentId',
  'storeId','committedVersion','committedDigest','archiveDigest',
  'objectVersion','contentDigest','retentionUntil','lockMode',
  'legalHoldClaim','deleteDeniedClaim','restoreHashMatchesClaim',
  'challengeNonce','observedAt','decision'],
 packet:['statement','signature'],
 signature:['role','keyId','algorithm','signature'],
 dispute:['status','forkReports','compromisedKeyIds','rollbackObserved',
  'releaseRequested','manualOverrideRequested']
};
export function signingBytes(kind,role,statement){
 if(!['mandate','cas','sealed-recovery'].includes(kind)||
    !ROLES.includes(role)||!own(statement)||
    JSON.stringify(statement).length>8192)
  throw Error('DB_INVALID_DOMAIN_ROLE_OR_SIZE');
 return Buffer.from(DOMAIN+kind+'/'+role+'/v1\n'+canonical(statement),'utf8');
}
export function sealedContentDigest(values){
 if(!own(values)||JSON.stringify(values).length>2048)
  throw Error('DB_SEALED_CONTENT_NOT_BOUNDED');
 return sha(Buffer.from(DOMAIN+'sealed-content/v1\n'+canonical(values),'utf8'));
}
function validKey(s,role,now){
 if(!exact(s,F.source)||s.role!==role||s.revoked!==false||
    !ID.test(s.organizationId??'')||!ID.test(s.keyId??'')||
    !publicHost(s.host)||!H.test(s.spkiSha256??'')||
    !H.test(s.tlsSpkiSha256??'')||
    !H.test(s.authorityEvidenceSha256??'')||
    typeof s.publicKeyPem!=='string'||s.publicKeyPem.length>4096||
    !Number.isFinite(age(s.validFrom))||!Number.isFinite(age(s.validUntil))||
    age(s.validFrom)>now||age(s.validUntil)<=now)return false;
 try{
  const pub=createPublicKey(s.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   sha(pub.export({format:'der',type:'spki'}))===s.spkiSha256;
 }catch{return false;}
}
function validSigned(kind,role,statement,signature,source){
 if(!exact(signature,F.signature)||signature.role!==role||
    signature.keyId!==source?.keyId||signature.algorithm!=='Ed25519'||
    !SIG.test(signature.signature??'')||!source)return false;
 try{
  const bytes=Buffer.from(signature.signature,'base64');
  return bytes.length===64&&bytes.toString('base64')===signature.signature&&
   verify(null,signingBytes(kind,role,statement),
    createPublicKey(source.publicKeyPem),bytes);
 }catch{return false;}
}
const safeDigest=(kind,role,statement)=>{
 try{return sha(signingBytes(kind,role,statement));}catch{return null;}
};
export function assessSealedOffsiteCasCandidate({
 daEvidence=null,sources=null,authorization=null,
 casReceipts=null,sealedRecovery=null,dispute=null,
 now='2026-11-20T00:00:00.000Z'
}={}){
 const errors=new Set(),add=(ok,code)=>{if(!ok)errors.add(code)};
 const nowMs=age(now);
 add(Number.isFinite(nowMs),'DB_VERIFICATION_CLOCK_INVALID');
 let prior;
 try{prior=assessAppendOnlyIncidentReplay({...daEvidence,now});}catch{}
 const priorValid=prior?.candidateAppendOnlyIncidentLineageMathematicallyConsistent===
  true&&prior?.quarantineRequired===true&&
  prior?.automaticRecoveryOrUnquarantineAllowed===false&&
  prior?.productionReleaseAuthorized===false&&prior?.releaseDecision==='HOLD';
 add(priorValid,'DB_PRECEDING_1DA_LEDGER_CANDIDATE_FAILED');
 const cz=daEvidence?.czEvidence,cy=cz?.cyEvidence,head=cy?.manifest?.currentHeadSha,
  base=cy?.manifest?.mainBaseSha,incident=cz?.incident,
  archive=incident?.archiveEvidenceSha256,
  objectVersion=cz?.recovery?.statement?.objectVersion,
  nonce=cy?.manifest?.nonce,
  expectedDigest=daEvidence?.anchor?.ledgerDigest,
  lastDigest=prior?.proposedFinalLedgerDigestSha256,
  startingVersion=daEvidence?.anchor?.ledgerVersion,
  endingVersion=Number.isSafeInteger(startingVersion)?startingVersion+4:null,
  lastEvent=daEvidence?.events?.[3]?.statement?.recordedAt,
  replayFinish=daEvidence?.replay?.finishedAt,
  officerRoster=cz?.authority?.officers,
  registrarKey=cz?.authority?.root;
 const all=exact(sources,ROLES);
 add(all,'DB_EXACT_FOUR_NOMINATED_EXTERNAL_SOURCES_REQUIRED');
 const orgs=new Set(),hosts=new Set(),keys=new Set(),tls=new Set(),keyIds=new Set();
 const forbidden=new Set([
  registrarKey?.spkiSha256,
  ...Object.values(officerRoster??{}).map(o=>o?.spkiSha256),
  ...Object.values(cy?.manifest?.sources??{}).map(o=>o?.signerSpkiSha256),
  ...Object.values(cy?.previous?.sources??{}).map(o=>o?.signerSpkiSha256)
 ].filter(x=>typeof x==='string'));
 for(const role of ROLES){
  const src=sources?.[role];
  if(!validKey(src,role,nowMs))
   errors.add('DB_SOURCE_PIN_ENROLLMENT_PACKET_INVALID_'+role);
  if(src&&typeof src==='object'){
   for(const [set,name] of [
    [orgs,'organizationId'],[hosts,'host'],[keys,'spkiSha256'],
    [tls,'tlsSpkiSha256'],[keyIds,'keyId']]){
    const v=src[name];
    if(typeof v!=='string'||set.has(v))
     errors.add('DB_SOURCE_ORGANIZATION_HOST_OR_KEY_NOT_INDEPENDENT');
    if(typeof v==='string')set.add(v);
   }
   if(forbidden.has(src.spkiSha256))
    errors.add('DB_SOURCE_REUSES_OFFICER_ROOT_OR_HISTORICAL_WITNESS_KEY');
  }
 }
 const a=authorization?.statement,as=authorization?.signature;
 const mandateDigest=priorValid?
  (()=>{try{
   return sha(Buffer.from('aaditech/phase1cz/mandate-incident-quarantine/v1/mandate/ROOT/v1\n'+
    canonical(cz.mandate),'utf8'));
  }catch{return null;}})():null;
 const officerDigest=officerRoster?
  (()=>{try{return sha(canonical(officerRoster));}catch{return null;}})():null;
 const authOk=exact(authorization,F.packet)&&exact(a,F.authorization)&&
  a.schemaVersion===1&&a.kind==='EXTERNAL_MANDATE_EVIDENCE_CANDIDATE_HOLD'&&
  a.repository===REPO&&a.sourceHeadSha===head&&SHA.test(head??'')&&
  a.mainBaseSha===base&&a.incidentId===incident?.incidentId&&
  a.mandateDigest===mandateDigest&&H.test(mandateDigest??'')&&
  a.officerRosterDigest===officerDigest&&H.test(officerDigest??'')&&
  a.rootSpkiSha256===registrarKey?.spkiSha256&&
  a.issuerEvidenceSha256===sources?.MANDATE_REGISTRAR?.authorityEvidenceSha256&&
  a.challengeNonce===nonce&&H.test(nonce??'')&&
  a.decision==='HOLD'&&validWithin(a.issuedAt,nowMs)&&
  Number.isFinite(age(a.expiresAt))&&age(a.expiresAt)>nowMs&&
  age(a.expiresAt)>age(a.issuedAt)&&
  age(a.expiresAt)-age(a.issuedAt)<=900000&&
  age(a.issuedAt)>age(incident?.issuedAt);
 add(authOk,'DB_EXTERNAL_MANDATE_BOUND_SOURCE_AND_FRESHNESS_INVALID');
 let verified=0;
 if(validSigned('mandate','MANDATE_REGISTRAR',a,as,sources?.MANDATE_REGISTRAR))
  verified++;
 else errors.add('DB_EXTERNAL_REGISTRAR_DETACHED_SIGNATURE_INVALID');
 const receipts=new Map();
 if(!Array.isArray(casReceipts)||casReceipts.length!==2)
  errors.add('DB_EXACT_TWO_CANDIDATE_CAS_RECEIPTS_REQUIRED');
 for(const packet of Array.isArray(casReceipts)?casReceipts:[]){
  const role=packet?.statement?.role;
  if(!['JOURNAL_PRIMARY','JOURNAL_REPLICA'].includes(role)||
     receipts.has(role)){
   errors.add('DB_DUPLICATE_OR_UNREVIEWED_CAS_ROLE');continue;
  }
  receipts.set(role,packet);
 }
 const casPayloads=[];
 let latestCasTime=Number.NEGATIVE_INFINITY;
 for(const role of ['JOURNAL_PRIMARY','JOURNAL_REPLICA']){
  const packet=receipts.get(role),s=packet?.statement;
  const obs=age(s?.observedAt);
  const valid=exact(packet,F.packet)&&exact(s,F.cas)&&
   s.schemaVersion===1&&s.kind==='CANDIDATE_CONDITIONAL_CAS_RECEIPT'&&
   s.role===role&&s.repository===REPO&&s.sourceHeadSha===head&&
   s.incidentId===incident?.incidentId&&s.storeId===daEvidence?.anchor?.storeId&&
   s.challengeNonce===nonce&&s.expectedVersion===startingVersion&&
   s.expectedDigest===expectedDigest&&H.test(expectedDigest??'')&&
   s.committedVersion===endingVersion&&s.committedDigest===lastDigest&&
   H.test(lastDigest??'')&&s.archiveDigest===archive&&
   s.objectVersion===objectVersion&&s.precondition==='IF_MATCH_EXACT_DIGEST'&&
   s.outcome==='CANDIDATE_CONDITIONAL_COMMIT'&&s.decision==='QUARANTINE'&&
   validWithin(s.observedAt,nowMs)&&obs>=age(replayFinish)&&
   obs>=age(a?.issuedAt);
  add(valid,'DB_CAS_VERSION_IF_MATCH_FORK_OR_CLOCK_INVALID_'+role);
  if(validSigned('cas',role,s,packet?.signature,sources?.[role]))
   verified++;
  else errors.add('DB_CAS_DETACHED_SIGNATURE_INVALID_'+role);
  latestCasTime=Math.max(latestCasTime,obs);
  if(exact(s,F.cas))casPayloads.push(canonical(Object.fromEntries(
   Object.entries(s).filter(([k])=>!['role','observedAt'].includes(k))
  )));
 }
 if(casPayloads.length!==2||casPayloads[0]!==casPayloads[1])
  errors.add('DB_DIVERGENT_CAS_PRIMARY_REPLICA_HIGHWATERMARK');
 const seal=sealedRecovery?.statement;
 const sealedValues={
  ledgerDigest:lastDigest??null,
  archiveEvidenceSha256:archive??null,
  objectVersion:objectVersion??null,
  sourceHeadSha:head??null,incidentId:incident?.incidentId??null
 };
 let contentDigest=null;
 try{contentDigest=sealedContentDigest(sealedValues);}catch{}
 const sealedOk=exact(sealedRecovery,F.packet)&&exact(seal,F.seal)&&
  seal.schemaVersion===1&&seal.kind==='SEALED_RECOVERY_PACKET_CANDIDATE_HOLD'&&
  seal.repository===REPO&&seal.sourceHeadSha===head&&
  seal.incidentId===incident?.incidentId&&
  seal.storeId===daEvidence?.anchor?.storeId&&
  seal.committedVersion===endingVersion&&seal.committedDigest===lastDigest&&
  H.test(lastDigest??'')&&seal.archiveDigest===archive&&
  seal.objectVersion===objectVersion&&seal.contentDigest===contentDigest&&
  seal.retentionUntil===daEvidence?.anchor?.retentionUntil&&
  Number.isFinite(age(seal.retentionUntil))&&
  age(seal.retentionUntil)>nowMs+30*86400000&&
  seal.lockMode==='COMPLIANCE'&&
  seal.legalHoldClaim===true&&seal.deleteDeniedClaim===true&&
  seal.restoreHashMatchesClaim===true&&
  seal.challengeNonce===nonce&&validWithin(seal.observedAt,nowMs)&&
  age(seal.observedAt)>=latestCasTime&&seal.decision==='HOLD';
 add(sealedOk,'DB_SEALED_RETENTION_ARCHIVE_CAS_BINDING_INVALID');
 if(validSigned('sealed-recovery','ARCHIVE_AUDITOR',seal,
    sealedRecovery?.signature,sources?.ARCHIVE_AUDITOR))verified++;
 else errors.add('DB_SEALED_ARCHIVE_DETACHED_SIGNATURE_INVALID');
 const disputeOk=exact(dispute,F.dispute)&&dispute.status==='QUARANTINED'&&
  Array.isArray(dispute.forkReports)&&dispute.forkReports.length===0&&
  Array.isArray(dispute.compromisedKeyIds)&&
  dispute.compromisedKeyIds.length===0&&
  dispute.rollbackObserved===false&&dispute.releaseRequested===false&&
  dispute.manualOverrideRequested===false;
 add(disputeOk,'DB_FORK_DISPUTE_COMPROMISE_OR_RELEASE_REQUEST_QUARANTINE');
 const valid=errors.size===0&&priorValid&&verified===4;
 const receipt=Object.freeze({
  phase:'1DB',schemaVersion:1,
  kind:'OFFLINE_EXTERNAL_MANDATE_CAS_AND_SEALED_RECOVERY_CANDIDATE_HARD_HOLD',
  repository:REPO,
  previous1DAIncidentLedgerCandidateMathematicallyConsistent:priorValid,
  candidateFourIndependentSourceSignaturesMathematicallyConsistent:valid,
  locallyVerifiedCandidateSignatures:verified,
  candidatePreviousLedgerDigest:H.test(expectedDigest??'')?expectedDigest:null,
  candidateCommittedLedgerDigest:H.test(lastDigest??'')?lastDigest:null,
  candidateSealedContentDigestSha256:contentDigest,
  anomalyCodes:Object.freeze([...errors].sort()),
  quarantineRequired:true,automaticRecoveryOrUnquarantineAllowed:false,
  independentlyAuthenticatedRegistrarOrganizationAndMandate:false,
  sourceSpkiAndTlsPinsExternallyEnrolledAndAuthenticated:false,
  externalProviderConditionalCasWritesActuallyExecuted:false,
  durableImmutableOffsiteAppendOnlyReadbackAndForkGossipVerified:false,
  providerVerifiedObjectLockComplianceDeleteDenialAndDr:false,
  legalSecurityBusinessIncidentAndOwnerApprovalsVerified:false,
  githubMainRulesetsCodeownersLatestHeadReviewsVerified:false,
  caRcaiCcaEmudhraOcspCrlMcaAndStagingVerified:false,
  independentOidcSlsaSupplyChainAttestationVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
 return receipt;
}
function localJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('DB_INVALID_OPERATOR_PACKET_PATH');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>262144)
  throw Error('DB_OPERATOR_PACKET_NOT_SAFE_BOUNDED_REGULAR_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    args[0]!=='--inspect-offsite-cas-candidate')
  throw Error('DB_OPERATOR_ONLY_READONLY_OFFLINE_CANDIDATE_INSPECTION');
 const payload=localJson(args[1]);
 const result=assessSealedOffsiteCasCandidate({...payload,now:new Date().toISOString()});
 console.log(JSON.stringify(result,null,2));
 if(!result.candidateFourIndependentSourceSignaturesMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main()}catch(e){
  console.error('DB externally authenticated mandate/CAS/WORM still HOLD:',
   e instanceof Error?e.message:'Unknown');process.exitCode=1;
 }
}
