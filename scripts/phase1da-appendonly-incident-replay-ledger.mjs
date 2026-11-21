import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,canonical}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {OFFICERS,WITNESSES,assessMandateForkRecoveryCandidate}
 from './phase1cz-corporate-mandate-incident-quarantine.mjs';

// Phase 1DA: purely offline applicant-controlled *candidate* append-only log,
// witness high-watermark, deterministic replay and denied recovery. This does
// not provide independently authenticated corporate appointment, immutable
// offsite CAS, real archival deletion denial or release privileges.
export const DOMAIN='aaditech/phase1da/candidate-incident-ledger/v1/';
export const STAGES=Object.freeze([
 'INCIDENT_OPENED','EVIDENCE_SEALED','RECOVERY_REHEARSED','RELEASE_DENIED'
]);
export const EVENT_SIGNERS=Object.freeze({
 INCIDENT_OPENED:Object.freeze(['INCIDENT_COMMANDER','SECURITY_OFFICER']),
 EVIDENCE_SEALED:Object.freeze(['SECURITY_OFFICER','BUSINESS_OFFICER']),
 RECOVERY_REHEARSED:Object.freeze(['INCIDENT_COMMANDER','RECOVERY_AUDITOR']),
 RELEASE_DENIED:Object.freeze(['BUSINESS_OFFICER','RECOVERY_AUDITOR'])
});
const HEX=/^[0-9a-f]{64}$/,SHA=/^[0-9a-f]{40}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/,ID=/^[a-z][a-z0-9._-]{5,79}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>own(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const count=x=>Number.isSafeInteger(x)&&x>=0;
const sha=x=>createHash('sha256').update(x).digest('hex');
const stamp=x=>{
 if(typeof x!=='string'||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const within=(date,now)=>Number.isFinite(date)&&Number.isFinite(now)&&
 date>=now-900000&&date<=now+300000;
const F={
 anchor:['schemaVersion','repository','sourceHeadSha','incidentId',
  'storeId','ledgerVersion','ledgerDigest','checkpointDigest',
  'observedAt','retentionUntil'],
 event:['schemaVersion','stage','repository','sourceHeadSha','mainBaseSha',
  'incidentId','sequence','previousDigest','checkpointDigest',
  'archiveEvidenceSha256','objectVersion','evidenceDigest',
  'recordedAt','decision'],
 witness:['schemaVersion','role','repository','sourceHeadSha','incidentId',
  'ledgerVersion','ledgerDigest','previousLedgerDigest',
  'checkpointDigest','nonce','observedAt','decision'],
 replay:['schemaVersion','kind','repository','sourceHeadSha','incidentId',
  'startingVersion','startingDigest','endingVersion','endingDigest',
  'archiveEvidenceSha256','objectVersion','startedAt','finishedAt',
  'rollbackAttempt','unquarantineRequested','releaseDecision'],
 signature:['role','keyId','algorithm','signature'],
 packet:['statement','signatures'],
 witnessPacket:['statement','signature'],
 state:['status','forkReports','releaseRequested','restoredExternally']
};
export function ledgerEventDigest(statement){
 if(!own(statement)||JSON.stringify(statement).length>8192)
  throw Error('DA_UNBOUNDED_EVENT_STATEMENT');
 return sha(Buffer.from(DOMAIN+'event-digest/v1\n'+canonical(statement),'utf8'));
}
export function evidenceSigningBytes(kind,role,statement){
 if(!['incident-event','witness-head','replay'].includes(kind)||
    ![...OFFICERS,...WITNESSES].includes(role)||
    !own(statement)||JSON.stringify(statement).length>8192)
  throw Error('DA_UNTRUSTED_ROLE_OR_OVERSIZE_SIGNED_INPUT');
 return Buffer.from(DOMAIN+kind+'/'+role+'/v1\n'+canonical(statement),'utf8');
}
function validSigner(key){
 if(!own(key)||typeof key.publicKeyPem!=='string'||
    key.publicKeyPem.length>4096||!HEX.test(key.spkiSha256??'')||
    !ID.test(key.keyId??''))return false;
 try{
  const pub=createPublicKey(key.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   sha(pub.export({type:'spki',format:'der'}))===key.spkiSha256;
 }catch{return false;}
}
function signed(kind,role,statement,signature,key){
 if(!exact(signature,F.signature)||signature.role!==role||
    signature.keyId!==key?.keyId||signature.algorithm!=='Ed25519'||
    !SIG.test(signature.signature??'')||!validSigner(key))return false;
 try{
  const bytes=Buffer.from(signature.signature,'base64');
  return bytes.length===64&&bytes.toString('base64')===signature.signature&&
   verify(null,evidenceSigningBytes(kind,role,statement),
    createPublicKey(key.publicKeyPem),bytes);
 }catch{return false;}
}
function verifyPair(kind,statement,signatures,roles,keys,errors,code){
 if(!Array.isArray(signatures)||signatures.length!==2){
  errors.add(code+'_EXACT_PAIR_MISSING');return 0;
 }
 let n=0;
 const seen=new Set();
 for(const entry of signatures){
  if(!roles.includes(entry?.role)||seen.has(entry.role)){
   errors.add(code+'_ROLE_DUPLICATE_OR_UNKNOWN');continue;
  }
  seen.add(entry.role);
  if(signed(kind,entry.role,statement,entry,keys?.[entry.role]))n++;
  else errors.add(code+'_SIGNATURE_INVALID_'+entry.role);
 }
 if(seen.size!==2)errors.add(code+'_ROLE_QUORUM_MISSING');
 return n;
}
const hold=(errors,{validPrevious,matched,finalDigest,anchorVersion,incidentId})=>
 Object.freeze({
  phase:'1DA',schemaVersion:1,
  kind:'UNTRUSTED_APPEND_ONLY_INCIDENT_RECOVERY_REPLAY_LEDGER_HARD_HOLD',
  repository:REPO,
  prior1CZCandidateMathematicallyConsistent:validPrevious,
  candidateAppendOnlyIncidentLineageMathematicallyConsistent:
   errors.size===0&&validPrevious&&matched===12,
  candidateDetachedSignaturesMatched:matched,
  proposedAnchorVersion:count(anchorVersion)?anchorVersion:null,
  proposedFinalLedgerDigestSha256:HEX.test(finalDigest??'')?finalDigest:null,
  candidateIncidentBindingSha256:sha(canonical({
   repository:REPO,incidentId:typeof incidentId==='string'?incidentId:null,
   finalDigest:HEX.test(finalDigest??'')?finalDigest:null,
   signatures:matched
  })),
  anomalyCodes:Object.freeze([...errors].sort()),
  quarantineRequired:true,
  automaticRecoveryOrUnquarantineAllowed:false,
  independentlyAuthenticatedCorporateMandateSource:false,
  externallyImmutableAppendOnlyLedgerAndCasVerified:false,
  independentlyAuthenticatedWitnessArchiveAndForkGossip:false,
  actualWormObjectLockDeleteDenialAndRestorationVerified:false,
  independentlyApprovedIncidentBreakGlassAndLegalSignoffs:false,
  independentCcaRcaiEmudhraMcaCrLOcspProvenanceVerified:false,
  actualGithubRulesetsCodeownersNonauthorApprovalsVerified:false,
  oidcSlsaCiAndApprovedStagingVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
export function assessAppendOnlyIncidentReplay({
 czEvidence=null,anchor=null,events=[],witnessHeads=[],replay=null,
 replaySignatures=[],incidentState=null,now='2026-11-20T00:00:00.000Z'
}={}){
 const errors=new Set();
 const add=(ok,code)=>{if(!ok)errors.add(code);};
 const currentTime=stamp(now);
 add(Number.isFinite(currentTime),'DA_VERIFICATION_CLOCK_INVALID');
 let prior;
 try{prior=assessMandateForkRecoveryCandidate({...czEvidence,now});}catch{}
 const validPrevious=prior?.candidateMandateIncidentRecoveryMathematicallyConsistent===
  true&&prior?.quarantineRequired===true&&
  prior?.automaticRecoveryOrUnquarantineAllowed===false&&
  prior?.productionReleaseAuthorized===false&&prior?.releaseDecision==='HOLD';
 add(validPrevious,'DA_PRECEDING_1CZ_MANDATE_OR_QUARANTINE_INVALID');
 const incident=czEvidence?.incident,cy=czEvidence?.cyEvidence,
  head=cy?.manifest?.currentHeadSha,base=cy?.manifest?.mainBaseSha,
  checkpoint=incident?.nextCheckpointDigest,
  archive=incident?.archiveEvidenceSha256,
  objectVersion=czEvidence?.recovery?.statement?.objectVersion,
  officers=czEvidence?.authority?.officers,
  oldWitnesses=cy?.previous?.sources,
  nonce=cy?.manifest?.nonce,incidentId=incident?.incidentId;
 const anchorGood=exact(anchor,F.anchor)&&anchor.schemaVersion===1&&
  anchor.repository===REPO&&anchor.sourceHeadSha===head&&
  SHA.test(anchor.sourceHeadSha??'')&&anchor.incidentId===incidentId&&
  ID.test(anchor.storeId??'')&&count(anchor.ledgerVersion)&&
  anchor.ledgerVersion<Number.MAX_SAFE_INTEGER-4&&
  HEX.test(anchor.ledgerDigest??'')&&
  anchor.checkpointDigest===checkpoint&&
  Number.isFinite(stamp(anchor.observedAt))&&
  within(stamp(anchor.observedAt),currentTime)&&
  Number.isFinite(stamp(anchor.retentionUntil))&&
  stamp(anchor.retentionUntil)>currentTime+30*86400000;
 add(anchorGood,'DA_APPLICANT_HIGHWATERMARK_OR_RETENTION_INVALID');
 let previousDigest=anchor?.ledgerDigest;
 let previousTime=stamp(anchor?.observedAt);
 let matched=0;
 const expected=[
  prior?.unsignedCandidateIncidentDigestSha256,
  prior?.unsignedCandidateMandateDigestSha256,
  prior?.unsignedCandidateRecoveryDigestSha256,
  prior?.unsignedCandidateIncidentDigestSha256
 ];
 if(!Array.isArray(events)||events.length!==4)
  errors.add('DA_EXACT_FOUR_ORDERED_APPEND_EVENTS_REQUIRED');
 for(let i=0;i<4;i++){
  const stage=STAGES[i],packet=Array.isArray(events)?events[i]:null,
   statement=packet?.statement;
  const current=stamp(statement?.recordedAt);
  const good=exact(packet,F.packet)&&exact(statement,F.event)&&
   statement.schemaVersion===1&&statement.stage===stage&&
   statement.repository===REPO&&statement.sourceHeadSha===head&&
   statement.mainBaseSha===base&&statement.incidentId===incidentId&&
   statement.sequence===anchor?.ledgerVersion+i+1&&
   statement.previousDigest===previousDigest&&
   statement.checkpointDigest===checkpoint&&
   statement.archiveEvidenceSha256===archive&&
   statement.objectVersion===objectVersion&&
   statement.evidenceDigest===expected[i]&&HEX.test(expected[i]??'')&&
   statement.decision===(i===0?'QUARANTINE':'HOLD')&&
   within(current,currentTime)&&current>previousTime;
  add(good,'DA_APPEND_EVENT_SEQ_PREDECESSOR_BINDING_OR_CLOCK_INVALID_'+stage);
  if(exact(statement,F.event)){
   try{previousDigest=ledgerEventDigest(statement)}
   catch{previousDigest=null;}
  }else previousDigest=null;
  previousTime=current;
  matched+=verifyPair('incident-event',statement,packet?.signatures,
   EVENT_SIGNERS[stage],officers,errors,'DA_'+stage);
 }
 const finalDigest=previousDigest,finalSeq=anchor?.ledgerVersion+4;
 const witnesses=new Map();
 if(!Array.isArray(witnessHeads)||witnessHeads.length!==2)
  errors.add('DA_EXACT_TWO_PREVIOUS_WITNESS_HIGHWATERMARKS_REQUIRED');
 for(const packet of Array.isArray(witnessHeads)?witnessHeads:[]){
  const role=packet?.statement?.role;
  if(!WITNESSES.includes(role)||witnesses.has(role)){
   errors.add('DA_DUPLICATE_OR_UNREVIEWED_WITNESS_ROLE');continue;
  }
  witnesses.set(role,packet);
 }
 let lastWitnessTime=Number.NEGATIVE_INFINITY;
 for(const role of WITNESSES){
  const packet=witnesses.get(role),s=packet?.statement,
   old=oldWitnesses?.[role],observed=stamp(s?.observedAt);
  const key=old?{
   keyId:old.keyId,publicKeyPem:old.publicKeyPem,
   spkiSha256:old.signerSpkiSha256
  }:null;
  const good=exact(packet,F.witnessPacket)&&exact(s,F.witness)&&
   s.schemaVersion===1&&s.role===role&&s.repository===REPO&&
   s.sourceHeadSha===head&&s.incidentId===incidentId&&
   s.ledgerVersion===finalSeq&&s.ledgerDigest===finalDigest&&
   HEX.test(finalDigest??'')&&
   s.previousLedgerDigest===anchor?.ledgerDigest&&
   s.checkpointDigest===checkpoint&&s.nonce===nonce&&
   s.decision==='QUARANTINE'&&within(observed,currentTime)&&
   observed>previousTime&&
   signed('witness-head',role,s,packet?.signature,key);
  add(good,'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_'+role);
  if(good)matched++;
  lastWitnessTime=Math.max(lastWitnessTime,observed);
 }
 const rp=replay,started=stamp(rp?.startedAt),finished=stamp(rp?.finishedAt);
 const replayGood=exact(rp,F.replay)&&rp.schemaVersion===1&&
  rp.kind==='CANDIDATE_READ_ONLY_REPLAY_HOLD'&&rp.repository===REPO&&
  rp.sourceHeadSha===head&&rp.incidentId===incidentId&&
  rp.startingVersion===anchor?.ledgerVersion&&
  rp.startingDigest===anchor?.ledgerDigest&&
  rp.endingVersion===finalSeq&&rp.endingDigest===finalDigest&&
  HEX.test(finalDigest??'')&&rp.archiveEvidenceSha256===archive&&
  rp.objectVersion===objectVersion&&
  within(started,currentTime)&&within(finished,currentTime)&&
  started>lastWitnessTime&&finished>=started&&
  rp.rollbackAttempt===false&&rp.unquarantineRequested===false&&
  rp.releaseDecision==='HOLD';
 add(replayGood,'DA_REPLAY_ROLLBACK_ARCHIVE_OR_HOLD_INVALID');
 matched+=verifyPair('replay',rp,replaySignatures,
  ['INCIDENT_COMMANDER','RECOVERY_AUDITOR'],
  officers,errors,'DA_REHEARSAL_REPLAY');
 const stateGood=exact(incidentState,F.state)&&
  incidentState.status==='QUARANTINED'&&
  Array.isArray(incidentState.forkReports)&&
  incidentState.forkReports.length===0&&
  incidentState.releaseRequested===false&&
  incidentState.restoredExternally===false;
 add(stateGood,'DA_FORK_REPORT_OR_UNAUTHORIZED_RELEASE_QUARANTINED');
 return hold(errors,{validPrevious,matched,finalDigest,
  anchorVersion:anchor?.ledgerVersion,incidentId});
}
function boundedJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('DA_INVALID_OPERATOR_PACKET_PATH');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>262144)
  throw Error('DA_PACKET_NOT_BOUNDED_REGULAR_OFFREPO_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    args[0]!=='--inspect-incident-ledger')
  throw Error('DA_OPERATOR_ONLY_LOCAL_OFFLINE_READONLY_INSPECTION');
 const input=boundedJson(args[1]);
 const report=assessAppendOnlyIncidentReplay({
  ...input,now:new Date().toISOString()
 });
 console.log(JSON.stringify(report,null,2));
 if(!report.candidateAppendOnlyIncidentLineageMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main()}catch(error){
  console.error('DA independent ledger/replay remains external-auth HOLD:',
   error instanceof Error?error.message:'Unknown');process.exitCode=1;
 }
}
