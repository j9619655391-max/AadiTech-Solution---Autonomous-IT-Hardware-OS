import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DV_ROLES} from './phase1dv-offline-observer-publication-candidate.mjs';
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';
import {DX_SOURCES,DX_RECOVERY_ROLES}
 from './phase1dx-offline-evidence-incident-recovery.mjs';
import {DY_OVERSIGHT_ROLES,DY_REVIEW_ROLES}
 from './phase1dy-offline-source-admission-unfreeze-preconditions.mjs';
import {DZ_ANCHOR_ROLES,DZ_CUSTODY_ROLES,anchorDigestDz}
 from './phase1dz-offline-cross-epoch-anchor-custody.mjs';
import {EA_PEER_ROLES,EA_FREEZE_ROLES,candidateEpochViewEa,
 epochViewDigestEa,admissionClaimDigestEa,
 assessOfflineGossipAdmissionBoundaryEa}
 from './phase1ea-offline-gossip-admission-boundary.mjs';

// No network access, approved provider, trusted time or durable external state.
// A complete synthetic transcript is never proof of actual independent gossip.
export const EB_RUN_ROLES=Object.freeze([
 'RUN1_ARCHIVE','RUN1_REGISTRY','RUN1_RECOVERY',
 'RUN2_ARCHIVE','RUN2_REGISTRY','RUN2_RECOVERY'
]);
export const EB_CUSTODY_ROLES=Object.freeze([
 'LEGAL_INCIDENT_RETENTION','SECURITY_INCIDENT_RETENTION'
]);
const HANDOFF_DOMAIN='aaditech/phase1eb/applicant-gossip-handoff/v1\n';
const RUN_DOMAIN='aaditech/phase1eb/cross-run-freeze-record/v1\n';
const PEER_DOMAIN='aaditech/phase1eb/cross-run-signed-peer/v1\n';
const CUSTODY_DOMAIN='aaditech/phase1eb/incident-custody-receipt/v1\n';
const TOP=['gossipCandidate','previousRunAnchor','runs','peerPins',
 'custodyPins','custodyPackets','now'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const ANCHOR=['sequence','digestSha256','observedAt'];
const RECORD=['schemaVersion','kind','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','finalSequence',
 'finalAnchorSha256','evidenceBundleSha256','epochViewSha256',
 'priorGossipHandoffSha256','previousRunSequence','sequence',
 'previousDigestSha256','nonce','observedAt','decision'];
const PEER=[...RECORD,'role',...PIN,'recordSha256',
 'expiresAt','observedAtPeer','disposition'];
const PACKET=['statement','publicKeyPem','signature'];
const RUN=['record','peerPackets'];
const CUSTODY=['schemaVersion','kind','role','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','priorGossipHandoffSha256',
 'previousAnchorSha256','firstRunSha256','finalRunSha256','finalSequence',
 'epochViewSha256','evidenceBundleSha256','challengeNonce',...PIN,
 'observedAt','expiresAt','retentionUntil','disposition'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,k)=>OWN(x)&&Object.keys(x).length===k.length&&
 k.every(y=>Object.hasOwn(x,y));
const HEX=/^[0-9a-f]{64}$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const HASH=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,n){try{
 const s=JSON.stringify(x);return typeof s==='string'&&
  Buffer.byteLength(s,'utf8')<=n;
}catch{return false;}}
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function fresh(observed,expires,clock,after){
 const t=utc(observed),x=utc(expires);
 return Number.isFinite(t)&&Number.isFinite(x)&&
  Number.isFinite(clock)&&t>after&&t>=clock-900000&&
  t<=clock+300000&&x>clock&&x>t&&x-t<=900000;
}
function pinOK(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  HEX.test(p.spkiSha256??'')&&ID.test(p.operatorId??'')&&
  ID.test(p.custodianOrganizationId??'');
}
function signed(p,role,fn){
 try{
  if(!EXACT(p,PACKET)||!bounded(p,12288)||
   typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>4096||
   !SIG.test(p.signature??''))return false;
  const k=createPublicKey(p.publicKeyPem),s=Buffer.from(p.signature,'base64');
  return k.asymmetricKeyType==='ed25519'&&s.length===64&&
   s.toString('base64')===p.signature&&
   HASH(k.export({format:'der',type:'spki'}))===
    p.statement.spkiSha256&&
   verify(null,fn(role,p.statement),k,s);
 }catch{return false;}
}
/** A caller-supplied previous gossip transcript, NOT an external durable anchor. */
export function gossipHandoffDigestEb(ea){
 const dz=ea?.anchorCandidate;
 const proof={
  repository:REPO,sourceHeadSha:dz?.admissionCandidate?.decisionCase?.sourceHeadSha,
  incidentId:dz?.admissionCandidate?.decisionCase?.incidentId,
  previousCursor:ea?.previousGossipCursor,
  finalAnchorSha256:anchorDigestDz(dz.epochs.at(-1).record),
  epochViewSha256:epochViewDigestEa(candidateEpochViewEa(dz)),
  admissionClaimSha256:admissionClaimDigestEa(ea.admissionClaim),
  peerStatements:EA_PEER_ROLES.map(role=>
   ea.peerPackets.find(p=>p?.statement?.role===role).statement),
  frozenReviewStatements:EA_FREEZE_ROLES.map(role=>
   ea.freezePackets.find(p=>p?.statement?.role===role).statement)
 };
 if(!bounded(proof,26000))throw Error('EB_GOSSIP_HANDOFF_BOUNDS');
 return HASH(HANDOFF_DOMAIN+canonical(proof));
}
export function runDigestEb(record){
 if(!EXACT(record,RECORD)||!bounded(record,8192))
  throw Error('EB_EXACT_RUN_RECORD_REQUIRED');
 return HASH(RUN_DOMAIN+canonical(record));
}
export function runPeerSigningBytesEb(role,statement){
 if(!EB_RUN_ROLES.includes(role)||!EXACT(statement,PEER)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('EB_EXACT_RUN_PEER_SCOPE_REQUIRED');
 return Buffer.from(PEER_DOMAIN+canonical(statement),'utf8');
}
export function custodySigningBytesEb(role,statement){
 if(!EB_CUSTODY_ROLES.includes(role)||!EXACT(statement,CUSTODY)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('EB_EXACT_CUSTODY_HOLD_SCOPE_REQUIRED');
 return Buffer.from(CUSTODY_DOMAIN+canonical(statement),'utf8');
}
function diverse(peerPins,custodyPins,ea){
 if(!EXACT(peerPins,EB_RUN_ROLES)||!
  EXACT(custodyPins,EB_CUSTODY_ROLES))return false;
 const own=[...EB_RUN_ROLES.map(r=>peerPins[r]),
  ...EB_CUSTODY_ROLES.map(r=>custodyPins[r])];
 if(!own.every(pinOK))return false;
 const dz=ea?.anchorCandidate,dy=dz?.admissionCandidate,
  dx=dy?.rehearsalCandidate,dw=dx?.custodyCandidate;
 const previous=[
  ...EA_PEER_ROLES.map(r=>ea?.peerPins?.[r]),
  ...EA_FREEZE_ROLES.map(r=>ea?.freezePins?.[r]),
  ...DZ_ANCHOR_ROLES.map(r=>dz?.anchorPins?.[r]),
  ...DZ_CUSTODY_ROLES.map(r=>dz?.custodyPins?.[r]),
  ...DY_OVERSIGHT_ROLES.map(r=>dy?.oversightPins?.[r]),
  ...DY_REVIEW_ROLES.map(r=>dy?.reviewPins?.[r]),
  ...DX_SOURCES.map(r=>dx?.sourcePins?.[r]),
  ...DX_RECOVERY_ROLES.map(r=>dx?.recoveryPins?.[r]),
  ...DW_ENROLLMENT_ROLES.map(r=>dw?.enrollmentPins?.[r]),
  ...DW_REVOCATION_ROLES.map(r=>dw?.revocationPins?.[r]),
  ...DV_ROLES.map(r=>dw?.publicationCandidate?.comparisonPins?.[r])
 ];
 const all=[...own,...previous];
 for(const field of ['keyId','spkiSha256','operatorId']){
  const vals=all.map(p=>p?.[field]);
  if(vals.some(v=>typeof v!=='string')||
   new Set(vals).size!==vals.length)return false;
 }
 const orgs=[
  ...own.map(p=>p.custodianOrganizationId),
  ...EA_PEER_ROLES.map(r=>ea.peerPins[r].custodianOrganizationId),
  ...EA_FREEZE_ROLES.map(r=>ea.freezePins[r].custodianOrganizationId),
  ...DZ_ANCHOR_ROLES.map(r=>dz.anchorPins[r].custodianOrganizationId),
  ...DZ_CUSTODY_ROLES.map(r=>dz.custodyPins[r].custodianOrganizationId),
  ...DY_OVERSIGHT_ROLES.map(r=>dy.oversightPins[r].custodianOrganizationId),
  ...DY_REVIEW_ROLES.map(r=>dy.reviewPins[r].custodianOrganizationId),
  ...DX_SOURCES.map(r=>dx.sourcePins[r].operatorOrganizationId),
  ...DX_RECOVERY_ROLES.map(r=>dx.recoveryPins[r].operatorOrganizationId),
  ...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins[r].custodianOrganizationId),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins[r].custodianOrganizationId)
 ];
 if(new Set(orgs).size!==orgs.length)return false;
 for(const epoch of dw?.publicationCandidate?.history?.epochs??[])
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   const w=epoch?.checkpointObservations?.[0]?.witnesses?.[role];
   if(!w||all.some(p=>p.keyId===w.keyId||
    p.spkiSha256===w.spkiSha256))return false;
  }
 return true;
}
function report(codes,detail={}){
 return Object.freeze({
  phase:'1EB',schemaVersion:1,
  kind:'OFFLINE_CROSS_RUN_GOSSIP_INCIDENT_CUSTODY_HARD_HOLD',
  repository:REPO,
  previousEaToDuFullCandidateReverifiedMathematicallyOnly:
   detail.prior===true,
  locallyLinkedSecondRunCount:detail.runs??0,
  mathematicallyVerifiedSixRunWitnessSignatures:detail.peers??0,
  mathematicallyVerifiedTwoIncidentRetentionSignatures:detail.custody??0,
  submittedCrossRunForkReplayAndCustodyInternallyConsistentOnly:
   detail.consistent===true,
  priorGossipAnchorAndClockAreApplicantControlled:true,
  realRemoteGossipAndAntiEquivocationGossipPerformed:false,
  externallyPersistedSignedHighwatermarkOrCasVerified:false,
  actualDurableWormRetentionDeleteDenialOrDrRestoreVerified:false,
  realProviderMcaLegalRcaIEdmudhraCcaIssuerTrustVerified:false,
  freshLiveSignedIssuerCrlOcspAuthenticated:false,
  independentLegalSecurityProductionUnfreezeApproval:false,
  noRawEvidencePublicKeysIdentityHashesOrNoncesReturned:true,
  productionSourceActivationOrExternalEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...codes].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Read-only validation of EXACT caller-supplied two-run candidate transcript. */
export function assessOfflineCrossRunGossipIncidentCustodyEb(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,3072*1024)){
  errors.add('EB_EXACT_BOUNDED_INPUT_REQUIRED');return report(errors);
 }
 const {gossipCandidate:ea,previousRunAnchor,runs,peerPins,custodyPins,
  custodyPackets,now}=args;
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('EB_EXPLICIT_UTC_CLOCK_REQUIRED');
 let prior=false,handoff=null,viewSha=null;
 try{
  const p=assessOfflineGossipAdmissionBoundaryEa(ea);
  prior=ea?.now===now&&p.localGossipReplayAndForkCandidateInternallyConsistentOnly&&
   p.anomalyCodes.length===0;
  if(prior){
   handoff=gossipHandoffDigestEb(ea);
   viewSha=epochViewDigestEa(candidateEpochViewEa(ea.anchorCandidate));
  }
 }catch{prior=false;}
 if(!prior)errors.add('EB_PREVIOUS_EA_ORIGINAL_HISTORY_NOT_REVERIFIED');
 const dz=ea?.anchorCandidate,dy=dz?.admissionCandidate,
  original=dy?.decisionCase,first=Array.isArray(dz?.epochs)?
   dz.epochs.at(-1)?.record:null;
 const expected=dy?.rehearsalCandidate?.custodyCandidate?.
  publicationCandidate?.expected;
 let lastReview=-Infinity;
 if(prior)for(const p of ea.freezePackets)
  lastReview=Math.max(lastReview,utc(p.statement.observedAt));
 const anchorOK=EXACT(previousRunAnchor,ANCHOR)&&
  Number.isSafeInteger(previousRunAnchor.sequence)&&
  previousRunAnchor.sequence>0&&previousRunAnchor.sequence<1_000_000_000&&
  HEX.test(previousRunAnchor.digestSha256??'')&&
  previousRunAnchor.digestSha256===handoff&&
  previousRunAnchor.sequence===first?.sequence&&
  Number.isFinite(utc(previousRunAnchor.observedAt))&&
  utc(previousRunAnchor.observedAt)>=lastReview&&
  utc(previousRunAnchor.observedAt)>=clock-900000&&
  utc(previousRunAnchor.observedAt)<=clock+300000;
 if(!anchorOK)errors.add('EB_PREVIOUS_GOSSIP_HANDOFF_ROLLBACK_OR_DRIFT');
 const independent=prior&&diverse(peerPins,custodyPins,ea);
 if(!independent)errors.add('EB_CROSS_RUN_SIGNER_KEY_OR_ORGANIZATION_REUSE');
 const exactRuns=Array.isArray(runs)&&runs.length===2;
 if(!exactRuns)errors.add('EB_EXACT_TWO_RUNS_REQUIRED');
 let seq=anchorOK?previousRunAnchor.sequence:null,
  previousHash=anchorOK?previousRunAnchor.digestSha256:null,
  previousTime=anchorOK?utc(previousRunAnchor.observedAt):NaN,
  seenPeers=0,firstRunSha=null,finalRunSha=null;
 const usedNonces=new Set([
  original?.challengeNonce,original?.reviewNonce,
  ...((Array.isArray(dz?.epochs)?dz.epochs:[]).map(x=>x?.record?.nonce)),
  ...((Array.isArray(ea?.peerPackets)?ea.peerPackets:[])
   .map(x=>x?.statement?.challengeNonce))
 ]);
 let validChain=exactRuns&&anchorOK&&prior&&independent;
 if(exactRuns)for(let i=0;i<2;i++){
  const run=runs[i],rec=run?.record;
  if(!EXACT(run,RUN)||!EXACT(rec,RECORD)||!bounded(run,47000)){
   errors.add('EB_RUN_RECORD_SCHEMA_OR_SIZE_INVALID');validChain=false;continue;
  }
  const ok=prior&&rec.schemaVersion===1&&
   rec.kind==='UNTRUSTED_OFFLINE_GOSSIP_REPLAY_FREEZE'&&
   rec.repository===REPO&&rec.incidentId===original?.incidentId&&
   rec.organizationId===expected?.organizationId&&
   rec.sourceHeadSha===expected?.sourceHeadSha&&
   rec.mainBaseSha===expected?.mainBaseSha&&
   rec.finalSequence===first?.sequence&&
   rec.finalAnchorSha256===anchorDigestDz(first)&&
   rec.evidenceBundleSha256===first?.evidenceBundleSha256&&
   rec.epochViewSha256===viewSha&&
   rec.priorGossipHandoffSha256===handoff&&
   Number.isSafeInteger(rec.sequence)&&
   Number.isSafeInteger(rec.previousRunSequence)&&
   rec.previousRunSequence===seq&&rec.sequence===seq+1&&
   rec.previousDigestSha256===previousHash&&
   HEX.test(rec.nonce??'')&&rec.nonce!=='0'.repeat(64)&&
   !usedNonces.has(rec.nonce)&&
   Number.isFinite(utc(rec.observedAt))&&
   utc(rec.observedAt)>previousTime&&
   utc(rec.observedAt)>=clock-900000&&
   utc(rec.observedAt)<=clock+300000&&rec.decision==='HOLD';
  if(!ok){
   errors.add('EB_RUN_ROLLBACK_FORK_REPLAY_OR_SCOPE_MISMATCH');
   validChain=false;
  }
  usedNonces.add(rec.nonce);
  let digest=null;
  try{digest=runDigestEb(rec);}
  catch{errors.add('EB_RUN_RECORD_SCHEMA_OR_SIZE_INVALID');validChain=false;continue;}
  if(i===0)firstRunSha=digest;
  else finalRunSha=digest;
  if(!Array.isArray(run.peerPackets)||run.peerPackets.length!==3){
   errors.add('EB_EXACT_THREE_PEERS_PER_RUN_REQUIRED');validChain=false;
  }else{
   const used=new Set();
   for(const packet of run.peerPackets){
    const stmt=packet?.statement,role=stmt?.role;
    if(!EB_RUN_ROLES.slice(i*3,i*3+3).includes(role)||
     used.has(role)||!EXACT(packet,PACKET)||
     !EXACT(stmt,PEER)||!bounded(packet,12288)){
     errors.add('EB_RUN_PEER_ROLE_OR_SCHEMA_INVALID');validChain=false;continue;
    }
    used.add(role);
    const pin=peerPins?.[role];
    if(!pinOK(pin)||PIN.some(k=>stmt[k]!==pin[k])){
     errors.add('EB_RUN_PEER_DETACHED_PIN_MISMATCH');validChain=false;
    }
    if(!RECORD.every(k=>stmt[k]===rec[k])||
     stmt.recordSha256!==digest||
     stmt.disposition!=='OBSERVE_FROZEN_ONLY'){
     errors.add('EB_SIGNED_INTER_RUN_PEER_FORK');validChain=false;
    }
    if(!fresh(stmt.observedAtPeer,stmt.expiresAt,clock,
      utc(rec.observedAt))){
     errors.add('EB_RUN_PEER_TIME_OR_EXPIRY_INVALID');validChain=false;
    }
    if(!signed(packet,role,runPeerSigningBytesEb)){
     errors.add('EB_RUN_PEER_SIGNATURE_OR_SPKI_INVALID');validChain=false;
    }else seenPeers++;
   }
   if(used.size!==3){
    errors.add('EB_THREE_DISTINCT_PEERS_PER_RUN_REQUIRED');validChain=false;
   }
  }
  const peerTimes=Array.isArray(run.peerPackets)?
   run.peerPackets.map(x=>utc(x?.statement?.observedAtPeer)):[];
  const latest=Math.max(utc(rec.observedAt),...peerTimes);
  seq=rec.sequence;previousHash=digest;
  previousTime=Number.isFinite(latest)?latest:NaN;
 }
 const custodyShape=Array.isArray(custodyPackets)&&
  custodyPackets.length===2&&EXACT(custodyPins,EB_CUSTODY_ROLES);
 if(!custodyShape)errors.add('EB_EXACT_TWO_CUSTODY_HOLD_PACKETS_REQUIRED');
 let signedCustody=0;
 const seenC=new Set();
 if(custodyShape)for(const packet of custodyPackets){
  const s=packet?.statement,role=s?.role;
  if(!EB_CUSTODY_ROLES.includes(role)||seenC.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,CUSTODY)||
   !bounded(packet,12288)){
   errors.add('EB_CUSTODY_ROLE_OR_SCHEMA_INVALID');continue;
  }
  seenC.add(role);
  if(!pinOK(custodyPins?.[role])||
   PIN.some(k=>s[k]!==custodyPins[role][k]))
   errors.add('EB_CUSTODY_DETACHED_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_INCIDENT_REPLAY_RETENTION'||
   s.disposition!=='RETAIN_QUARANTINE_HOLD_NO_UNFREEZE'||
   s.repository!==REPO||s.incidentId!==original?.incidentId||
   s.organizationId!==expected?.organizationId||
   s.sourceHeadSha!==expected?.sourceHeadSha||
   s.mainBaseSha!==expected?.mainBaseSha||
   s.priorGossipHandoffSha256!==handoff||
   s.previousAnchorSha256!==previousRunAnchor?.digestSha256||
   s.firstRunSha256!==firstRunSha||
   s.finalRunSha256!==finalRunSha||
   s.finalSequence!==seq||s.epochViewSha256!==viewSha||
   s.evidenceBundleSha256!==first?.evidenceBundleSha256||
   s.challengeNonce!==original?.reviewNonce||!validChain)
   errors.add('EB_CUSTODY_RUN_HANDOFF_OR_UNFREEZE_MISMATCH');
  if(!fresh(s.observedAt,s.expiresAt,clock,previousTime)||
   !Number.isFinite(utc(s.retentionUntil))||
   utc(s.retentionUntil)<clock+30*86400*1000||
   utc(s.retentionUntil)>clock+10*366*86400*1000)
   errors.add('EB_CUSTODY_TIME_OR_RETENTION_INVALID');
  if(!signed(packet,role,custodySigningBytesEb))
   errors.add('EB_CUSTODY_SIGNATURE_OR_SPKI_INVALID');
  else signedCustody++;
 }
 if(custodyShape&&seenC.size!==2)
  errors.add('EB_CUSTODY_ROLE_QUORUM_INCOMPLETE');
 if(custodyShape&&seenC.size===2){
  const [a,b]=EB_CUSTODY_ROLES.map(role=>
   custodyPackets.find(p=>p?.statement?.role===role).statement);
  if(a.retentionUntil!==b.retentionUntil)
   errors.add('EB_CUSTODY_RETENTION_SPLIT_VIEW');
 }
 const consistent=prior&&anchorOK&&independent&&validChain&&
  seenPeers===6&&signedCustody===2&&errors.size===0;
 return report(errors,{prior,runs:validChain?2:0,peers:seenPeers,
  custody:signedCustody,consistent});
}
