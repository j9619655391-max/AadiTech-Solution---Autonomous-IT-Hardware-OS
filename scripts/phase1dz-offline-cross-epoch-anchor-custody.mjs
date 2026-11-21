import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DV_ROLES} from './phase1dv-offline-observer-publication-candidate.mjs';
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';
import {DX_SOURCES,DX_RECOVERY_ROLES,evidenceSetDigestDx,
 recoveryStepDigestDx} from './phase1dx-offline-evidence-incident-recovery.mjs';
import {DY_OVERSIGHT_ROLES,DY_REVIEW_ROLES,frozenCaseDigestDy,
 inventoryDigestDy,assessOfflineAdmissionUnfreezePreconditionsDy}
 from './phase1dy-offline-source-admission-unfreeze-preconditions.mjs';

// Applicant-controlled OFFLINE mathematical candidate checks only:
// no remote source, clock, signer enrollment, WORM lock, persistent CAS,
// delete-denial, actual incident intervention or production release operation.
export const DZ_ANCHOR_ROLES=Object.freeze([
 'ARCHIVE_ANCHOR_OBSERVER','RECOVERY_ANCHOR_COMPARATOR'
]);
export const DZ_CUSTODY_ROLES=Object.freeze([
 'LEGAL_CUSTODY_RECEIPT','SECURITY_CUSTODY_RECEIPT'
]);
const EVIDENCE_DOMAIN='aaditech/phase1dz/offline-evidence-bundle/v1\n';
const ANCHOR_DOMAIN='aaditech/phase1dz/epoch-anchor/v1\n';
const OBSERVER_DOMAIN='aaditech/phase1dz/epoch-anchor-observer/v1\n';
const CUSTODY_DOMAIN='aaditech/phase1dz/retention-hold-custodian/v1\n';
const TOP=['admissionCandidate','previousAnchor','epochs','anchorPins',
 'evidenceBundleBase64','custodyPins','custodyPackets','now'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const PREV=['sequence','digestSha256','observedAt'];
const PACKET=['statement','publicKeyPem','signature'];
const EPOCH=['record','observerPackets'];
const RECORD=['schemaVersion','kind','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','checkpointSha256',
 'archiveSha256','revocationDigestSha256','authorityInventorySha256',
 'frozenCaseSha256','sourceSetDigestSha256','recoveryLedgerDigestSha256',
 'previousSequence','sequence','previousDigestSha256',
 'evidenceBundleSha256','nonce','observedAt','decision'];
const OBS=[...RECORD,'role',...PIN,'anchorDigestSha256',
 'expiresAt','disposition'];
const CUSTODY=['schemaVersion','kind','role','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','previousAnchorSha256',
 'finalAnchorSha256','finalSequence','evidenceBundleSha256',
 'authorityInventorySha256','sourceSetDigestSha256','challengeNonce',
 ...PIN,'observedAt','expiresAt','retentionUntil','disposition'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HEX=/^[0-9a-f]{64}$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const HASH=x=>createHash('sha256').update(x).digest('hex');
const BOUND=(x,max)=>{try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}};
function UTC(s){
 if(typeof s!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s))
  return NaN;
 const n=Date.parse(s);
 return Number.isFinite(n)&&new Date(n).toISOString()===s?n:NaN;
}
function timeOK(s,expires,clock,min,allowFuture=300000){
 const t=UTC(s),x=UTC(expires);
 return Number.isFinite(t)&&Number.isFinite(x)&&
  Number.isFinite(clock)&&t>min&&t>=clock-900000&&
  t<=clock+allowFuture&&x>clock&&x>t&&x-t<=900000;
}
function PIN_OK(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  HEX.test(p.spkiSha256??'')&&ID.test(p.operatorId??'')&&
  ID.test(p.custodianOrganizationId??'');
}
function signed(packet,role,bytes){
 try{
  if(!EXACT(packet,PACKET)||!BOUND(packet,12288)||
   typeof packet.publicKeyPem!=='string'||
   packet.publicKeyPem.length>4096||!SIG.test(packet.signature??''))
   return false;
  const key=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&sig.length===64&&
   sig.toString('base64')===packet.signature&&
   HASH(key.export({format:'der',type:'spki'}))===
    packet.statement.spkiSha256&&
   verify(null,bytes(role,packet.statement),key,sig);
 }catch{return false;}
}
function decode(raw){
 if(typeof raw!=='string'||raw.length<4||raw.length>24576||
  !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw))
  return null;
 const b=Buffer.from(raw,'base64');
 return b.length>0&&b.length<=16384&&b.toString('base64')===raw?b:null;
}
export function evidenceBundleBytesDz(admission){
 const dx=admission?.rehearsalCandidate,expected=dx?.custodyCandidate?.
  publicationCandidate?.expected;
 const c=admission?.decisionCase;
 if(!OWN(expected)||!OWN(c))throw Error('DZ_COMPLETE_ADMISSION_REQUIRED');
 const sourceStatements=DX_SOURCES.map(role=>
  dx.sourceReceipts.find(p=>p?.statement?.role===role).statement);
 const bundle={
  repository:REPO,organizationId:expected.organizationId,
  sourceHeadSha:expected.sourceHeadSha,mainBaseSha:expected.mainBaseSha,
  checkpointSha256:expected.checkpointSha256,
  archiveSha256:expected.archiveSha256,
  revocationDigestSha256:expected.revocationDigestSha256,
  frozenCaseSha256:frozenCaseDigestDy(c),
  authorityInventorySha256:inventoryDigestDy(admission.authorityInventory),
  sourceSetDigestSha256:evidenceSetDigestDx(sourceStatements),
  recoveryLedgerDigestSha256:recoveryStepDigestDx(dx.recoverySteps.at(-1)),
  signedReviewStatementsSha256:HASH(canonical(
   DY_REVIEW_ROLES.map(role=>admission.reviewPackets.find(p=>
    p?.statement?.role===role).statement)))
 };
 if(!BOUND(bundle,8192))throw Error('DZ_EVIDENCE_BUNDLE_LIMIT');
 return Buffer.from(EVIDENCE_DOMAIN+canonical(bundle),'utf8');
}
export function anchorDigestDz(record){
 if(!EXACT(record,RECORD)||!BOUND(record,8192))
  throw Error('DZ_EXACT_ANCHOR_SCHEMA_REQUIRED');
 return HASH(ANCHOR_DOMAIN+canonical(record));
}
export function anchorSigningBytesDz(role,statement){
 if(!DZ_ANCHOR_ROLES.includes(role)||!EXACT(statement,OBS)||
  statement.role!==role||!BOUND(statement,8192))
  throw Error('DZ_ANCHOR_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(OBSERVER_DOMAIN+canonical(statement),'utf8');
}
export function custodySigningBytesDz(role,statement){
 if(!DZ_CUSTODY_ROLES.includes(role)||!EXACT(statement,CUSTODY)||
  statement.role!==role||!BOUND(statement,8192))
  throw Error('DZ_CUSTODY_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(CUSTODY_DOMAIN+canonical(statement),'utf8');
}
function keyDiversity(anchorPins,custodyPins,dy){
 if(!EXACT(anchorPins,DZ_ANCHOR_ROLES)||!
  EXACT(custodyPins,DZ_CUSTODY_ROLES))return false;
 const now=[
  ...DZ_ANCHOR_ROLES.map(role=>anchorPins[role]),
  ...DZ_CUSTODY_ROLES.map(role=>custodyPins[role])];
 if(!now.every(PIN_OK))return false;
 const dx=dy?.rehearsalCandidate,dw=dx?.custodyCandidate;
 const prior=[
  ...DY_OVERSIGHT_ROLES.map(role=>dy?.oversightPins?.[role]),
  ...DY_REVIEW_ROLES.map(role=>dy?.reviewPins?.[role]),
  ...DX_SOURCES.map(role=>dx?.sourcePins?.[role]),
  ...DX_RECOVERY_ROLES.map(role=>dx?.recoveryPins?.[role]),
  ...DW_ENROLLMENT_ROLES.map(role=>dw?.enrollmentPins?.[role]),
  ...DW_REVOCATION_ROLES.map(role=>dw?.revocationPins?.[role]),
  ...DV_ROLES.map(role=>dw?.publicationCandidate?.comparisonPins?.[role])
 ];
 const all=[...now,...prior];
 for(const k of ['keyId','spkiSha256','operatorId']){
  const values=all.map(p=>p?.[k]);
  if(values.some(x=>typeof x!=='string')||
   new Set(values).size!==values.length)return false;
 }
 const organizations=[
  ...now.map(p=>p.custodianOrganizationId),
  ...DY_OVERSIGHT_ROLES.map(r=>dy.oversightPins[r].custodianOrganizationId),
  ...DY_REVIEW_ROLES.map(r=>dy.reviewPins[r].custodianOrganizationId),
  ...DX_SOURCES.map(r=>dx.sourcePins[r].operatorOrganizationId),
  ...DX_RECOVERY_ROLES.map(r=>dx.recoveryPins[r].operatorOrganizationId),
  ...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins[r].custodianOrganizationId),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins[r].custodianOrganizationId)
 ];
 if(new Set(organizations).size!==organizations.length)return false;
 for(const epoch of dw?.publicationCandidate?.history?.epochs??[])
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   const witness=epoch?.checkpointObservations?.[0]?.witnesses?.[role];
   if(!witness||all.some(p=>p.keyId===witness.keyId||
    p.spkiSha256===witness.spkiSha256))return false;
  }
 return true;
}
function result(errors,detail={}){
 return Object.freeze({
  phase:'1DZ',schemaVersion:1,
  kind:'UNTRUSTED_CROSS_EPOCH_ANCHOR_FORK_AND_CUSTODY_HARD_HOLD',
  repository:REPO,
  previousDuToDyOriginalSignedHistoryReverifiedMathematicallyOnly:
   detail.previous===true,
  locallyLinkedCandidateAnchorEpochs:detail.epochs??0,
  mathematicallyVerifiedEpochWitnessSignatures:detail.witnesses??0,
  mathematicallyVerifiedRetentionCustodySignatures:detail.custody??0,
  suppliedEvidenceBundleBytesAgreeWithSourceDigestsOnly:
   detail.bundle===true,
  candidateCrossEpochAndRetentionClaimsCorrelatedMathematicallyOnly:
   detail.consistent===true,
  applicantOwnedPinsAnchorClockAndKeysNotIndependent:true,
  independentExternalSourceRetrievalActuallyPerformed:false,
  actualCrossSystemForkAbsenceOrGossipAuthenticated:false,
  externalWormRetentionOrObjectLockDenialTestVerified:false,
  independentlyPersistedAntiRollbackHighwatermarkVerified:false,
  authenticSignedLiveCrlOcspMcaMandateAndExternalTrustVerified:false,
  independentRealIncidentRestoreAndUnfreezeApprovalVerified:false,
  safeProductionSourceThawPossible:false,
  noRawEvidenceKeySignatureIdentityOrNonceInReport:true,
  productionMutationOrExternalCredentialEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Mathematically verifies *submitted* epoch views only; no authority. */
export function assessOfflineCrossEpochAnchorCustodyDz(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!BOUND(args,2048*1024)){
  errors.add('DZ_EXACT_BOUNDED_INPUT_REQUIRED');
  return result(errors);
 }
 const {admissionCandidate:dy,previousAnchor,epochs,anchorPins,
  evidenceBundleBase64,custodyPins,custodyPackets,now}=args;
 const clock=UTC(now);
 if(!Number.isFinite(clock))errors.add('DZ_EXPLICIT_UTC_CLOCK_REQUIRED');
 let dyOK=false;
 try{
  const r=assessOfflineAdmissionUnfreezePreconditionsDy(dy);
  dyOK=dy?.now===now&&
   r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly&&
   r.anomalyCodes.length===0;
 }catch{dyOK=false;}
 if(!dyOK)errors.add('DZ_DY_FULL_HISTORY_UNVERIFIED');
 const dx=dy?.rehearsalCandidate,c=dy?.decisionCase;
 const expected=dx?.custodyCandidate?.publicationCandidate?.expected;
 const pinsOK=dyOK&&keyDiversity(anchorPins,custodyPins,dy);
 if(!pinsOK)errors.add('DZ_ROLE_KEY_OPERATOR_OR_CUSTODY_COLLISION');
 const anchorOK=EXACT(previousAnchor,PREV)&&
  Number.isSafeInteger(previousAnchor.sequence)&&
  previousAnchor.sequence>0&&previousAnchor.sequence<1_000_000_000&&
  HEX.test(previousAnchor.digestSha256??'')&&
  Number.isFinite(UTC(previousAnchor.observedAt))&&
  Number.isFinite(clock)&&
  UTC(previousAnchor.observedAt)>=clock-900000&&
  UTC(previousAnchor.observedAt)<=clock+300000&&
  previousAnchor.sequence===c?.observationSequence&&
  previousAnchor.digestSha256===(
   dyOK?frozenCaseDigestDy(c):null)&&
  Array.isArray(dy?.reviewPackets)&&
  dy.reviewPackets.every(p=>UTC(p?.statement?.observedAt)<=
   UTC(previousAnchor.observedAt));
 if(!anchorOK)errors.add('DZ_PREVIOUS_ANCHOR_DY_CUSTODY_MISMATCH');
 let bundleOK=false,bundleSha=null;
 try{
  const submitted=decode(evidenceBundleBase64),
   expectedBytes=dyOK?evidenceBundleBytesDz(dy):null;
  bundleOK=submitted!==null&&expectedBytes!==null&&
   submitted.equals(expectedBytes);
  if(bundleOK)bundleSha=HASH(submitted);
 }catch{bundleOK=false;}
 if(!bundleOK)errors.add('DZ_BUNDLE_BYTES_NOT_SOURCE_BOUND');
 const arrayOK=Array.isArray(epochs)&&epochs.length>=2&&epochs.length<=4;
 if(!arrayOK)errors.add('DZ_TWO_TO_FOUR_EXACT_EPOCHS_REQUIRED');
 let linked=arrayOK&&anchorOK&&bundleOK,seenW=0;
 let seq=anchorOK?previousAnchor.sequence:null;
 let previousHash=anchorOK?previousAnchor.digestSha256:null,
  previousTime=anchorOK?UTC(previousAnchor.observedAt):NaN;
 const nonceSet=new Set([expected?.challengeNonce,c?.reviewNonce]);
 if(arrayOK)for(const e of epochs){
  const record=e?.record;
  if(!EXACT(e,EPOCH)||!EXACT(record,RECORD)||!BOUND(e,30000)){
   errors.add('DZ_EPOCH_RECORD_SCHEMA_INVALID');linked=false;continue;
  }
  const scopeOK=dyOK&&record.schemaVersion===1&&
   record.kind==='UNTRUSTED_OFFLINE_CROSS_EPOCH_ANCHOR'&&
   record.repository===REPO&&record.incidentId===c?.incidentId&&
   ['organizationId','sourceHeadSha','mainBaseSha','checkpointSha256',
    'archiveSha256','revocationDigestSha256'].every(k=>
    record[k]===expected?.[k])&&
   record.authorityInventorySha256===c?.authorityInventorySha256&&
   record.frozenCaseSha256===frozenCaseDigestDy(c)&&
   record.sourceSetDigestSha256===c?.evidenceSetDigestSha256&&
   record.recoveryLedgerDigestSha256===c?.recoveryLedgerDigestSha256&&
   record.evidenceBundleSha256===bundleSha&&
   record.decision==='HOLD'&&
   Number.isSafeInteger(record.previousSequence)&&
   Number.isSafeInteger(record.sequence)&&
   record.previousSequence===seq&&record.sequence===seq+1&&
   record.previousDigestSha256===previousHash&&
   HEX.test(record.nonce??'')&&record.nonce!=='0'.repeat(64)&&
   !nonceSet.has(record.nonce)&&
   Number.isFinite(UTC(record.observedAt))&&
   UTC(record.observedAt)>previousTime&&
   UTC(record.observedAt)<=clock+300000&&
   UTC(record.observedAt)>=clock-900000;
  if(!scopeOK){errors.add('DZ_EPOCH_FORK_ROLLBACK_OR_SCOPE_MISMATCH');linked=false;}
  nonceSet.add(record.nonce);
  const epochSha=anchorDigestDz(record);
  const packets=e.observerPackets;
  if(!Array.isArray(packets)||packets.length!==2){
   errors.add('DZ_TWO_SIGNED_EPOCH_VIEWS_REQUIRED');linked=false;
  }else{
   const used=new Set();
   for(const p of packets){
    const s=p?.statement,role=s?.role;
    if(!DZ_ANCHOR_ROLES.includes(role)||used.has(role)||
     !EXACT(p,PACKET)||!EXACT(s,OBS)){
     errors.add('DZ_EPOCH_OBSERVER_PACKET_INVALID');linked=false;continue;
    }
    used.add(role);
    const pin=anchorPins?.[role];
    if(!PIN_OK(pin)||PIN.some(k=>s[k]!==pin[k])){
     errors.add('DZ_EPOCH_WITNESS_PIN_MISMATCH');linked=false;
    }
    const same=RECORD.every(k=>s[k]===record[k])&&
     s.anchorDigestSha256===epochSha&&
     s.disposition==='OBSERVE_HOLD_ONLY';
    if(!same){
     errors.add('DZ_SIGNED_CROSS_VIEW_EQUIVOCATION');linked=false;
    }
    if(!timeOK(s.observedAt,s.expiresAt,clock,previousTime)){
     errors.add('DZ_EPOCH_WITNESS_TIME_OR_EXPIRY_INVALID');linked=false;
    }
    if(!signed(p,role,anchorSigningBytesDz)){
     errors.add('DZ_EPOCH_SIGNATURE_OR_SPKI_INVALID');linked=false;
    }else seenW++;
   }
   if(used.size!==2){
    errors.add('DZ_EPOCH_WITNESS_QUORUM_INCOMPLETE');linked=false;
   }
  }
  seq=record.sequence;previousHash=epochSha;
  previousTime=UTC(record.observedAt);
 }
 const custodyOK=Array.isArray(custodyPackets)&&
  custodyPackets.length===2&&EXACT(custodyPins,DZ_CUSTODY_ROLES);
 if(!custodyOK)errors.add('DZ_TWO_CUSTODY_HOLD_RECEIPTS_REQUIRED');
 const requiredRetain=clock+30*86400*1000;
 const seenC=new Set();
 let seenCustody=0;
 if(custodyOK)for(const packet of custodyPackets){
  const s=packet?.statement,role=s?.role;
  if(!DZ_CUSTODY_ROLES.includes(role)||seenC.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,CUSTODY)){
   errors.add('DZ_CUSTODY_ROLE_PACKET_INVALID');continue;
  }
  seenC.add(role);
  const pin=custodyPins[role];
  if(!PIN_OK(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('DZ_CUSTODY_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_EVIDENCE_RETENTION_CANDIDATE'||
   s.disposition!=='RETAIN_HOLD_NO_DELETE'||s.repository!==REPO||
   s.incidentId!==c?.incidentId||
   s.organizationId!==expected?.organizationId||
   s.sourceHeadSha!==expected?.sourceHeadSha||
   s.mainBaseSha!==expected?.mainBaseSha||
   s.previousAnchorSha256!==previousAnchor?.digestSha256||
   s.finalAnchorSha256!==previousHash||
   s.finalSequence!==seq||s.evidenceBundleSha256!==bundleSha||
   s.authorityInventorySha256!==c?.authorityInventorySha256||
   s.sourceSetDigestSha256!==c?.evidenceSetDigestSha256||
   s.challengeNonce!==c?.reviewNonce||!linked)
   errors.add('DZ_CUSTODY_FINAL_ANCHOR_OR_HOLD_SCOPE_INVALID');
  if(!timeOK(s.observedAt,s.expiresAt,clock,previousTime)||
   !Number.isFinite(UTC(s.retentionUntil))||
   UTC(s.retentionUntil)<requiredRetain||
   UTC(s.retentionUntil)>clock+10*366*86400*1000)
   errors.add('DZ_CUSTODY_RETENTION_CLAIM_OR_CLOCK_INVALID');
  if(!signed(packet,role,custodySigningBytesDz))
   errors.add('DZ_CUSTODY_SIGNATURE_OR_SPKI_INVALID');
  else seenCustody++;
 }
 if(custodyOK&&seenC.size!==2)
  errors.add('DZ_CUSTODY_SIGNER_QUORUM_INCOMPLETE');
 if(custodyOK&&seenC.size===2){
  const [a,b]=DZ_CUSTODY_ROLES.map(role=>
   custodyPackets.find(p=>p.statement?.role===role).statement);
  if(a.retentionUntil!==b.retentionUntil){
   errors.add('DZ_CUSTODY_RETENTION_SPLIT_VIEW');linked=false;
  }
 }
 const consistent=dyOK&&pinsOK&&anchorOK&&bundleOK&&linked&&
  seenW===epochs?.length*2&&seenCustody===2&&errors.size===0;
 return result(errors,{previous:dyOK,epochs:linked?epochs?.length:0,
  witnesses:seenW,custody:seenCustody,bundle:bundleOK,consistent});
}
