import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DV_ROLES} from './phase1dv-offline-observer-publication-candidate.mjs';
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';
import {DX_SOURCES,DX_RECOVERY_ROLES,evidenceSetDigestDx,
 recoveryStepDigestDx,assessOfflineEvidenceIncidentRecoveryCandidate}
 from './phase1dx-offline-evidence-incident-recovery.mjs';

// Phase 1DY admits NO real credentials, external trust, source access, storage
// persistence, release decision or live incident unfreeze. Every signature,
// previous anchor, organization claim and clock below is caller-controlled.
export const DY_REQUIRED_GATES=Object.freeze([
 'PROVIDER_WRITTEN_AGREEMENT','APPROVED_SANDBOX_CREDENTIAL_CUSTODY',
 'CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY','LIVE_ISSUER_SIGNED_CRL_OCSP',
 'MCA_LEGAL_AND_SIGNATORY_MANDATE','INDEPENDENT_KEY_ENROLLMENT',
 'AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES','WORM_CAS_SIGNED_ANTI_EQUIVOCATION',
 'TRUSTED_TIMESTAMP_SOURCE','INDEPENDENT_DR_RESTORE_ACCEPTANCE',
 'PROTECTED_MAIN_NONAUTHOR_REVIEWS','INDEPENDENT_STAGING_RELEASE_SIGNOFF'
]);
export const DY_OVERSIGHT_ROLES=Object.freeze([
 'SOURCE_INTEGRITY_OVERSIGHT','RECOVERY_FREEZE_OVERSIGHT'
]);
export const DY_REVIEW_ROLES=Object.freeze([
 'LEGAL_UNFREEZE_REVIEW','SECURITY_UNFREEZE_REVIEW',
 'OPERATIONS_UNFREEZE_REVIEW'
]);
const INV_DOMAIN='aaditech/phase1dy/authority-precondition-inventory/v1\n';
const CASE_DOMAIN='aaditech/phase1dy/frozen-incident-case/v1\n';
const OBS_DOMAIN='aaditech/phase1dy/oversight-observation/v1\n';
const SET_DOMAIN='aaditech/phase1dy/dual-oversight-set/v1\n';
const REVIEW_DOMAIN='aaditech/phase1dy/independent-review-hold/v1\n';
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const HEX=/^[0-9a-f]{64}$/,SHA=/^[0-9a-f]{40}$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/,SIG=/^[A-Za-z0-9+/]{86}==$/;
const ZERO='0'.repeat(64);
const TOP=['rehearsalCandidate','authorityInventory',
 'previousObservationAnchor','decisionCase','oversightPins',
 'oversightPackets','reviewPins','reviewPackets','now'];
const GATE=['state','evidenceSha256','observedAt'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const PREV=['sequence','digestSha256','observedAt'];
const PACKET=['statement','publicKeyPem','signature'];
const CASE=['schemaVersion','kind','incidentId','repository',
 'organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','archiveSha256','revocationDigestSha256',
 'evidenceSetDigestSha256','recoveryLedgerDigestSha256',
 'authorityInventorySha256','previousObservationSha256',
 'observationSequence','challengeNonce','reviewNonce','frozenAt','decision'];
const BASE=['schemaVersion','kind','role','repository',
 'organizationId','sourceHeadSha','mainBaseSha','incidentId',
 'evidenceSetDigestSha256','recoveryLedgerDigestSha256',
 'authorityInventorySha256','caseDigestSha256',
 'previousObservationSha256','observationSequence',
 'challengeNonce','reviewNonce',...PIN,
 'observedAt','expiresAt','disposition'];
const OVERSIGHT=BASE;
const REVIEW=[...BASE,'oversightSetDigestSha256'];
const hash=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,max){try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}}
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function validPin(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  ID.test(p.operatorId??'')&&
  ID.test(p.custodianOrganizationId??'')&&
  HEX.test(p.spkiSha256??'');
}
function validGate(g){
 return EXACT(g,GATE)&&
  ['MISSING','PRESENT_UNVERIFIED','REJECTED'].includes(g.state)&&
  HEX.test(g.evidenceSha256??'')&&
  (g.state==='MISSING'?
   g.evidenceSha256===ZERO&&g.observedAt===null:
   g.evidenceSha256!==ZERO&&Number.isFinite(utc(g.observedAt)));
}
function validInventory(inventory){
 return EXACT(inventory,DY_REQUIRED_GATES)&&
  DY_REQUIRED_GATES.every(g=>validGate(inventory[g]));
}
function validAnchor(a){
 return EXACT(a,PREV)&&Number.isSafeInteger(a.sequence)&&
  a.sequence>=1&&a.sequence<1_000_000_000&&
  HEX.test(a.digestSha256??'')&&a.digestSha256!==ZERO&&
  Number.isFinite(utc(a.observedAt));
}
function fresh(observed,expires,clock,after){
 const a=utc(observed),b=utc(expires);
 return Number.isFinite(clock)&&Number.isFinite(a)&&Number.isFinite(b)&&
  a>=clock-900000&&a<=clock+300000&&a>=after&&
  b>clock&&b>a&&b-a<=900000;
}
/** Domain-separated digest of EXACT, unverified external-prerequisite inventory. */
export function inventoryDigestDy(inventory){
 if(!validInventory(inventory)||!bounded(inventory,32768))
  throw Error('DY_EXACT_UNVERIFIED_AUTHORITY_INVENTORY_REQUIRED');
 return hash(INV_DOMAIN+canonical(inventory));
}
/** Signed case digest is for a local frozen incident, never a release decision. */
export function frozenCaseDigestDy(c){
 if(!EXACT(c,CASE)||!bounded(c,8192))
  throw Error('DY_FROZEN_CASE_SCOPE_INVALID');
 return hash(CASE_DOMAIN+canonical(c));
}
export function oversightSigningBytesDy(role,statement){
 if(!DY_OVERSIGHT_ROLES.includes(role)||
  !EXACT(statement,OVERSIGHT)||statement.role!==role||
  !bounded(statement,8192))
  throw Error('DY_OVERSIGHT_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(OBS_DOMAIN+canonical(statement),'utf8');
}
export function oversightSetDigestDy(statements){
 if(!Array.isArray(statements)||statements.length!==2||
  !statements.every((s,i)=>EXACT(s,OVERSIGHT)&&
   s.role===DY_OVERSIGHT_ROLES[i])||!bounded(statements,20000))
  throw Error('DY_TWO_ORDERED_OVERSIGHT_STATEMENTS_REQUIRED');
 return hash(SET_DOMAIN+canonical(statements));
}
export function reviewSigningBytesDy(role,statement){
 if(!DY_REVIEW_ROLES.includes(role)||!EXACT(statement,REVIEW)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('DY_REVIEW_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(REVIEW_DOMAIN+canonical(statement),'utf8');
}
function signed(packet,role,signBytes){
 try{
  if(!EXACT(packet,PACKET)||typeof packet.publicKeyPem!=='string'||
    packet.publicKeyPem.length>4096||!SIG.test(packet.signature??'')||
    !bounded(packet,12288))return false;
  const key=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&sig.length===64&&
   sig.toString('base64')===packet.signature&&
   hash(key.export({format:'der',type:'spki'}))===
    packet.statement.spkiSha256&&
   verify(null,signBytes(role,packet.statement),key,sig);
 }catch{return false;}
}
function independentPins(oversightPins,reviewPins,dx){
 if(!EXACT(oversightPins,DY_OVERSIGHT_ROLES)||
  !EXACT(reviewPins,DY_REVIEW_ROLES))return false;
 const current=[
  ...DY_OVERSIGHT_ROLES.map(r=>oversightPins[r]),
  ...DY_REVIEW_ROLES.map(r=>reviewPins[r])];
 if(!current.every(validPin))return false;
 const dw=dx?.custodyCandidate,prior=[
  ...DX_SOURCES.map(r=>dx?.sourcePins?.[r]),
  ...DX_RECOVERY_ROLES.map(r=>dx?.recoveryPins?.[r]),
  ...DW_ENROLLMENT_ROLES.map(r=>dw?.enrollmentPins?.[r]),
  ...DW_REVOCATION_ROLES.map(r=>dw?.revocationPins?.[r]),
  ...DV_ROLES.map(r=>dw?.publicationCandidate?.comparisonPins?.[r])
 ];
 const all=[...current,...prior];
 for(const field of ['keyId','spkiSha256','operatorId']){
  const arr=all.map(p=>p?.[field]);
  if(arr.some(x=>typeof x!=='string')||new Set(arr).size!==arr.length)
   return false;
 }
 const orgs=[
  ...current.map(p=>p.custodianOrganizationId),
  ...DX_SOURCES.map(r=>dx.sourcePins[r].operatorOrganizationId),
  ...DX_RECOVERY_ROLES.map(r=>dx.recoveryPins[r].operatorOrganizationId),
  ...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins[r].custodianOrganizationId),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins[r].custodianOrganizationId)
 ];
 if(new Set(orgs).size!==orgs.length)return false;
 for(const epoch of dw?.publicationCandidate?.history?.epochs??[])
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   const witness=epoch?.checkpointObservations?.[0]?.witnesses?.[role];
   if(!witness||all.some(p=>p.keyId===witness.keyId||
     p.spkiSha256===witness.spkiSha256))return false;
  }
 return true;
}
function report(errors,flags={}){
 return Object.freeze({
  phase:'1DY',schemaVersion:1,
  kind:'OFFLINE_UNTRUSTED_EXTERNAL_ADMISSION_AND_UNFREEZE_HARD_HOLD',
  repository:REPO,
  precedingDxDwDvDuFullOriginalHistoryReverifiedMathematicallyOnly:
   flags.prior===true,
  authorityPrerequisiteSlotsInspected:flags.slots??0,
  authorityPrerequisitesMissing:flags.missing??0,
  authorityPrerequisitesPresentButNotAuthenticated:flags.unverified??0,
  authorityPrerequisitesRejected:flags.rejected??0,
  dualOversightObservationsSignedMathematicallyOnly:
   flags.oversight??0,
  tripleIndependentReviewHoldSignaturesMathematicallyOnly:
   flags.review??0,
  candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly:
   flags.consistent===true,
  admissionChecklistCallerControlledAndNotTrustEvidence:true,
  currentExternalIndependentTrustGatesAuthenticated:0,
  genuineProviderAgreementCredentialsAndIssuerTrustVerified:false,
  signedLiveCrlOcspAndMcaCorporateMandateVerified:false,
  independentlyRetrievedTlsAndArchiveAndDurableWormVerified:false,
  protectedMainNonauthorStagingAndDrAcceptanceVerified:false,
  independentlyAuthenticatedExternalUnfreezeApprovalVerified:false,
  actualProductionUnfreezeOrAutomaticReleasePossible:false,
  noRawCertificatesKeysSignaturesNonceOrEvidenceReturned:true,
  productionMutationOrSourceActivationPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Stateless, deny-only evaluation of submitted *untrusted* admission paperwork. */
export function assessOfflineAdmissionUnfreezePreconditionsDy(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,1536*1024)){
  errors.add('DY_EXACT_BOUNDED_INPUT_REQUIRED');
  return report(errors);
 }
 const {rehearsalCandidate:dx,authorityInventory,previousObservationAnchor,
  decisionCase:c,oversightPins,oversightPackets,reviewPins,reviewPackets,
  now}=args;
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('DY_EXPLICIT_UTC_CLOCK_REQUIRED');
 let priorOK=false;
 try{
  const proof=assessOfflineEvidenceIncidentRecoveryCandidate(dx);
  priorOK=dx?.now===now&&
   proof.candidateEvidenceAndFrozenRehearsalInternallyConsistentOnly&&
   proof.anomalyCodes.length===0;
 }catch{priorOK=false;}
 if(!priorOK)errors.add('DY_PRECEDING_DX_OR_HISTORY_NOT_REVERIFIED');
 let inventoryHash=null,missing=0,unverified=0,rejected=0;
 const invOK=validInventory(authorityInventory)&&
  bounded(authorityInventory,32768);
 if(!invOK)errors.add('DY_EXACT_AUTHORITY_PREREQUISITE_STATUSES_REQUIRED');
 if(invOK){
  for(const gate of DY_REQUIRED_GATES){
   const v=authorityInventory[gate];
   if(v.state==='MISSING')missing++;
   else if(v.state==='PRESENT_UNVERIFIED')unverified++;
   else rejected++;
   if(v.state!=='MISSING'&&
     (!Number.isFinite(clock)||utc(v.observedAt)>clock+300000))
    errors.add('DY_GATE_TIME_CLAIM_INVALID');
  }
  inventoryHash=inventoryDigestDy(authorityInventory);
 }
 const expected=dx?.custodyCandidate?.publicationCandidate?.expected;
 const anchorOK=validAnchor(previousObservationAnchor)&&
  Number.isFinite(clock)&&
  utc(previousObservationAnchor.observedAt)>=clock-900000&&
  utc(previousObservationAnchor.observedAt)<=clock+300000;
 if(!anchorOK)errors.add('DY_PRIOR_HIGHWATERMARK_OR_CLOCK_INVALID');
 let sourceSet=null,ledger=null;
 if(priorOK)try{
  const statements=DX_SOURCES.map(role=>
   dx.sourceReceipts.find(p=>p?.statement?.role===role).statement);
  sourceSet=evidenceSetDigestDx(statements);
  ledger=recoveryStepDigestDx(dx.recoverySteps.at(-1));
 }catch{errors.add('DY_PRECEDING_EVIDENCE_DIGEST_UNAVAILABLE');}
 const incident=dx?.incident,freeze=Array.isArray(dx?.recoverySteps)?
  dx.recoverySteps.at(-1):null;
 const caseOK=EXACT(c,CASE)&&bounded(c,8192)&&
  c.schemaVersion===1&&
  c.kind==='UNTRUSTED_INDEPENDENT_UNFREEZE_REVIEW_CASE'&&
  c.decision==='REMAINS_FROZEN'&&c.repository===REPO&&
  c.incidentId===incident?.incidentId&&
  c.organizationId===expected?.organizationId&&
  c.sourceHeadSha===expected?.sourceHeadSha&&
  c.mainBaseSha===expected?.mainBaseSha&&
  c.checkpointSha256===expected?.checkpointSha256&&
  c.archiveSha256===expected?.archiveSha256&&
  c.revocationDigestSha256===expected?.revocationDigestSha256&&
  c.evidenceSetDigestSha256===sourceSet&&
  c.recoveryLedgerDigestSha256===ledger&&
  c.authorityInventorySha256===inventoryHash&&
  c.previousObservationSha256===previousObservationAnchor?.digestSha256&&
  anchorOK&&c.observationSequence===previousObservationAnchor.sequence+1&&
  c.challengeNonce===expected?.challengeNonce&&
  HEX.test(c.reviewNonce??'')&&c.reviewNonce!==ZERO&&
  c.reviewNonce!==c.challengeNonce&&
  c.frozenAt===freeze?.observedAt&&
  Number.isFinite(utc(c.frozenAt))&&
  utc(c.frozenAt)>utc(previousObservationAnchor.observedAt)&&
  utc(c.frozenAt)<=clock+300000;
 if(!caseOK)errors.add('DY_FROZEN_CASE_SCOPE_SEQUENCE_OR_THAW_INVALID');
 const diverse=priorOK&&independentPins(oversightPins,reviewPins,dx);
 if(!diverse)errors.add('DY_NEW_INDEPENDENT_ROLE_PINS_UNPROVEN');
 const shape=Array.isArray(oversightPackets)&&oversightPackets.length===2&&
  EXACT(oversightPins,DY_OVERSIGHT_ROLES);
 if(!shape)errors.add('DY_TWO_EXACT_OVERSIGHT_PACKETS_REQUIRED');
 let oversight=0;
 const obs=new Map();
 let caseHash=null;
 if(caseOK)caseHash=frozenCaseDigestDy(c);
 if(shape)for(const packet of oversightPackets){
  const s=packet?.statement,role=s?.role;
  if(!DY_OVERSIGHT_ROLES.includes(role)||obs.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,OVERSIGHT)||!bounded(packet,12288)){
   errors.add('DY_OVERSIGHT_ROLE_PACKET_INVALID');continue;
  }
  obs.set(role,packet);
  const pin=oversightPins[role];
  if(!validPin(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('DY_OVERSIGHT_DETACHED_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_FROZEN_SOURCE_OVERSIGHT'||
   s.disposition!=='OBSERVE_FROZEN_ONLY'||s.repository!==REPO||
   !caseOK||s.incidentId!==c.incidentId||
   s.organizationId!==c.organizationId||
   s.sourceHeadSha!==c.sourceHeadSha||
   s.mainBaseSha!==c.mainBaseSha||
   s.evidenceSetDigestSha256!==sourceSet||
   s.recoveryLedgerDigestSha256!==ledger||
   s.authorityInventorySha256!==inventoryHash||
   s.caseDigestSha256!==caseHash||
   s.previousObservationSha256!==c.previousObservationSha256||
   s.observationSequence!==c.observationSequence||
   s.challengeNonce!==c.challengeNonce||
   s.reviewNonce!==c.reviewNonce)
   errors.add('DY_OVERSIGHT_CASE_SCOPE_OR_DISPOSITION_MISMATCH');
  if(!fresh(s.observedAt,s.expiresAt,clock,utc(c?.frozenAt)))
   errors.add('DY_OVERSIGHT_STALE_OR_PRE_FREEZE');
  if(!signed(packet,role,oversightSigningBytesDy))
   errors.add('DY_OVERSIGHT_SIGNATURE_OR_SPKI_INVALID');
  else oversight++;
 }
 if(shape&&obs.size!==2)errors.add('DY_OVERSIGHT_QUORUM_INCOMPLETE');
 let obsDigest=null;
 if(shape&&obs.size===2)try{
  obsDigest=oversightSetDigestDy(
   DY_OVERSIGHT_ROLES.map(role=>obs.get(role).statement));
 }catch{errors.add('DY_OVERSIGHT_SET_DIGEST_INVALID');}
 const reviewsShape=Array.isArray(reviewPackets)&&reviewPackets.length===3&&
  EXACT(reviewPins,DY_REVIEW_ROLES);
 if(!reviewsShape)errors.add('DY_THREE_EXACT_REVIEW_HOLD_PACKETS_REQUIRED');
 let review=0;
 const seen=new Set();
 if(reviewsShape)for(const packet of reviewPackets){
  const s=packet?.statement,role=s?.role;
  if(!DY_REVIEW_ROLES.includes(role)||seen.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,REVIEW)||!bounded(packet,12288)){
   errors.add('DY_REVIEW_ROLE_PACKET_INVALID');continue;
  }
  seen.add(role);
  const pin=reviewPins[role];
  if(!validPin(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('DY_REVIEW_DETACHED_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_INDEPENDENT_REVIEW_HOLD'||
   s.disposition!=='REVIEW_HOLD_ONLY'||s.repository!==REPO||
   !caseOK||s.incidentId!==c.incidentId||
   s.organizationId!==c.organizationId||
   s.sourceHeadSha!==c.sourceHeadSha||
   s.mainBaseSha!==c.mainBaseSha||
   s.evidenceSetDigestSha256!==sourceSet||
   s.recoveryLedgerDigestSha256!==ledger||
   s.authorityInventorySha256!==inventoryHash||
   s.caseDigestSha256!==caseHash||
   s.previousObservationSha256!==c.previousObservationSha256||
   s.observationSequence!==c.observationSequence||
   s.challengeNonce!==c.challengeNonce||
   s.reviewNonce!==c.reviewNonce||
   s.oversightSetDigestSha256!==obsDigest)
   errors.add('DY_REVIEW_CASE_SCOPE_OR_FORBIDDEN_UNFREEZE');
  const latest=shape&&obs.size===2?Math.max(...DY_OVERSIGHT_ROLES
   .map(r=>utc(obs.get(r).statement.observedAt))):NaN;
  if(!fresh(s.observedAt,s.expiresAt,clock,latest))
   errors.add('DY_REVIEW_STALE_OR_PRE_OVERSIGHT');
  if(!signed(packet,role,reviewSigningBytesDy))
   errors.add('DY_REVIEW_SIGNATURE_OR_SPKI_INVALID');
  else review++;
 }
 if(reviewsShape&&seen.size!==3)errors.add('DY_REVIEW_QUORUM_INCOMPLETE');
 const consistent=priorOK&&invOK&&anchorOK&&caseOK&&diverse&&
  oversight===2&&review===3&&errors.size===0;
 return report(errors,{prior:priorOK,slots:invOK?12:0,
  missing,unverified,rejected,oversight,review,consistent});
}
