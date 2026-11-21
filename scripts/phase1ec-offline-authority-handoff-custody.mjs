import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DV_ROLES} from './phase1dv-offline-observer-publication-candidate.mjs';
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';
import {DX_SOURCES,DX_RECOVERY_ROLES}
 from './phase1dx-offline-evidence-incident-recovery.mjs';
import {DY_REQUIRED_GATES,DY_OVERSIGHT_ROLES,DY_REVIEW_ROLES}
 from './phase1dy-offline-source-admission-unfreeze-preconditions.mjs';
import {DZ_ANCHOR_ROLES,DZ_CUSTODY_ROLES}
 from './phase1dz-offline-cross-epoch-anchor-custody.mjs';
import {EA_PEER_ROLES,EA_FREEZE_ROLES}
 from './phase1ea-offline-gossip-admission-boundary.mjs';
import {EB_RUN_ROLES,EB_CUSTODY_ROLES,gossipHandoffDigestEb,
 runDigestEb,assessOfflineCrossRunGossipIncidentCustodyEb}
 from './phase1eb-offline-cross-run-gossip-incident-custody.mjs';

// All records and keys are caller supplied. No real provider authorization,
// external evidence fetch, independent key enrollment or persistent storage.
export const EC_AUTHORITY_GATES=DY_REQUIRED_GATES;
export const EC_REVIEW_ROLES=Object.freeze([
 'ARCHIVE_EVIDENCE_HANDOFF_REVIEW','INCIDENT_PROVENANCE_HANDOFF_REVIEW'
]);
export const EC_CUSTODY_ROLES=Object.freeze([
 'LEGAL_AUTHORITY_HANDOFF_CUSTODY','SECURITY_AUTHORITY_HANDOFF_CUSTODY'
]);
const SOURCE_DOMAIN='aaditech/phase1ec/offline-eb-source-receipt/v1\n';
const CLAIM_DOMAIN='aaditech/phase1ec/unverified-12-gate-handoff/v1\n';
const MANIFEST_DOMAIN='aaditech/phase1ec/authority-handoff-freeze/v1\n';
const REVIEW_DOMAIN='aaditech/phase1ec/authority-handoff-review/v1\n';
const REVIEWSET_DOMAIN='aaditech/phase1ec/two-review-hold/v1\n';
const CUSTODY_DOMAIN='aaditech/phase1ec/legal-security-custody-hold/v1\n';
const TOP=['incidentCandidate','previousHandoffAnchor','authorityClaims',
 'manifest','reviewPins','reviewPackets','custodyPins','custodyPackets','now'];
const ANCHOR=['sequence','digestSha256','observedAt'];
const CLAIM=['state','evidenceSha256','issuerOrganizationClaim',
 'submittedAt','validUntil'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const MANIFEST=['schemaVersion','kind','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','finalRunSequence',
 'finalRunSha256','ebCustodySourceSha256','priorGossipHandoffSha256',
 'authorityClaimsSha256','previousHandoffSequence','previousHandoffSha256',
 'sequence','challengeNonce','observedAt','decision'];
const REVIEW=[...MANIFEST,'role',...PIN,'manifestSha256',
 'reviewObservedAt','expiresAt','disposition'];
const CUSTODY=[...MANIFEST,'role',...PIN,'manifestSha256',
 'reviewSetSha256','observedAtCustody','expiresAt','retentionUntil',
 'disposition'];
const PACKET=['statement','publicKeyPem','signature'];
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
 const t=utc(observed),end=utc(expires);
 return Number.isFinite(clock)&&Number.isFinite(t)&&
  Number.isFinite(end)&&t>after&&t>=clock-900000&&
  t<=clock+300000&&end>clock&&end>t&&end-t<=900000;
}
function pinOK(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  HEX.test(p.spkiSha256??'')&&ID.test(p.operatorId??'')&&
  ID.test(p.custodianOrganizationId??'');
}
function signed(packet,role,signBytes){
 try{
  if(!EXACT(packet,PACKET)||!bounded(packet,12288)||
   typeof packet.publicKeyPem!=='string'||packet.publicKeyPem.length>4096||
   !SIG.test(packet.signature??''))return false;
  const key=createPublicKey(packet.publicKeyPem);
  const signature=Buffer.from(packet.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&signature.length===64&&
   signature.toString('base64')===packet.signature&&
   HASH(key.export({format:'der',type:'spki'}))===
    packet.statement.spkiSha256&&
   verify(null,signBytes(role,packet.statement),key,signature);
 }catch{return false;}
}
/** Original two-run and both retention statements; not an offsite anchor. */
export function sourceReceiptDigestEc(eb){
 const last=eb?.runs,receipts=eb?.custodyPackets;
 if(!Array.isArray(last)||last.length!==2||
  !Array.isArray(receipts)||receipts.length!==2)
  throw Error('EC_ORIGINAL_TWO_RUNS_AND_TWO_CUSTODIANS_REQUIRED');
 const proof={
  repository:REPO,priorHandoffSha256:gossipHandoffDigestEb(eb.gossipCandidate),
  firstRunSha256:runDigestEb(last[0].record),
  finalRunSha256:runDigestEb(last[1].record),
  custodians:EB_CUSTODY_ROLES.map(role=>
   receipts.find(p=>p?.statement?.role===role).statement)
 };
 if(!bounded(proof,18000))throw Error('EC_BOUNDED_ORIGINAL_SOURCE_REQUIRED');
 return HASH(SOURCE_DOMAIN+canonical(proof));
}
/** Exact self-reported preflight; deliberately no VERIFIED or APPROVED state. */
export function authorityClaimsDigestEc(claims){
 if(!EXACT(claims,EC_AUTHORITY_GATES)||!bounded(claims,32768)||
  !EC_AUTHORITY_GATES.every(role=>{
   const c=claims[role];
   if(!EXACT(c,CLAIM)||!HEX.test(c.evidenceSha256??''))return false;
   if(c.state==='MISSING')
    return c.evidenceSha256==='0'.repeat(64)&&
     c.issuerOrganizationClaim===null&&c.submittedAt===null&&
     c.validUntil===null;
   return ['PRESENT_UNVERIFIED','REJECTED'].includes(c.state)&&
    c.evidenceSha256!=='0'.repeat(64)&&
    ID.test(c.issuerOrganizationClaim??'')&&
    Number.isFinite(utc(c.submittedAt))&&
    Number.isFinite(utc(c.validUntil))&&
    utc(c.validUntil)>utc(c.submittedAt);
  }))throw Error('EC_UNVERIFIED_EXACT_12_GATE_CLAIMS_REQUIRED');
 return HASH(CLAIM_DOMAIN+canonical(claims));
}
export function manifestDigestEc(m){
 if(!EXACT(m,MANIFEST)||!bounded(m,8192))
  throw Error('EC_EXACT_FROZEN_MANIFEST_REQUIRED');
 return HASH(MANIFEST_DOMAIN+canonical(m));
}
export function reviewSigningBytesEc(role,s){
 if(!EC_REVIEW_ROLES.includes(role)||!EXACT(s,REVIEW)||
  s.role!==role||!bounded(s,8192))
  throw Error('EC_EXACT_REVIEW_SIGNATURE_SCOPE_REQUIRED');
 return Buffer.from(REVIEW_DOMAIN+canonical(s),'utf8');
}
export function reviewSetDigestEc(ordered){
 if(!Array.isArray(ordered)||ordered.length!==2||
  !ordered.every((s,i)=>EXACT(s,REVIEW)&&s.role===EC_REVIEW_ROLES[i])||
  !bounded(ordered,18000))
  throw Error('EC_TWO_ORDERED_REVIEW_HOLD_STATEMENTS_REQUIRED');
 return HASH(REVIEWSET_DOMAIN+canonical(ordered));
}
export function custodySigningBytesEc(role,s){
 if(!EC_CUSTODY_ROLES.includes(role)||!EXACT(s,CUSTODY)||
  s.role!==role||!bounded(s,8192))
  throw Error('EC_EXACT_CUSTODY_SIGNATURE_SCOPE_REQUIRED');
 return Buffer.from(CUSTODY_DOMAIN+canonical(s),'utf8');
}
function independentPins(reviewPins,custodyPins,eb){
 if(!EXACT(reviewPins,EC_REVIEW_ROLES)||
  !EXACT(custodyPins,EC_CUSTODY_ROLES))return false;
 const current=[...EC_REVIEW_ROLES.map(r=>reviewPins[r]),
  ...EC_CUSTODY_ROLES.map(r=>custodyPins[r])];
 if(!current.every(pinOK))return false;
 const ea=eb?.gossipCandidate,dz=ea?.anchorCandidate,
  dy=dz?.admissionCandidate,dx=dy?.rehearsalCandidate,
  dw=dx?.custodyCandidate;
 const previous=[
  ...EB_RUN_ROLES.map(r=>eb?.peerPins?.[r]),
  ...EB_CUSTODY_ROLES.map(r=>eb?.custodyPins?.[r]),
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
 const all=[...current,...previous];
 for(const field of ['keyId','spkiSha256','operatorId']){
  const values=all.map(p=>p?.[field]);
  if(values.some(x=>typeof x!=='string')||
   new Set(values).size!==values.length)return false;
 }
 const org=[
  ...current.map(p=>p.custodianOrganizationId),
  ...EB_RUN_ROLES.map(r=>eb.peerPins[r].custodianOrganizationId),
  ...EB_CUSTODY_ROLES.map(r=>eb.custodyPins[r].custodianOrganizationId),
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
 if(new Set(org).size!==org.length)return false;
 for(const e of dw?.publicationCandidate?.history?.epochs??[])
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   const w=e?.checkpointObservations?.[0]?.witnesses?.[role];
   if(!w||all.some(p=>p.keyId===w.keyId||
    p.spkiSha256===w.spkiSha256))return false;
  }
 return true;
}
function hold(errors,flags={}){
 return Object.freeze({
  phase:'1EC',schemaVersion:1,
  kind:'OFFLINE_EXTERNAL_AUTHORITY_HANDOFF_CUSTODY_HARD_HOLD',
  repository:REPO,
  precedingEbToDuOriginalHistoryReverifiedMathematicallyOnly:
   flags.previous===true,
  exactTwelveApplicantOnlyGateClaims:flags.gates??0,
  mathematicallyVerifiedTwoReviewSignatures:flags.review??0,
  mathematicallyVerifiedTwoCustodySignatures:flags.custody??0,
  candidateHandoffManifestCorrelatedMathematicallyOnly:
   flags.consistent===true,
  everyGateUnverifiedAndNoExternalTrustPromoted:true,
  actualExternalProviderOrMcaMandateVerified:false,
  issuerSignedLiveCrlOcspOrCcaRcaiEmudhraVerified:false,
  independentTlsEvidenceRetrievalOrSignedGossipPerformed:false,
  durableWormCasObjectLockAndIndependentDrVerified:false,
  actualIndependentReviewerOrStagingAuthorizationVerified:false,
  productionSourceUnfreezeOrCredentialEnrollmentPossible:false,
  noRawEvidenceSignaturesKeysOrClaimedIdentitiesReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Exact applicant-only preflight handoff, never independent admission. */
export function assessOfflineExternalAuthorityHandoffEc(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,3584*1024)){
  errors.add('EC_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {incidentCandidate:eb,previousHandoffAnchor,authorityClaims,manifest:m,
  reviewPins,reviewPackets,custodyPins,custodyPackets,now}=args;
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('EC_EXPLICIT_UTC_CLOCK_REQUIRED');
 let previous=false,sourceSha=null;
 try{
  const r=assessOfflineCrossRunGossipIncidentCustodyEb(eb);
  previous=eb?.now===now&&
   r.submittedCrossRunForkReplayAndCustodyInternallyConsistentOnly&&
   r.anomalyCodes.length===0;
  if(previous)sourceSha=sourceReceiptDigestEc(eb);
 }catch{previous=false;}
 if(!previous)errors.add('EC_ORIGINAL_EB_HISTORY_NOT_REVERIFIED');
 const dy=eb?.gossipCandidate?.anchorCandidate?.admissionCandidate,
  original=dy?.decisionCase,oldGates=dy?.authorityInventory,
  expected=dy?.rehearsalCandidate?.custodyCandidate?.
   publicationCandidate?.expected,
  final=Array.isArray(eb?.runs)?eb.runs.at(-1)?.record:null;
 let claimSha=null,claimsOK=false;
 try{
  claimSha=authorityClaimsDigestEc(authorityClaims);
  claimsOK=EC_AUTHORITY_GATES.every(role=>{
   const c=authorityClaims[role],prior=oldGates?.[role];
   if(!prior||c.state!==prior.state||
    c.evidenceSha256!==prior.evidenceSha256)return false;
   if(c.state==='MISSING')return true;
   return c.submittedAt===prior.observedAt&&
    utc(c.submittedAt)<=clock+300000&&
    utc(c.validUntil)>clock&&
    utc(c.validUntil)<=clock+30*86400*1000;
  });
 }catch{claimsOK=false;}
 if(!claimsOK)errors.add('EC_ORIGINAL_12_GATE_STATUS_OR_EVIDENCE_DRIFT');
 const predecessorTime=Array.isArray(eb?.custodyPackets)?
  Math.max(...eb.custodyPackets.map(p=>utc(p?.statement?.observedAt))):NaN;
 const anchorOK=EXACT(previousHandoffAnchor,ANCHOR)&&
  Number.isSafeInteger(previousHandoffAnchor.sequence)&&
  previousHandoffAnchor.sequence>0&&
  previousHandoffAnchor.sequence<1000000000&&
  previousHandoffAnchor.sequence===final?.sequence&&
  previousHandoffAnchor.digestSha256===sourceSha&&
  Number.isFinite(clock)&&
  Number.isFinite(utc(previousHandoffAnchor.observedAt))&&
  utc(previousHandoffAnchor.observedAt)>=predecessorTime&&
  utc(previousHandoffAnchor.observedAt)>=clock-900000&&
  utc(previousHandoffAnchor.observedAt)<=clock+300000;
 if(!anchorOK)errors.add('EC_PREVIOUS_INCIDENT_SOURCE_ANCHOR_INVALID');
 const manifestOK=EXACT(m,MANIFEST)&&bounded(m,8192)&&
  m.schemaVersion===1&&m.kind==='APPLICANT_UNVERIFIED_AUTHORITY_HANDOFF_HOLD'&&
  m.repository===REPO&&m.incidentId===original?.incidentId&&
  m.organizationId===expected?.organizationId&&
  m.sourceHeadSha===expected?.sourceHeadSha&&
  m.mainBaseSha===expected?.mainBaseSha&&
  m.finalRunSequence===final?.sequence&&
  m.finalRunSha256===(previous?runDigestEb(final):null)&&
  m.ebCustodySourceSha256===sourceSha&&
  m.priorGossipHandoffSha256===eb?.previousRunAnchor?.digestSha256&&
  m.authorityClaimsSha256===claimSha&&
  anchorOK&&m.previousHandoffSequence===previousHandoffAnchor.sequence&&
  m.previousHandoffSha256===previousHandoffAnchor.digestSha256&&
  m.sequence===previousHandoffAnchor.sequence+1&&
  HEX.test(m.challengeNonce??'')&&m.challengeNonce!=='0'.repeat(64)&&
  m.challengeNonce!==original?.reviewNonce&&
  m.challengeNonce!==final?.nonce&&
  Number.isFinite(utc(m.observedAt))&&
  utc(m.observedAt)>utc(previousHandoffAnchor.observedAt)&&
  utc(m.observedAt)<=clock+300000&&m.decision==='HOLD';
 if(!manifestOK)errors.add('EC_HOLD_MANIFEST_SOURCE_OR_SEQUENCE_MISMATCH');
 const diversity=previous&&independentPins(reviewPins,custodyPins,eb);
 if(!diversity)errors.add('EC_SIGNER_KEY_OPERATOR_OR_ORG_NOT_SEPARATED');
 const reviewShape=Array.isArray(reviewPackets)&&
  reviewPackets.length===2&&EXACT(reviewPins,EC_REVIEW_ROLES);
 if(!reviewShape)errors.add('EC_EXACT_TWO_REVIEW_PACKETS_REQUIRED');
 const reviews=new Map(),manifestSha=manifestOK?manifestDigestEc(m):null;
 let validReviewSignatures=0;
 if(reviewShape)for(const packet of reviewPackets){
  const s=packet?.statement,role=s?.role;
  if(!EC_REVIEW_ROLES.includes(role)||reviews.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,REVIEW)||!bounded(packet,12288)){
   errors.add('EC_REVIEW_ROLE_PACKET_INVALID');continue;
  }
  reviews.set(role,packet);
  const pin=reviewPins[role];
  if(!pinOK(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('EC_REVIEW_DETACHED_PIN_INVALID');
  if(!manifestOK||!MANIFEST.every(k=>s[k]===m[k])||
   s.manifestSha256!==manifestSha||
   s.disposition!=='REVIEW_UNVERIFIED_HOLD_ONLY')
   errors.add('EC_REVIEW_SIGNED_SCOPE_OR_FALSE_APPROVAL');
  if(!fresh(s.reviewObservedAt,s.expiresAt,clock,utc(m?.observedAt)))
   errors.add('EC_REVIEW_CLOCK_OR_EXPIRY_INVALID');
  if(!signed(packet,role,reviewSigningBytesEc))
   errors.add('EC_REVIEW_SIGNATURE_OR_SPKI_INVALID');
  else validReviewSignatures++;
 }
 if(reviewShape&&reviews.size!==2)
  errors.add('EC_REVIEW_QUORUM_INCOMPLETE');
 let reviewSetSha=null,latestReview=NaN;
 if(reviewShape&&reviews.size===2)try{
  const ordered=EC_REVIEW_ROLES.map(role=>reviews.get(role).statement);
  reviewSetSha=reviewSetDigestEc(ordered);
  latestReview=Math.max(...ordered.map(s=>utc(s.reviewObservedAt)));
 }catch{errors.add('EC_REVIEW_SET_DIGEST_INVALID');}
 const custodyShape=Array.isArray(custodyPackets)&&
  custodyPackets.length===2&&EXACT(custodyPins,EC_CUSTODY_ROLES);
 if(!custodyShape)errors.add('EC_EXACT_TWO_CUSTODY_PACKETS_REQUIRED');
 let validCustodySignatures=0;
 const custodians=new Map();
 const previousRetention=Array.isArray(eb?.custodyPackets)?
  eb.custodyPackets[0]?.statement?.retentionUntil:null;
 if(custodyShape)for(const packet of custodyPackets){
  const s=packet?.statement,role=s?.role;
  if(!EC_CUSTODY_ROLES.includes(role)||custodians.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,CUSTODY)||!bounded(packet,12288)){
   errors.add('EC_CUSTODY_ROLE_PACKET_INVALID');continue;
  }
  custodians.set(role,packet);
  const pin=custodyPins[role];
  if(!pinOK(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('EC_CUSTODY_DETACHED_PIN_INVALID');
  if(!manifestOK||!MANIFEST.every(k=>s[k]===m[k])||
   s.manifestSha256!==manifestSha||
   s.reviewSetSha256!==reviewSetSha||
   s.disposition!=='RETAIN_UNVERIFIED_HOLD_NO_UNFREEZE')
   errors.add('EC_CUSTODY_SIGNED_SOURCE_OR_UNFREEZE_FORBIDDEN');
  if(!fresh(s.observedAtCustody,s.expiresAt,clock,latestReview)||
   s.retentionUntil!==previousRetention||
   utc(s.retentionUntil)<clock+30*86400*1000)
   errors.add('EC_CUSTODY_TIME_OR_RETENTION_INVALID');
  if(!signed(packet,role,custodySigningBytesEc))
   errors.add('EC_CUSTODY_SIGNATURE_OR_SPKI_INVALID');
  else validCustodySignatures++;
 }
 if(custodyShape&&custodians.size!==2)
  errors.add('EC_CUSTODY_QUORUM_INCOMPLETE');
 if(custodians.size===2){
  const a=custodians.get(EC_CUSTODY_ROLES[0]).statement;
  const b=custodians.get(EC_CUSTODY_ROLES[1]).statement;
  if(a.retentionUntil!==b.retentionUntil)
   errors.add('EC_CUSTODY_RETENTION_FORK');
 }
 const consistent=previous&&claimsOK&&anchorOK&&manifestOK&&diversity&&
  validReviewSignatures===2&&validCustodySignatures===2&&errors.size===0;
 return hold(errors,{previous,gates:claimsOK?12:0,
  review:validReviewSignatures,custody:validCustodySignatures,consistent});
}
