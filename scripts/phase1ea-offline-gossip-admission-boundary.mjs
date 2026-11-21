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
import {DZ_ANCHOR_ROLES,DZ_CUSTODY_ROLES,
 anchorDigestDz,assessOfflineCrossEpochAnchorCustodyDz}
 from './phase1dz-offline-cross-epoch-anchor-custody.mjs';

// Phase 1EA is a read-only OFFLINE consistency gate. All presented gossip,
// pins, time, signer/operator labels and alleged source identities remain
// applicant-supplied, not authenticated external evidence or real network IO.
export const EA_PEER_ROLES=Object.freeze([
 'ARCHIVE_GOSSIP_PEER','REGISTRY_GOSSIP_PEER','RECOVERY_GOSSIP_PEER'
]);
export const EA_FREEZE_ROLES=Object.freeze([
 'LEGAL_GOSSIP_FREEZE_REVIEW','SECURITY_GOSSIP_FREEZE_REVIEW'
]);
const VIEW_DOMAIN='aaditech/phase1ea/offline-epoch-view/v1\n';
const PEER_DOMAIN='aaditech/phase1ea/peer-receipt/v1\n';
const QUORUM_DOMAIN='aaditech/phase1ea/three-peer-quorum/v1\n';
const CLAIM_DOMAIN='aaditech/phase1ea/untrusted-admission-claim/v1\n';
const FREEZE_DOMAIN='aaditech/phase1ea/freeze-hold-review/v1\n';
const TOP=['anchorCandidate','previousGossipCursor','admissionClaim',
 'peerPins','peerPackets','freezePins','freezePackets','now'];
const CURSOR=['sequence','digestSha256','observedAt'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const CLAIM=['kind','sourceType','trustStatus','providerAuthorized',
 'legalAuthorityVerified','liveIssuerRevocationAuthenticated',
 'remoteArchiveRetrieved','wormCasRetentionVerified',
 'independentStagingApproved','releaseApproved','decision'];
const EPOCH=['sequence','previousSequence','previousDigestSha256',
 'anchorDigestSha256','nonceSha256','observedAt'];
const PEER_STMT=['schemaVersion','kind','role','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha',
 'previousSequence','previousAnchorSha256','finalSequence',
 'finalAnchorSha256','evidenceBundleSha256','authorityInventorySha256',
 'epochViewSha256','challengeNonce',...PIN,'observedAt','expiresAt','decision'];
const PEER_PACKET=['statement','viewEpochs','publicKeyPem','signature'];
const FREEZE_STMT=['schemaVersion','kind','role','repository','incidentId',
 'organizationId','sourceHeadSha','mainBaseSha','finalSequence',
 'finalAnchorSha256','evidenceBundleSha256','epochViewSha256',
 'peerQuorumSha256','admissionClaimSha256','reviewNonce',
 ...PIN,'observedAt','expiresAt','disposition'];
const PACKET=['statement','publicKeyPem','signature'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HEX=/^[a-f0-9]{64}$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const HASH=x=>createHash('sha256').update(x).digest('hex');
const bounded=(x,max)=>{try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}};
function utc(v){
 if(typeof v!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v))
  return NaN;
 const t=Date.parse(v);
 return Number.isFinite(t)&&new Date(t).toISOString()===v?t:NaN;
}
function fresh(observed,expiry,clock,after){
 const a=utc(observed),b=utc(expiry);
 return Number.isFinite(clock)&&Number.isFinite(a)&&
  Number.isFinite(b)&&a>after&&a>=clock-900000&&
  a<=clock+300000&&b>clock&&b>a&&b-a<=900000;
}
function pinOK(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  HEX.test(p.spkiSha256??'')&&ID.test(p.operatorId??'')&&
  ID.test(p.custodianOrganizationId??'');
}
function signed(packet,role,bytes){
 try{
  if(!OWN(packet)||typeof packet.publicKeyPem!=='string'||
   packet.publicKeyPem.length>4096||
   !SIG.test(packet.signature??'')||!bounded(packet,30000))
   return false;
  const key=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&sig.length===64&&
   sig.toString('base64')===packet.signature&&
   HASH(key.export({type:'spki',format:'der'}))===
    packet.statement.spkiSha256&&
   verify(null,bytes(role,packet.statement),key,sig);
 }catch{return false;}
}
function validEpoch(v){
 return EXACT(v,EPOCH)&&Number.isSafeInteger(v.sequence)&&
  v.sequence>0&&Number.isSafeInteger(v.previousSequence)&&
  v.previousSequence>=0&&v.sequence===v.previousSequence+1&&
  HEX.test(v.previousDigestSha256??'')&&
  HEX.test(v.anchorDigestSha256??'')&&
  HEX.test(v.nonceSha256??'')&&Number.isFinite(utc(v.observedAt));
}
export function candidateEpochViewEa(anchorCandidate){
 const records=anchorCandidate?.epochs;
 if(!Array.isArray(records)||records.length<2||records.length>4)
  throw Error('EA_ORIGINAL_EPOCHS_REQUIRED');
 return records.map(item=>{
  const r=item?.record;
  return {sequence:r.sequence,previousSequence:r.previousSequence,
   previousDigestSha256:r.previousDigestSha256,
   anchorDigestSha256:anchorDigestDz(r),nonceSha256:HASH(r.nonce),
   observedAt:r.observedAt};
 });
}
export function epochViewDigestEa(view){
 if(!Array.isArray(view)||view.length<2||view.length>4||
  !view.every(validEpoch)||!bounded(view,8192))
  throw Error('EA_EXACT_BOUNDED_VIEW_REQUIRED');
 return HASH(VIEW_DOMAIN+canonical(view));
}
export function admissionClaimDigestEa(claim){
 if(!EXACT(claim,CLAIM)||!bounded(claim,4096)||
  claim.kind!=='UNTRUSTED_OFFLINE_ADMISSION_PREFLIGHT'||
  claim.sourceType!=='APPLICANT_OFFLINE_SUBMISSION'||
  claim.trustStatus!=='NOT_AUTHENTICATED'||
  claim.decision!=='HOLD'||CLAIM.filter(k=>
   ['providerAuthorized','legalAuthorityVerified',
    'liveIssuerRevocationAuthenticated','remoteArchiveRetrieved',
    'wormCasRetentionVerified','independentStagingApproved',
    'releaseApproved'].includes(k)).some(k=>claim[k]!==false))
  throw Error('EA_SELF_APPROVAL_CANNOT_BE_ADMITTED');
 return HASH(CLAIM_DOMAIN+canonical(claim));
}
export function peerSigningBytesEa(role,statement){
 if(!EA_PEER_ROLES.includes(role)||!EXACT(statement,PEER_STMT)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('EA_PEER_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(PEER_DOMAIN+canonical(statement),'utf8');
}
export function peerQuorumDigestEa(statements){
 if(!Array.isArray(statements)||statements.length!==3||
  !statements.every((s,i)=>EXACT(s,PEER_STMT)&&
   s.role===EA_PEER_ROLES[i])||!bounded(statements,27000))
  throw Error('EA_EXACT_THREE_ROLE_QUORUM_REQUIRED');
 return HASH(QUORUM_DOMAIN+canonical(statements));
}
export function freezeSigningBytesEa(role,statement){
 if(!EA_FREEZE_ROLES.includes(role)||!EXACT(statement,FREEZE_STMT)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('EA_FREEZE_SIGNATURE_SCOPE_INVALID');
 return Buffer.from(FREEZE_DOMAIN+canonical(statement),'utf8');
}
function diverse(peerPins,freezePins,dz){
 if(!EXACT(peerPins,EA_PEER_ROLES)||
  !EXACT(freezePins,EA_FREEZE_ROLES))return false;
 const current=[...EA_PEER_ROLES.map(r=>peerPins[r]),
  ...EA_FREEZE_ROLES.map(r=>freezePins[r])];
 if(!current.every(pinOK))return false;
 const dy=dz?.admissionCandidate,dx=dy?.rehearsalCandidate,
  dw=dx?.custodyCandidate;
 const previous=[
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
  const vals=all.map(p=>p?.[field]);
  if(vals.some(v=>typeof v!=='string')||
    new Set(vals).size!==vals.length)return false;
 }
 const organizations=[
  ...current.map(p=>p.custodianOrganizationId),
  ...DZ_ANCHOR_ROLES.map(r=>dz.anchorPins[r].custodianOrganizationId),
  ...DZ_CUSTODY_ROLES.map(r=>dz.custodyPins[r].custodianOrganizationId),
  ...DY_OVERSIGHT_ROLES.map(r=>dy.oversightPins[r].custodianOrganizationId),
  ...DY_REVIEW_ROLES.map(r=>dy.reviewPins[r].custodianOrganizationId),
  ...DX_SOURCES.map(r=>dx.sourcePins[r].operatorOrganizationId),
  ...DX_RECOVERY_ROLES.map(r=>dx.recoveryPins[r].operatorOrganizationId),
  ...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins[r].custodianOrganizationId),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins[r].custodianOrganizationId)
 ];
 if(new Set(organizations).size!==organizations.length)return false;
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
  phase:'1EA',schemaVersion:1,
  kind:'OFFLINE_UNTRUSTED_GOSSIP_AND_ADMISSION_GATE_HARD_HOLD',
  repository:REPO,
  priorDzToDuOriginalHistoryReverifiedMathematicallyOnly:
   flags.prior===true,
  threeSignedCandidatePeerViewsMathematicallyVerifiedOnly:
   flags.peers??0,
  epochVectorClaimsAgreeWithReverifiedSourceOnly:
   flags.views===true,
  twoFrozenAdmissionReviewSignaturesMathematicallyVerifiedOnly:
   flags.freeze??0,
  localGossipReplayAndForkCandidateInternallyConsistentOnly:
   flags.consistent===true,
  sourceAdmissionAttestationsAreApplicantControlled:true,
  independentlyAuthenticatedExternalPeerEnrollment:false,
  actualHttpsGossipOrPublicationRetrievalPerformed:false,
  actualOffPlatformCasWormObjectLockOrDurableCursorVerified:false,
  actualExternalCertificateTrustAndLiveCrlOcspAuthenticated:false,
  corporateMcaProviderMandateAndExternalReviewAuthenticated:false,
  productionIncidentUnfreezeOrSourceActivationPossible:false,
  noRawViewKeysSignaturesIdentitiesOrNoncesReturned:true,
  productionMutationOrCredentialEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Candidate cryptographic consistency only: zero remote APIs or approval path. */
export function assessOfflineGossipAdmissionBoundaryEa(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,2560*1024)){
  errors.add('EA_EXACT_BOUNDED_INPUT_REQUIRED');
  return hold(errors);
 }
 const {anchorCandidate:dz,previousGossipCursor,admissionClaim,
  peerPins,peerPackets,freezePins,freezePackets,now}=args;
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('EA_EXPLICIT_UTC_CLOCK_REQUIRED');
 let prior=false;
 try{
  const v=assessOfflineCrossEpochAnchorCustodyDz(dz);
  prior=dz?.now===now&&
   v.candidateCrossEpochAndRetentionClaimsCorrelatedMathematicallyOnly&&
   v.anomalyCodes.length===0;
 }catch{prior=false;}
 if(!prior)errors.add('EA_DZ_FULL_SOURCE_NOT_REVERIFIED');
 let claimHash=null;
 try{claimHash=admissionClaimDigestEa(admissionClaim);}
 catch{errors.add('EA_SELF_APPROVAL_OR_ADMISSION_CLAIM_INVALID');}
 const pinsOK=prior&&diverse(peerPins,freezePins,dz);
 if(!pinsOK)errors.add('EA_SIGNER_OPERATOR_OR_ORGANIZATION_COLLISION');
 const previous=dz?.previousAnchor,final=Array.isArray(dz?.epochs)?
  dz.epochs.at(-1)?.record:null,
  original=dz?.admissionCandidate?.decisionCase;
 const expected=dz?.admissionCandidate?.rehearsalCandidate?.custodyCandidate?.
  publicationCandidate?.expected;
 const cursorOK=EXACT(previousGossipCursor,CURSOR)&&
  Number.isSafeInteger(previousGossipCursor.sequence)&&
  previousGossipCursor.sequence>0&&
  /^[a-f0-9]{64}$/.test(previousGossipCursor.digestSha256??'')&&
  Number.isFinite(utc(previousGossipCursor.observedAt))&&
  Number.isFinite(clock)&&
  utc(previousGossipCursor.observedAt)>=clock-900000&&
  utc(previousGossipCursor.observedAt)<=clock+300000&&
  previousGossipCursor.sequence===previous?.sequence&&
  previousGossipCursor.digestSha256===previous?.digestSha256&&
  previousGossipCursor.observedAt===previous?.observedAt;
 if(!cursorOK)errors.add('EA_GOSSIP_CURSOR_REPLAY_ROLLBACK_OR_SUBSTITUTION');
 let expectedView=null,viewSha=null;
 if(prior)try{
  expectedView=candidateEpochViewEa(dz);
  viewSha=epochViewDigestEa(expectedView);
 }catch{errors.add('EA_CANONICAL_EPOCH_VIEW_UNAVAILABLE');}
 const expectedFinal=expectedView?.at(-1);
 const sameEpoch=(view)=>Array.isArray(view)&&Array.isArray(expectedView)&&
  view.length===expectedView.length&&view.every((item,i)=>
   EXACT(item,EPOCH)&&EPOCH.every(k=>item[k]===expectedView[i][k]));
 const fullShape=Array.isArray(peerPackets)&&peerPackets.length===3&&
  EXACT(peerPins,EA_PEER_ROLES);
 if(!fullShape)errors.add('EA_THREE_EXACT_PEER_PACKETS_REQUIRED');
 const peerMap=new Map(),nonces=new Set([
  original?.challengeNonce,original?.reviewNonce,
  ...((Array.isArray(dz?.epochs)?dz.epochs:[]).map(x=>x?.record?.nonce))
 ]);
 let goodPeers=0,allViews=fullShape&&expectedView!==null;
 if(fullShape)for(const packet of peerPackets){
  const s=packet?.statement,role=s?.role;
  if(!EA_PEER_ROLES.includes(role)||peerMap.has(role)||
   !EXACT(packet,PEER_PACKET)||!EXACT(s,PEER_STMT)||
   !bounded(packet,27000)){
   errors.add('EA_PEER_ROLE_OR_PACKET_SCHEMA_INVALID');allViews=false;continue;
  }
  peerMap.set(role,packet);
  const pin=peerPins[role];
  if(!pinOK(pin)||PIN.some(k=>pin[k]!==s[k]))
   errors.add('EA_PEER_DETACHED_KEY_PIN_MISMATCH');
  let observedDigest=null;
  try{observedDigest=epochViewDigestEa(packet.viewEpochs);}
  catch{errors.add('EA_PEER_EPOCH_VECTOR_SCHEMA_INVALID');allViews=false;}
  if(!sameEpoch(packet.viewEpochs)||
   observedDigest!==viewSha||
   s.epochViewSha256!==observedDigest){
   errors.add('EA_SIGNED_PEER_EPOCH_FORK_OR_REPLAY');allViews=false;
  }
  if(s.schemaVersion!==1||s.kind!=='UNTRUSTED_OFFLINE_EPOCH_GOSSIP'||
   s.repository!==REPO||s.decision!=='HOLD'||
   s.incidentId!==original?.incidentId||
   s.organizationId!==expected?.organizationId||
   s.sourceHeadSha!==expected?.sourceHeadSha||
   s.mainBaseSha!==expected?.mainBaseSha||
   s.previousSequence!==previousGossipCursor?.sequence||
   s.previousAnchorSha256!==previousGossipCursor?.digestSha256||
   s.finalSequence!==expectedFinal?.sequence||
   s.finalAnchorSha256!==expectedFinal?.anchorDigestSha256||
   s.evidenceBundleSha256!==final?.evidenceBundleSha256||
   s.authorityInventorySha256!==original?.authorityInventorySha256)
   errors.add('EA_PEER_SIGNED_SOURCE_OR_HOLD_SCOPE_INVALID');
  if(!HEX.test(s.challengeNonce??'')||
   s.challengeNonce==='0'.repeat(64)||nonces.has(s.challengeNonce)){
   errors.add('EA_REPLAYED_PEER_CHALLENGE_NONCE');allViews=false;
  }
  nonces.add(s.challengeNonce);
  if(!fresh(s.observedAt,s.expiresAt,clock,utc(final?.observedAt)))
   errors.add('EA_PEER_FRESHNESS_OR_EXPIRY_INVALID');
  if(!signed(packet,role,peerSigningBytesEa))
   errors.add('EA_PEER_ED25519_OR_SPKI_INVALID');
  else goodPeers++;
 }
 if(fullShape&&peerMap.size!==3)errors.add('EA_PEER_ROLE_QUORUM_INCOMPLETE');
 let quorumSha=null,latestTime=NaN;
 if(peerMap.size===3)try{
  const ordered=EA_PEER_ROLES.map(role=>peerMap.get(role).statement);
  quorumSha=peerQuorumDigestEa(ordered);
  latestTime=Math.max(...ordered.map(s=>utc(s.observedAt)));
 }catch{errors.add('EA_PEER_QUORUM_DIGEST_INVALID');}
 const freezeShape=Array.isArray(freezePackets)&&freezePackets.length===2&&
  EXACT(freezePins,EA_FREEZE_ROLES);
 if(!freezeShape)errors.add('EA_TWO_EXACT_FREEZE_REVIEW_RECEIPTS_REQUIRED');
 let goodFreezes=0;
 const seen=new Set();
 if(freezeShape)for(const packet of freezePackets){
  const s=packet?.statement,role=s?.role;
  if(!EA_FREEZE_ROLES.includes(role)||seen.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,FREEZE_STMT)||
   !bounded(packet,12288)){
   errors.add('EA_FREEZE_REVIEW_ROLE_OR_PACKET_INVALID');continue;
  }
  seen.add(role);
  const pin=freezePins[role];
  if(!pinOK(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('EA_FREEZE_REVIEW_KEY_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_GOSSIP_ADMISSION_FREEZE'||
   s.disposition!=='CONTINUE_FREEZE_NO_AUTHORITY'||
   s.repository!==REPO||s.incidentId!==original?.incidentId||
   s.organizationId!==expected?.organizationId||
   s.sourceHeadSha!==expected?.sourceHeadSha||
   s.mainBaseSha!==expected?.mainBaseSha||
   s.finalSequence!==expectedFinal?.sequence||
   s.finalAnchorSha256!==expectedFinal?.anchorDigestSha256||
   s.evidenceBundleSha256!==final?.evidenceBundleSha256||
   s.epochViewSha256!==viewSha||
   s.peerQuorumSha256!==quorumSha||
   s.admissionClaimSha256!==claimHash||
   s.reviewNonce!==original?.reviewNonce)
   errors.add('EA_FREEZE_SIGNED_SOURCE_OR_UNFREEZE_FORBIDDEN');
  if(!fresh(s.observedAt,s.expiresAt,clock,latestTime))
   errors.add('EA_FREEZE_REVIEW_STALE_OR_PRE_GOSSIP');
  if(!signed(packet,role,freezeSigningBytesEa))
   errors.add('EA_FREEZE_ED25519_OR_SPKI_INVALID');
  else goodFreezes++;
 }
 if(freezeShape&&seen.size!==2)
  errors.add('EA_FREEZE_REVIEW_QUORUM_INCOMPLETE');
 const consistent=prior&&claimHash!==null&&pinsOK&&cursorOK&&
  allViews&&goodPeers===3&&goodFreezes===2&&errors.size===0;
 return hold(errors,{prior,peers:goodPeers,views:allViews,
  freeze:goodFreezes,consistent});
}
