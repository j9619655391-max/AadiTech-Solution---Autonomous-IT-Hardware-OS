import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {assessOfflineMultiEpochRolloverChain}
 from './phase1du-offline-multi-epoch-rollover-chain.mjs';
import {REPO,canonical}
 from './phase1cx-pinned-external-source-highwatermark.mjs';

// Phase 1DV is OFFLINE and deny-only. All comparison pins, archive bytes,
// observer claims, genesis and clocks are applicant-provided. No network
// retrieval, certificate trust, mandate enrollment or state mutation exists.
export const DV_ROLES=Object.freeze([
 'CHECKPOINT_PUBLISHER','INDEPENDENT_ARCHIVE_OBSERVER'
]);
export const DV_DOMAIN='aaditech/phase1dv/offline-observer-publication/v1\n';
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const TOP=['history','observations','comparisonPins','expected',
 'archivePayloadBase64','now'];
const EXPECT=['organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','previousCheckpointSha256','sequence','archiveVersion',
 'archiveSha256','legalMandateDigestSha256','revocationDigestSha256',
 'challengeNonce'];
const PIN=['keyId','spkiSha256','observerId','operatorId','endpointHost',
 'tlsPeerSpkiSha256'];
const PACKET=['statement','publicKeyPem','signature'];
const STATEMENT=['schemaVersion','kind','role','repository',
 'organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','previousCheckpointSha256','sequence',
 'archiveVersion','archiveSha256','legalMandateDigestSha256',
 'revocationDigestSha256','challengeNonce',
 'keyId','spkiSha256','observerId','operatorId','endpointHost',
 'tlsPeerSpkiSha256','httpStatus','redirectCount','observedAt',
 'expiresAt','decision'];
const SHA=/^[0-9a-f]{40}$/,HEX=/^[0-9a-f]{64}$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/,HOST=/^[a-z0-9.-]{5,253}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
function bounded(v,limit){try{
 const s=JSON.stringify(v);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=limit;
}catch{return false;}}
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function validExpected(e){
 return EXACT(e,EXPECT)&&ID.test(e.organizationId??'')&&
  SHA.test(e.sourceHeadSha??'')&&SHA.test(e.mainBaseSha??'')&&
  Number.isSafeInteger(e.sequence)&&e.sequence>0&&
  e.sequence<Number.MAX_SAFE_INTEGER&&
  ID.test(e.archiveVersion??'')&&
  ['checkpointSha256','previousCheckpointSha256','archiveSha256',
   'legalMandateDigestSha256','revocationDigestSha256','challengeNonce']
   .every(k=>HEX.test(e[k]??''))&&
  e.challengeNonce!=='0'.repeat(64);
}
function validPin(p){
 return EXACT(p,PIN)&&
  ['keyId','observerId','operatorId'].every(k=>ID.test(p[k]??''))&&
  HEX.test(p.spkiSha256??'')&&HEX.test(p.tlsPeerSpkiSha256??'')&&
  HOST.test(p.endpointHost??'')&&
  !p.endpointHost.includes('..')&&
  !p.endpointHost.startsWith('.')&&!p.endpointHost.endsWith('.');
}
function distinctPins(pins){
 return DV_ROLES.every(role=>validPin(pins[role]))&&
  PIN.every(key=>pins[DV_ROLES[0]][key]!==pins[DV_ROLES[1]][key]);
}
/** Domain-separated canonical bytes for one UNTRUSTED offline observer statement. */
export function observerSigningBytesDv(statement){
 if(!EXACT(statement,STATEMENT)||!bounded(statement,8192))
  throw Error('DV_INVALID_OBSERVER_SIGNING_SCOPE');
 return Buffer.from(DV_DOMAIN+canonical(statement),'utf8');
}
function signed(packet,statement){
 try{
  if(!EXACT(packet,PACKET)||
   typeof packet.publicKeyPem!=='string'||
   packet.publicKeyPem.length>4096||
   typeof packet.signature!=='string'||!SIG.test(packet.signature))return false;
  const pub=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return pub.asymmetricKeyType==='ed25519'&&
   sig.length===64&&sig.toString('base64')===packet.signature&&
   hash(pub.export({type:'spki',format:'der'}))===statement.spkiSha256&&
   verify(null,observerSigningBytesDv(statement),pub,sig);
 }catch{return false;}
}
function archiveHash(encoded){
 if(typeof encoded!=='string'||encoded.length<4||
    encoded.length>24576||!/^([A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
  return null;
 const bytes=Buffer.from(encoded,'base64');
 return bytes.length>0&&bytes.length<=16384&&
  bytes.toString('base64')===encoded?hash(bytes):null;
}
/**
 * Strictly re-check the full Phase 1DU 2-6 epoch Ed25519 history, then compare
 * its verified terminal v2 checkpoint to TWO differently keyed, role-separated
 * signed observations of the same applicant-provided archive bytes.
 * This verifies MATH only: neither source is fetched or externally enrolled.
 */
export function assessOfflineObserverPublicationCandidate(args={}){
 const anomalies=new Set();
 const valid=EXACT(args,TOP)&&bounded(args,768*1024);
 if(!valid)anomalies.add('DV_EXACT_BOUNDED_INPUT_REQUIRED');
 const {history=null,observations=null,comparisonPins=null,
  expected=null,archivePayloadBase64=null,now=null}=OWN(args)?args:{};
 const clock=utc(now);
 if(!Number.isFinite(clock))anomalies.add('DV_EXPLICIT_UTC_CLOCK_REQUIRED');
 const eValid=validExpected(expected);
 if(!eValid)anomalies.add('DV_EXACT_CHECKPOINT_ARCHIVE_AND_EVIDENCE_PINS_REQUIRED');
 let chainOK=false,terminal=null;
 if(OWN(history)&&EXACT(history,['epochs','now'])&&history.now===now){
  try{
   const proof=assessOfflineMultiEpochRolloverChain(history);
   chainOK=proof.consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly&&
    proof.anomalyCodes.length===0;
   if(chainOK)terminal=history.epochs.at(-1).checkpointObservations[0];
  }catch{chainOK=false;}
 }
 if(!chainOK)anomalies.add('DV_PRECEDING_DU_SIGNED_HISTORY_UNVERIFIED');
 if(chainOK&&eValid&&!(
  terminal.manifest.organizationId===expected.organizationId&&
  terminal.manifest.sourceHeadSha===expected.sourceHeadSha&&
  terminal.manifest.mainBaseSha===expected.mainBaseSha&&
  terminal.manifest.sequence===expected.sequence&&
  terminal.manifest.previousCheckpointSha256===expected.previousCheckpointSha256&&
  terminal.claimedCheckpointSha256===expected.checkpointSha256))
  anomalies.add('DV_TERMINAL_SIGNED_CHECKPOINT_SCOPE_MISMATCH');
 const rawHash=archiveHash(archivePayloadBase64);
 if(!rawHash||!eValid||rawHash!==expected.archiveSha256)
  anomalies.add('DV_SUPPLIED_ARCHIVE_BYTES_OR_DIGEST_INVALID');
 const pins=EXACT(comparisonPins,DV_ROLES)&&distinctPins(comparisonPins);
 if(!pins)anomalies.add('DV_DISTINCT_DETACHED_OBSERVER_PINS_REQUIRED');
 const range=Array.isArray(observations)&&observations.length===2;
 if(!range)anomalies.add('DV_EXACT_TWO_SIGNED_OBSERVATIONS_REQUIRED');
 let verified=0;
 const seen=new Set();
 if(valid&&range)for(const packet of observations){
  const s=packet?.statement,role=s?.role;
  if(!DV_ROLES.includes(role)||seen.has(role)||
    !EXACT(packet,PACKET)||!EXACT(s,STATEMENT)||!bounded(packet,12288)){
   anomalies.add('DV_OBSERVER_ROLE_PACKET_SCHEMA_OR_DUPLICATE');continue;
  }
  seen.add(role);
  const pin=OWN(comparisonPins)?comparisonPins[role]:null;
  const identity=validPin(pin)&&PIN.every(k=>s[k]===pin[k]);
  if(!identity)anomalies.add('DV_OBSERVER_KEY_TLS_OR_OPERATOR_PIN_MISMATCH');
  const binding=eValid&&EXPECT.every(k=>s[k]===expected[k])&&
   s.schemaVersion===1&&
   s.kind==='UNTRUSTED_OFFLINE_OBSERVER_PUBLICATION_CANDIDATE'&&
   s.repository===REPO&&s.decision==='HOLD'&&
   s.httpStatus===200&&s.redirectCount===0;
  if(!binding)anomalies.add('DV_SIGNED_SCOPE_RETRIEVAL_OR_HOLD_INVALID');
  const issued=utc(s.observedAt),expiry=utc(s.expiresAt);
  if(!(Number.isFinite(clock)&&Number.isFinite(issued)&&
    Number.isFinite(expiry)&&issued>=clock-900000&&
    issued<=clock+300000&&expiry>clock&&expiry>issued&&
    expiry<=issued+900000))
   anomalies.add('DV_SIGNED_OBSERVER_TIME_OR_EXPIRY_INVALID');
  if(!signed(packet,s)){
   anomalies.add('DV_OBSERVER_SIGNATURE_OR_SPKI_INVALID');continue;
  }
  verified++;
 }
 if(range&&seen.size!==2)anomalies.add('DV_INCOMPLETE_ROLE_QUORUM');
 // A publication 'observer' must not quietly reuse any witness key that
 // already signed an epoch, even when the signature is mathematically valid.
 if(chainOK&&pins)for(const epoch of history.epochs){
  const w=epoch.checkpointObservations[0].witnesses;
  if(DV_ROLES.some(role=>['LEGAL_WITNESS','REGISTRY_WITNESS']
   .some(k=>comparisonPins[role].spkiSha256===w[k].spkiSha256||
    comparisonPins[role].keyId===w[k].keyId)))
   anomalies.add('DV_OBSERVER_REUSES_CHAIN_WITNESS_IDENTITY');
 }
 const correlated=valid&&chainOK&&eValid&&pins&&range&&
  verified===2&&anomalies.size===0;
 return Object.freeze({
  phase:'1DV',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_OBSERVER_PUBLICATION_AND_ANCHOR_HARD_HOLD',
  repository:REPO,
  fullSignedHistoryReverifiedMathematicallyOnly:chainOK,
  roleSeparatedSignedObserverPacketsMathematicallyVerifiedOnly:verified,
  suppliedArchiveBytesHashMatchedSignedClaimsOnly:
   Boolean(rawHash&&eValid&&rawHash===expected.archiveSha256),
  candidateObserverPublicationCorroboratedMathematicallyOnly:correlated,
  candidateObserverKeysAndTlsPinsCallerControlled:true,
  externalIndependentPublicationAndRetrievalAuthenticated:false,
  externalSignedLegalMandateAndMcaAuthorityAuthenticated:false,
  liveSignedRevocationChainCrlOcspAuthenticated:false,
  externallyAnchoredGenesisAndWormCasHighwatermarkVerified:false,
  trustedObserverClockAndCertificatePolicyVerified:false,
  independentCorporateObserverKeyEnrollmentVerified:false,
  independentReviewerGithubStagingAndDrApprovalVerified:false,
  outputContainsNoRawKeysSignaturesOrArchiveBytes:true,
  productionMutationOrKeyEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
