import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES,manifestDigestEc}
 from './phase1ec-offline-authority-handoff-custody.mjs';
import {ED_GATE_INTERFACE_CONTRACT,ED_RECEIPT_STATUSES,
 workOrderDigestEd,assessDisconnectedAuthorityVerificationPortEd}
 from './phase1ed-disconnected-authority-verification-ports.mjs';

// Phase 1EE: DISCONNECTED protocol-version and injected failure taxonomy only.
// Never execute provider adapters, fetch external evidence, enroll identity,
// persist a high-watermark, validate MCA/CCA/RCAI/eMudhra or approve release.
export const EE_SUPPORTED_PROTOCOL_VERSION=1;
export const EE_PORT_FAILURE_CLASSES=Object.freeze(Object.fromEntries([
 ['PROVIDER_WRITTEN_AGREEMENT','SIMULATED_PROVIDER_LICENSE_ABSENT'],
 ['APPROVED_SANDBOX_CREDENTIAL_CUSTODY','SIMULATED_SECRET_CUSTODY_MISSING'],
 ['CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY','SIMULATED_ISSUER_POLICY_MISMATCH'],
 ['LIVE_ISSUER_SIGNED_CRL_OCSP','SIMULATED_REVOCATION_STALE'],
 ['MCA_LEGAL_AND_SIGNATORY_MANDATE','SIMULATED_MCA_SIGNATORY_UNVERIFIED'],
 ['INDEPENDENT_KEY_ENROLLMENT','SIMULATED_KEY_CUSTODY_COLLISION'],
 ['AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES','SIMULATED_TLS_SPKI_MISMATCH'],
 ['WORM_CAS_SIGNED_ANTI_EQUIVOCATION','SIMULATED_EXTERNAL_ANCHOR_FORK'],
 ['TRUSTED_TIMESTAMP_SOURCE','SIMULATED_TRUSTED_CLOCK_ABSENT'],
 ['INDEPENDENT_DR_RESTORE_ACCEPTANCE','SIMULATED_DR_RESTORE_REJECTED'],
 ['PROTECTED_MAIN_NONAUTHOR_REVIEWS','SIMULATED_NONAUTHOR_REVIEW_MISSING'],
 ['INDEPENDENT_STAGING_RELEASE_SIGNOFF','SIMULATED_STAGING_SIGNOFF_MISSING']
].map(([gate,specific])=>[gate,Object.freeze(['NOT_ATTEMPTED',specific])])));
if(EC_AUTHORITY_GATES.length!==12||
 EC_AUTHORITY_GATES.some(g=>!EE_PORT_FAILURE_CLASSES[g]))
 throw Error('EE_EXACT_12_GATE_FAULT_MAP_REQUIRED');
const VERSION_DOMAIN='aaditech/phase1ee/disconnected-compatibility-v1\n';
const RECEIPT_DOMAIN='aaditech/phase1ee/ed-local-receipt-v1\n';
const SOURCE_DOMAIN='aaditech/phase1ee/ed-work-receipt-set-v1\n';
const PLAN_DOMAIN='aaditech/phase1ee/negotiation-plan-v1\n';
const FAILURE_DOMAIN='aaditech/phase1ee/local-fault-event-v1\n';
const TOP=['previousPortCandidate','plans','failureEvents','now'];
const RECEIPT=['schemaVersion','kind','gate','portType','workOrderSha256',
 'requestNonce','adapterId','observedEvidenceSha256','status',
 'observedAt','expiresAt','executionMode','networkRequests',
 'authoritiesAuthenticated','sideEffects','releaseDecision'];
const PLAN=['schemaVersion','kind','repository','gate','portType',
 'sourceBundleSha256','workOrderSha256','receiptSha256','compatibilitySha256',
 'requestedVersion','minimumAcceptedVersion','maximumAcceptedVersion',
 'negotiation','fallbackPolicy','adapterExecution','decision'];
const FAILURE=['schemaVersion','kind','gate','planSha256','sequence',
 'previousFailureSha256','faultCode','simulated','networkRequests',
 'authoritiesAuthenticated','sideEffects','retryPolicy',
 'observedAt','expiresAt','disposition','releaseDecision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HEX=/^[0-9a-f]{64}$/;
const HASH=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,n){try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=n;
}catch{return false;}}
function utc(value){
 if(typeof value!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value))return NaN;
 const n=Date.parse(value);
 return Number.isFinite(n)&&new Date(n).toISOString()===value?n:NaN;
}
function fresh(observed,expiry,clock,after){
 const t=utc(observed),x=utc(expiry);
 return Number.isFinite(t)&&Number.isFinite(x)&&
  Number.isFinite(clock)&&t>after&&t>=clock-900000&&
  t<=clock+300000&&x>clock&&x>t&&x-t<=900000;
}
export function compatibilityDigestEe(){
 return HASH(VERSION_DOMAIN+canonical({
  repository:REPO,protocolVersion:EE_SUPPORTED_PROTOCOL_VERSION,
  portContract:ED_GATE_INTERFACE_CONTRACT,
  permittedDisconnectedStatuses:ED_RECEIPT_STATUSES,
  policy:'PINNED_V1_NO_DOWNGRADE_NO_EXTERNAL_AUTHORITY'
 }));
}
export function receiptDigestEe(receipt){
 if(!EXACT(receipt,RECEIPT)||!bounded(receipt,8192)||
  !EC_AUTHORITY_GATES.includes(receipt.gate)||
  receipt.schemaVersion!==1||
  receipt.kind!=='APPLICANT_DISCONNECTED_TEST_DOUBLE_RECEIPT'||
  receipt.portType!==ED_GATE_INTERFACE_CONTRACT[receipt.gate].portType||
  !ED_RECEIPT_STATUSES.includes(receipt.status)||
  receipt.executionMode!=='DISCONNECTED_LOCAL_TEST_DOUBLE'||
  receipt.networkRequests!==0||receipt.authoritiesAuthenticated!==0||
  receipt.sideEffects!==0||receipt.releaseDecision!=='HOLD')
  throw Error('EE_ONLY_DISCONNECTED_ORIGINAL_ED_RECEIPT_ALLOWED');
 return HASH(RECEIPT_DOMAIN+canonical(receipt));
}
/** Exact upstream ED evidence is recomputed before this caller-local bundle. */
export function sourceBundleDigestEe(originalEd){
 if(!OWN(originalEd)||!Array.isArray(originalEd.workOrders)||
  originalEd.workOrders.length!==12||
  !Array.isArray(originalEd.receipts)||originalEd.receipts.length!==12)
  throw Error('EE_EXPECTS_TWELVE_ED_WORK_ORDERS_AND_RECEIPTS');
 const handoff=originalEd.handoffCandidate;
 const payload={
  repository:REPO,
  sourceManifestSha256:manifestDigestEc(handoff.manifest),
  sourceHeadSha:handoff.manifest.sourceHeadSha,
  incidentId:handoff.manifest.incidentId,
  handoffSequence:handoff.manifest.sequence,
  originalEdNow:originalEd.now,
  workOrderSha256:originalEd.workOrders.map(workOrderDigestEd),
  localReceiptSha256:originalEd.receipts.map(receiptDigestEe)
 };
 if(!bounded(payload,16384))throw Error('EE_BOUNDED_SOURCE_REQUIRED');
 return HASH(SOURCE_DOMAIN+canonical(payload));
}
export function planDigestEe(plan){
 if(!EXACT(plan,PLAN)||!bounded(plan,8192))
  throw Error('EE_EXACT_PLAN_REQUIRED');
 return HASH(PLAN_DOMAIN+canonical(plan));
}
export function failureDigestEe(record){
 if(!EXACT(record,FAILURE)||!bounded(record,8192))
  throw Error('EE_EXACT_LOCAL_FAILURE_RECORD_REQUIRED');
 return HASH(FAILURE_DOMAIN+canonical(record));
}
function originalReady(ed,now){
 try{
  const r=assessDisconnectedAuthorityVerificationPortEd(ed);
  return ed?.now===now&&r.syntheticPortProtocolInternallyConsistentOnly===true&&
   r.anomalyCodes.length===0;
 }catch{return false;}
}
function buildPlans(ed){
 const src=sourceBundleDigestEe(ed),version=compatibilityDigestEe();
 return Object.freeze(EC_AUTHORITY_GATES.map((gate,i)=>{
  const plan={
   schemaVersion:1,kind:'DISCONNECTED_PINNED_V1_FAILURE_TEST_PLAN',
   repository:REPO,gate,portType:ED_GATE_INTERFACE_CONTRACT[gate].portType,
   sourceBundleSha256:src,
   workOrderSha256:workOrderDigestEd(ed.workOrders[i]),
   receiptSha256:receiptDigestEe(ed.receipts[i]),
   compatibilitySha256:version,
   requestedVersion:1,minimumAcceptedVersion:1,maximumAcceptedVersion:1,
   negotiation:'PINNED_V1_ONLY',fallbackPolicy:'DENY_NO_DOWNGRADE',
   adapterExecution:'NO_NETWORK_NO_SECRETS',decision:'HOLD'
  };
  return Object.freeze(plan);
 }));
}
/** Prepared frozen test plans, never any live adapter execution or negotiation. */
export function createDisconnectedFailurePlansEe(originalEd){
 if(!OWN(originalEd)||!bounded(originalEd,4096*1024)||
  !originalReady(originalEd,originalEd.now))
  throw Error('EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');
 return buildPlans(originalEd);
}
function hold(errors,d={}){
 return Object.freeze({
  phase:'1EE',schemaVersion:1,
  kind:'DISCONNECTED_VERSION_NEGOTIATION_AND_FAILURE_TAXONOMY_HARD_HOLD',
  repository:REPO,
  precedingEdToDuOriginalHistoryReverifiedMathematicallyOnly:
   d.previous===true,
  exactlyPinnedV1ProtocolPlans:d.plans??0,
  linkedMockFailureEventsMathematicallyConsistentOnly:d.events??0,
  notAttemptedLocalAdapterCount:d.notAttempted??0,
  syntheticVersionAndFailureTranscriptConsistentOnly:d.consistent===true,
  protocolUpgradeDowngradeAndSilentFallbackDenied:true,
  externalAdapterOrNetworkInvocationPerformed:false,
  genuineExternalProviderMcaCcaRcaiEmudhraAuthorityVerified:false,
  realIssuerSignedCrlOcspOrTlsSourceVerified:false,
  independentDurableCasWormGossipOrDrAccepted:false,
  independentLegalSecurityReviewerStagingReleaseAuthorized:false,
  mockFailureDiagnosisCanNeverUnfreezeIncident:true,
  noRawSourceHashesAdapterIdentitiesOrEvidenceReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Every object is applicant-controlled; exact local version/failure checks only. */
export function assessDisconnectedVersionFailureTaxonomyEe(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,4608*1024)){
  errors.add('EE_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {previousPortCandidate:ed,plans,failureEvents,now}=args;
 const nowMs=utc(now);
 if(!Number.isFinite(nowMs))errors.add('EE_EXPLICIT_UTC_CLOCK_REQUIRED');
 const prior=ed?.now===now&&originalReady(ed,now);
 if(!prior)errors.add('EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');
 let expected=null,source=null;
 if(prior)try{
  expected=buildPlans(ed);source=sourceBundleDigestEe(ed);
 }catch{errors.add('EE_SOURCE_OR_PLAN_GENERATION_FAILED');}
 const planShape=Array.isArray(plans)&&plans.length===12&&expected!==null;
 if(!planShape)errors.add('EE_EXACT_TWELVE_VERSION_PLANS_REQUIRED');
 let plansOK=0;
 if(planShape)for(let i=0;i<12;i++){
  const p=plans[i],e=expected[i];
  if(!EXACT(p,PLAN)||!bounded(p,8192)||canonical(p)!==canonical(e)||
   p.requestedVersion!==1||p.minimumAcceptedVersion!==1||
   p.maximumAcceptedVersion!==1||p.fallbackPolicy!=='DENY_NO_DOWNGRADE'||
   p.adapterExecution!=='NO_NETWORK_NO_SECRETS'){
   errors.add('EE_VERSION_DOWNGRADE_UPGRADE_OR_SCOPE_FORK');continue;
  }
  plansOK++;
 }
 const eventShape=Array.isArray(failureEvents)&&failureEvents.length===12;
 if(!eventShape)errors.add('EE_EXACT_TWELVE_FAILURE_EVENTS_REQUIRED');
 let good=0,notAttempted=0;
 let previousSha=source,sequence=0;
 let lastTime=NaN;
 if(prior)try{
  const last=ed.receipts.at(-1);
  lastTime=utc(last.observedAt);
 }catch{}
 if(eventShape)for(let i=0;i<12;i++){
  const e=failureEvents[i],p=expected?.[i],gate=EC_AUTHORITY_GATES[i];
  if(!EXACT(e,FAILURE)||!bounded(e,8192)){
   errors.add('EE_FAILURE_EVENT_SCHEMA_INVALID');continue;
  }
  const typeOK=p!==undefined&&e.schemaVersion===1&&
   e.kind==='APPLICANT_SIMULATED_ADAPTER_FAULT_HOLD'&&
   e.gate===gate&&e.planSha256===planDigestEe(p)&&
   e.sequence===sequence+1&&e.previousFailureSha256===previousSha&&
   EE_PORT_FAILURE_CLASSES[gate].includes(e.faultCode)&&
   e.simulated===true&&e.networkRequests===0&&
   e.authoritiesAuthenticated===0&&e.sideEffects===0&&
   e.retryPolicy==='HOLD_MANUAL_AUTH_REVIEW'&&
   e.disposition==='REMAINS_QUARANTINED'&&e.releaseDecision==='HOLD';
  if(!typeOK)
   errors.add('EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');
  if(!fresh(e.observedAt,e.expiresAt,nowMs,lastTime))
   errors.add('EE_FAILURE_EVENT_ORDER_FRESHNESS_OR_EXPIRY_INVALID');
  if(e.faultCode==='NOT_ATTEMPTED')notAttempted++;
  if(typeOK)good++;
  try{previousSha=failureDigestEe(e);}
  catch{errors.add('EE_FAILURE_EVENT_SCHEMA_INVALID');previousSha=null;}
  lastTime=utc(e.observedAt);
  sequence++;
 }
 const consistent=prior&&planShape&&plansOK===12&&eventShape&&
  good===12&&errors.size===0;
 return hold(errors,{previous:prior,plans:plansOK,events:good,
  notAttempted,consistent});
}
