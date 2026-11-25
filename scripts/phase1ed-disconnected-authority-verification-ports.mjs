import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES,authorityClaimsDigestEc,manifestDigestEc,
 assessOfflineExternalAuthorityHandoffEc}
 from './phase1ec-offline-authority-handoff-custody.mjs';

// No provider network calls, signed CA credentials, actual secret-manager access,
// independent identities, persistent CAS/WORM or release authorization here.
// All requests and receipts below are DISCONNECTED TEST INPUTS only.
const TYPES=[
 ['PROVIDER_CONTRACT',['PROVIDER_SIGNED_CONTRACT','LICENSED_ACCOUNT_AUTHORITY']],
 ['SECRET_CUSTODY',['APPROVED_SECRET_MANAGER','NAMED_CREDENTIAL_OWNER']],
 ['ISSUER_CHAIN',['OFFICIAL_ROOT_CHAIN','CERTIFICATE_POLICY','KU_EKU_SCOPE']],
 ['REVOCATION_STATUS',['ISSUER_SIGNATURE','SERIAL','NONCE','THIS_NEXT_UPDATE','REVOCATION_STATE']],
 ['CORPORATE_LEGAL',['MCA_REGISTRY','CORPORATE_MANDATE','AUTHORIZED_SIGNATORY']],
 ['INDEPENDENT_KEYS',['OUT_OF_BAND_ORGANIZATION_AUTH','KEY_CUSTODY_SEPARATION']],
 ['HTTPS_SOURCE',['TLS_HOSTNAME','CHAIN_AND_SPKI','BOUNDED_BYTES','NO_REDIRECT','SSRF_DENY']],
 ['OFF_PLATFORM_STORAGE',['WORM_OBJECT_LOCK','CAS_HIGHWATERMARK','SIGNED_FORK_GOSSIP','DELETE_DENIAL']],
 ['TRUSTED_TIME',['INDEPENDENT_TIME_SOURCE','SKEW_AND_REPLAY']],
 ['DISASTER_RECOVERY',['ISOLATED_RESTORE','RTO_RPO','RETENTION_AND_DELETE_DENIAL']],
 ['PROTECTED_REPOSITORY',['BRANCH_PROTECTION','CODEOWNERS','TWO_NONAUTHOR_REVIEWS']],
 ['STAGING_RELEASE',['SECURITY_SIGNOFF','BUSINESS_LEGAL_SIGNOFF','OPERATIONS_SIGNOFF']]
];
if(TYPES.length!==EC_AUTHORITY_GATES.length)
 throw Error('ED_GATE_INTERFACE_COUNT_MISMATCH');
export const ED_GATE_INTERFACE_CONTRACT=Object.freeze(Object.fromEntries(
 EC_AUTHORITY_GATES.map((gate,i)=>[gate,Object.freeze({
  portType:TYPES[i][0],requiredChecks:Object.freeze([...TYPES[i][1]])
 })])
));
export const ED_RECEIPT_STATUSES=Object.freeze([
 'NOT_EXECUTED','SIMULATED_MISSING','SIMULATED_REJECTED','SIMULATED_UNVERIFIED'
]);
const WORK_DOMAIN='aaditech/phase1ed/disconnected-work-order/v1\n';
const NONCE_DOMAIN='aaditech/phase1ed/caller-controlled-challenge/v1\n';
const RECEIPT_DOMAIN='aaditech/phase1ed/simulator-receipt/v1\n';
const TOP=['handoffCandidate','workOrders','receipts','now'];
const WORK=['schemaVersion','kind','repository','gate','portType',
 'requiredChecks','organizationId','incidentId','sourceHeadSha','mainBaseSha',
 'manifestSha256','authorityClaimsSha256','handoffSequence',
 'expectedEvidenceSha256','issuedAt','requestNonce','executionPolicy','decision'];
const RECEIPT=['schemaVersion','kind','gate','portType','workOrderSha256',
 'requestNonce','adapterId','observedEvidenceSha256','status',
 'observedAt','expiresAt','executionMode','networkRequests',
 'authoritiesAuthenticated','sideEffects','releaseDecision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HEX=/^[0-9a-f]{64}$/,SHA=/^[0-9a-f]{40}$/,
 ID=/^test_adapter_[a-z0-9_]{6,55}$/;
const HASH=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,n){try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=n;
}catch{return false;}}
function utc(value){
 if(typeof value!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value))
  return NaN;
 const n=Date.parse(value);
 return Number.isFinite(n)&&new Date(n).toISOString()===value?n:NaN;
}
function workValid(w){
 const spec=ED_GATE_INTERFACE_CONTRACT[w?.gate];
 return EXACT(w,WORK)&&bounded(w,8192)&&spec!==undefined&&
  w.schemaVersion===1&&w.kind==='DISCONNECTED_AUTHORITY_WORK_ORDER'&&
  w.repository===REPO&&w.portType===spec.portType&&
  Array.isArray(w.requiredChecks)&&
  w.requiredChecks.length===spec.requiredChecks.length&&
  w.requiredChecks.every((s,i)=>s===spec.requiredChecks[i])&&
  typeof w.organizationId==='string'&&w.organizationId.length<128&&
  typeof w.incidentId==='string'&&w.incidentId.length<128&&
  SHA.test(w.sourceHeadSha??'')&&SHA.test(w.mainBaseSha??'')&&
  HEX.test(w.manifestSha256??'')&&
  HEX.test(w.authorityClaimsSha256??'')&&
  Number.isSafeInteger(w.handoffSequence)&&w.handoffSequence>0&&
  HEX.test(w.expectedEvidenceSha256??'')&&
  HEX.test(w.requestNonce??'')&&w.requestNonce!=='0'.repeat(64)&&
  Number.isFinite(utc(w.issuedAt))&&
  w.executionPolicy==='DISCONNECTED_TEST_ONLY_NO_IO'&&
  w.decision==='HOLD';
}
/** Domain-separated work-order hash is a local binding, NOT a trusted credential. */
export function workOrderDigestEd(workOrder){
 if(!workValid(workOrder))throw Error('ED_EXACT_DISCONNECTED_WORK_ORDER_REQUIRED');
 return HASH(WORK_DOMAIN+canonical(workOrder));
}
function sourceReady(ec,now){
 try{
  const check=assessOfflineExternalAuthorityHandoffEc(ec);
  return ec?.now===now&&
   check.candidateHandoffManifestCorrelatedMathematicallyOnly===true&&
   check.anomalyCodes.length===0;
 }catch{return false;}
}
function buildWorkOrders(ec){
 const m=ec.manifest,claimSha=authorityClaimsDigestEc(ec.authorityClaims),
  manifestSha=manifestDigestEc(m);
 const time=Math.max(...ec.custodyPackets.map(p=>
  utc(p.statement.observedAtCustody)));
 if(!Number.isFinite(time))throw Error('ED_MISSING_CUSTODY_TIME');
 const issuedAt=new Date(time).toISOString();
 return Object.freeze(EC_AUTHORITY_GATES.map(gate=>{
  const spec=ED_GATE_INTERFACE_CONTRACT[gate];
  const requestNonce=HASH(NONCE_DOMAIN+canonical({
   gate,manifestSha,requestChallenge:m.challengeNonce,sequence:m.sequence
  }));
  return Object.freeze({
   schemaVersion:1,kind:'DISCONNECTED_AUTHORITY_WORK_ORDER',
   repository:REPO,gate,portType:spec.portType,
   requiredChecks:spec.requiredChecks,
   organizationId:m.organizationId,incidentId:m.incidentId,
   sourceHeadSha:m.sourceHeadSha,mainBaseSha:m.mainBaseSha,
   manifestSha256:manifestSha,authorityClaimsSha256:claimSha,
   handoffSequence:m.sequence,
   expectedEvidenceSha256:ec.authorityClaims[gate].evidenceSha256,
   issuedAt,requestNonce,
   executionPolicy:'DISCONNECTED_TEST_ONLY_NO_IO',decision:'HOLD'
  });
 }));
}
/** Prepared, NON-executable work orders. Does not call any adapter. */
export function createDisconnectedAuthorityWorkOrdersEd(handoffCandidate){
 if(!OWN(handoffCandidate)||!bounded(handoffCandidate,3584*1024)||
  !sourceReady(handoffCandidate,handoffCandidate.now))
  throw Error('ED_ORIGINAL_EC_HISTORY_NOT_VERIFIED_FOR_OFFLINE_WORK_ORDERS');
 return buildWorkOrders(handoffCandidate);
}
/** A deliberately untrusted local test double. No adapter/network invoked. */
export function createDisconnectedTestReceiptEd(workOrder,{
 adapterId,status='NOT_EXECUTED',observedAt
}={}){
 if(!workValid(workOrder)||!ID.test(adapterId??'')||
  !ED_RECEIPT_STATUSES.includes(status)||!Number.isFinite(utc(observedAt))||
  utc(observedAt)<=utc(workOrder.issuedAt))
  throw Error('ED_INVALID_DISCONNECTED_TEST_DOUBLE_INPUT');
 return Object.freeze({
  schemaVersion:1,kind:'APPLICANT_DISCONNECTED_TEST_DOUBLE_RECEIPT',
  gate:workOrder.gate,portType:workOrder.portType,
  workOrderSha256:workOrderDigestEd(workOrder),
  requestNonce:workOrder.requestNonce,adapterId,
  observedEvidenceSha256:workOrder.expectedEvidenceSha256,
  status,observedAt,
  expiresAt:new Date(utc(observedAt)+600000).toISOString(),
  executionMode:'DISCONNECTED_LOCAL_TEST_DOUBLE',
  networkRequests:0,authoritiesAuthenticated:0,sideEffects:0,
  releaseDecision:'HOLD'
 });
}
function hold(errors,d={}){
 return Object.freeze({
  phase:'1ED',schemaVersion:1,
  kind:'DISCONNECTED_AUTHORITY_VERIFICATION_PORT_PROTOCOL_HARD_HOLD',
  repository:REPO,
  priorEcToDuOriginalHistoryReverifiedMathematicallyOnly:
   d.previous===true,
  exactApplicantOnlyPortWorkOrders:d.orders??0,
  internallyCorrelatedDisconnectedTestReceipts:d.receipts??0,
  notExecutedReceiptCount:d.notExecuted??0,
  syntheticPortProtocolInternallyConsistentOnly:d.consistent===true,
  workOrdersAreNonExecutableAndNoExternalProviderQueried:true,
  realProviderOrMcaMandateAuthenticated:false,
  liveIssuerSignedCrlOcspOrCcaRcaiEmudhraVerified:false,
  actualIndependentTlsEvidenceOrGossipObtained:false,
  realProtectedWormCasObjectLockOrDrAcceptanceVerified:false,
  independentSignerEnrollmentOrStagingReleaseApproved:false,
  applicantSimulatedReceiptCannotBecomeExternalProof:true,
  productionSourceActivationOrCredentialEnrollmentPossible:false,
  noRawEvidenceKeysSourceHashesOrAdapterIdentitiesInReport:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/** Validate caller-submitted MOCK receipts only; never run an external adapter. */
export function assessDisconnectedAuthorityVerificationPortEd(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,4096*1024)){
  errors.add('ED_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {handoffCandidate:ec,workOrders,receipts,now}=args;
 const nowMs=utc(now);
 if(!Number.isFinite(nowMs))errors.add('ED_EXPLICIT_UTC_CLOCK_REQUIRED');
 const prior=ec?.now===now&&sourceReady(ec,now);
 if(!prior)errors.add('ED_ORIGINAL_EC_AUTHORITY_HANDOFF_NOT_REVERIFIED');
 let expected=null;
 if(prior)try{expected=buildWorkOrders(ec);}
 catch{errors.add('ED_WORK_ORDER_GENERATION_FAILED');}
 const exactOrders=Array.isArray(workOrders)&&workOrders.length===12&&
  Array.isArray(expected)&&expected.length===12;
 if(!exactOrders)errors.add('ED_EXACT_TWELVE_WORK_ORDERS_REQUIRED');
 let verifiedOrders=0;
 if(exactOrders)for(let i=0;i<12;i++){
  const a=workOrders[i],b=expected[i];
  if(!workValid(a)||canonical(a)!==canonical(b)){
   errors.add('ED_WORK_ORDER_SOURCE_SCOPE_OR_PORT_DRIFT');
  }else verifiedOrders++;
 }
 const exactReceipts=Array.isArray(receipts)&&receipts.length===12;
 if(!exactReceipts)errors.add('ED_EXACT_TWELVE_RECEIPTS_REQUIRED');
 const adapters=new Set(),nonces=new Set();
 let matched=0,unexecuted=0,previousTime=NaN;
 if(exactReceipts)for(let i=0;i<12;i++){
  const r=receipts[i],w=expected?.[i];
  if(!EXACT(r,RECEIPT)||!bounded(r,8192)){
   errors.add('ED_RECEIPT_EXACT_SCHEMA_REQUIRED');continue;
  }
  const protocolOK=w!==undefined&&
   r.schemaVersion===1&&
   r.kind==='APPLICANT_DISCONNECTED_TEST_DOUBLE_RECEIPT'&&
   r.gate===w.gate&&r.portType===w.portType&&
   r.workOrderSha256===workOrderDigestEd(w)&&
   r.requestNonce===w.requestNonce&&
   r.observedEvidenceSha256===w.expectedEvidenceSha256&&
   r.executionMode==='DISCONNECTED_LOCAL_TEST_DOUBLE'&&
   r.networkRequests===0&&r.authoritiesAuthenticated===0&&
   r.sideEffects===0&&r.releaseDecision==='HOLD';
  if(!protocolOK)errors.add('ED_DISCONNECTED_RESPONSE_SCOPE_OR_FALSE_AUTHORITY');
  if(!ID.test(r.adapterId??'')||adapters.has(r.adapterId)){
   errors.add('ED_DUPLICATE_OR_FORGED_TEST_ADAPTER_ID');
  }
  adapters.add(r.adapterId);
  if(nonces.has(r.requestNonce)){
   errors.add('ED_REPLAYED_REQUEST_NONCE');
  }
  nonces.add(r.requestNonce);
  const type=ec?.authorityClaims?.[r.gate]?.state;
  const allowed=type==='MISSING'?
   ['NOT_EXECUTED','SIMULATED_MISSING']:
   type==='PRESENT_UNVERIFIED'?['SIMULATED_UNVERIFIED']:
   type==='REJECTED'?['SIMULATED_REJECTED']:[];
  if(!allowed.includes(r.status)||!ED_RECEIPT_STATUSES.includes(r.status))
   errors.add('ED_FAKE_VERIFIED_APPROVED_OR_STATUS_DRIFT');
  const t=utc(r.observedAt),x=utc(r.expiresAt);
  if(!Number.isFinite(t)||!Number.isFinite(x)||
   !Number.isFinite(nowMs)||t<=utc(w?.issuedAt)||
   t<nowMs-900000||t>nowMs+300000||
   t<=previousTime||x<=nowMs||x<=t||x-t>900000)
   errors.add('ED_TEST_RECEIPT_TIME_OR_EXPIRY_INVALID');
  previousTime=t;
  if(protocolOK)matched++;
  if(r.status==='NOT_EXECUTED')unexecuted++;
 }
 const consistent=prior&&exactOrders&&verifiedOrders===12&&
  exactReceipts&&matched===12&&adapters.size===12&&
  nonces.size===12&&errors.size===0;
 return hold(errors,{previous:prior,orders:verifiedOrders,
  receipts:matched,notExecuted:unexecuted,consistent});
}
