/**
 * Phase 1BJ: deny-only classification of applicant-provided commercial provenance.
 * This function deliberately NEVER verifies signatures, company identity or title.
 * A positive shape check is insufficient to authorize external actions.
 */
const SHA=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const ALLOWED=new Set(['CUSTOMER_QUOTE','SUPPLIER_QUOTE','SUPPLIER_PO','WAREHOUSE_RECEIPT']);
const CODE=Object.freeze({
 INVALID_RECORD:'INVALID_RECORD',INVALID_SCOPE:'INVALID_SCOPE',INVALID_DIGEST:'INVALID_DIGEST',
 INVALID_TIME:'INVALID_TIME',EXPIRED:'EXPIRED',FUTURE_ISSUE:'FUTURE_ISSUE',
 UNSAFE_REFERENCE:'UNSAFE_REFERENCE',REPLAY:'REPLAY',MISSING_INDEPENDENT_AUTHORITY:'MISSING_INDEPENDENT_AUTHORITY'
});
const safe=(s,max)=>typeof s==='string' && s.length>0 && s.length<=max && /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(s) && !s.includes('..') && !s.includes('//');
export function classifyApplicantCommercialEvidence(record,options={}){
 const problems=[];
 const r=record && typeof record==='object' && !Array.isArray(record)?record:null;
 if(!r) problems.push(CODE.INVALID_RECORD);
 if(!r || !ALLOWED.has(r.kind) || !UUID.test(r.subjectId??'') || !UUID.test(r.actorId??'')) problems.push(CODE.INVALID_SCOPE);
 if(!r || !SHA.test(r.sha256??'') || !SHA.test(r.subjectSnapshotSha256??'')) problems.push(CODE.INVALID_DIGEST);
 if(!r || !safe(r.reference,160) || !safe(r.issuerClaim,160)) problems.push(CODE.UNSAFE_REFERENCE);
 const now=options.nowMs, issued=r?.issuedAt, expires=r?.expiresAt;
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(issued)||!Number.isSafeInteger(expires)||issued>=expires||expires-issued>31*86400000) problems.push(CODE.INVALID_TIME);
 else {
  if(expires<=now)problems.push(CODE.EXPIRED);
  if(issued>now)problems.push(CODE.FUTURE_ISSUE);
 }
 const replay=options.seenDigests;
 if(!Array.isArray(replay) || replay.some(x=>!SHA.test(x)) || (r && replay.includes(r.sha256))) problems.push(CODE.REPLAY);
 problems.push(CODE.MISSING_INDEPENDENT_AUTHORITY);
 return Object.freeze({
  locallyWellFormed:problems.length===1,
  provenanceClass:'APPLICANT_ASSERTED_UNVERIFIED',
  anomalies:Object.freeze([...new Set(problems)]),
  externallyAuthenticated:false,
  releaseDecision:'HOLD',productionReleaseBlocked:true,productionReleaseAuthorized:false,
  mayIssueCustomerQuote:false,mayDispatchSupplierPO:false,mayPostStock:false
 });
}
