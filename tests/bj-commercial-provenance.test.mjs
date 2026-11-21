import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyApplicantCommercialEvidence as classify} from '../server/commercialIntegrity/applicantEvidence.mjs';
const uuid='11111111-1111-4111-8111-111111111111';
const sha='a'.repeat(64), other='b'.repeat(64);
const base=()=>({kind:'SUPPLIER_QUOTE',subjectId:uuid,actorId:uuid,sha256:sha,subjectSnapshotSha256:other,reference:'RFQ-123',issuerClaim:'vendor.example',issuedAt:1000,expiresAt:2000});
const opts=()=>({nowMs:1500,seenDigests:[]});
test('even coherent applicant evidence cannot be independently authenticated or release any business action',()=>{
 const r=classify(base(),opts());
 assert.equal(r.locallyWellFormed,true);
 assert.equal(r.externallyAuthenticated,false);
 assert.equal(r.provenanceClass,'APPLICANT_ASSERTED_UNVERIFIED');
 assert.deepEqual(r.anomalies,['MISSING_INDEPENDENT_AUTHORITY']);
 for(const k of ['productionReleaseAuthorized','mayIssueCustomerQuote','mayDispatchSupplierPO','mayPostStock']) assert.equal(r[k],false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('changed digest, mismatched subject, replay and malicious references are never accepted',()=>{
 const mutations=[
  [x=>x.sha256='INVALID','INVALID_DIGEST'],
  [x=>x.subjectId='foreign','INVALID_SCOPE'],
  [x=>x.reference='../unsafe','UNSAFE_REFERENCE'],
  [x=>x.issuerClaim='https://user:pass@example','UNSAFE_REFERENCE'],
  [x=>x.expiresAt=1499,'EXPIRED'],
  [x=>x.issuedAt=1501,'FUTURE_ISSUE']
 ];
 for(const [mutate,expected] of mutations){const x=base();mutate(x);const r=classify(x,opts());assert.ok(r.anomalies.includes(expected),expected);assert.equal(r.productionReleaseBlocked,true);}
 const r=classify(base(),{...opts(),seenDigests:[sha]});
 assert.ok(r.anomalies.includes('REPLAY'));
 assert.equal(r.locallyWellFormed,false);
});
test('missing record, malformed local clock or unspecified replay register fail closed',()=>{
 for(const [record,options] of [[null,opts()],[base(),{}],[base(),{nowMs:1500}]]){
  const r=classify(record,options);
  assert.equal(r.locallyWellFormed,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
