import test from 'node:test';
import assert from 'node:assert/strict';
import {assessPhase1BbEvidenceIntake,phase1BbSignedBytes}
 from '../scripts/lib/phase1BbEvidenceIntake.mjs';
import {fixture,h,now} from './support/phase1bbFixture.mjs';

const assess=x=>assessPhase1BbEvidenceIntake(x);
test('six signed local fixture records are internally consistent but never externally authenticated',()=>{
 const f=fixture(),r=assess(f);
 assert.equal(r.internalEvidenceConsistent,true,r.blockerCodes.join(','));
 assert.equal(r.signedClaimsChecked,6);
 assert.equal(r.challengeDigests.length,6);
 assert.match(r.batchSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.independentSourcesAuthenticated,false);
 assert.equal(r.independentChallengeIssuanceVerified,false);
 assert.equal(r.keyCustodyAuthenticated,false);
 assert.equal(r.externalImmutabilityVerified,false);
 assert.equal(r.realDRWitnessed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('deterministic signed batch commitment is invariant under record order, not under tamper',()=>{
 const a=fixture();
 const first=assess(a);
 assert.equal(assess({...a,records:[...a.records].reverse()}).batchSha256,first.batchSha256);
 const bad=fixture();bad.records[0].body.evidenceSha256=h(700);
 const r=assess(bad);
 assert.notEqual(r.batchSha256,first.batchSha256);
 assert.equal(r.internalEvidenceConsistent,false);
 assert.ok(r.blockerCodes.includes('EVIDENCE_DIGEST_OR_SUBJECT_MISMATCH'));
});
test('zero evidence and incomplete quorum cannot produce an ingestion authorization',()=>{
 const empty=assess();
 assert.equal(empty.batchSha256,null);
 assert.equal(empty.productionReleaseAuthorized,false);
 assert.ok(empty.blockerCodes.includes('MISSING_SIX_DOMAIN_EVIDENCE_RECORDS'));
 const f=fixture();
 const incomplete=assess({...f,records:f.records.slice(0,5)});
 assert.equal(incomplete.internalEvidenceConsistent,false);
 assert.equal(incomplete.productionReleaseBlocked,true);
});
test('forged detached signature or unregistered key swap blocked',()=>{
 const f=fixture();f.records[0].signature.signatureBase64=Buffer.alloc(64,1).toString('base64');
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('INVALID_DETACHED_EVIDENCE_SIGNATURE'));
 assert.equal(r.internalEvidenceConsistent,false);
 const swap=fixture();swap.records[0].body.publicKeySha256=h(200);
 const r2=assess(swap);
 assert.ok(r2.blockerCodes.includes('WITNESS_ENROLLMENT_PIN_NOT_MATCHED'));
 assert.ok(r2.blockerCodes.includes('INVALID_DETACHED_EVIDENCE_SIGNATURE'));
});
test('cross-signer nonce replay and claimed administrative overlap are denied',()=>{
 const f=fixture();f.records[1].body.challengeSha256=f.records[0].body.challengeSha256;
 f.records[1].body.authorityRef=f.records[0].body.authorityRef;
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('REPLAYED_CHALLENGE_OR_SHARED_AUTHORITY'));
 assert.equal(r.internalEvidenceConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('source evidence hash must match Phase 1AZ witness policy, storage hold and each review',()=>{
 for(const index of [0,2,3,4,5]){
  const f=fixture();
  f.records[index].body.evidenceSha256=h(201+index);
  const r=assess(f);
  assert.ok(r.blockerCodes.includes('EVIDENCE_DIGEST_OR_SUBJECT_MISMATCH'));
  assert.equal(r.internalEvidenceConsistent,false);
 }
});
test('AZ digest and log substitutions cannot cross over between evidence packets',()=>{
 const f=fixture();f.records[0].body.packetSha256=h(300);
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('PACKET_OR_LOG_BINDING_MISMATCH'));
 const g=fixture();g.records[1].body.logRef='different-checkpoint-log';
 assert.ok(assess(g).blockerCodes.includes('PACKET_OR_LOG_BINDING_MISMATCH'));
});
test('role smuggling, credential/raw proof injection and GO switches fail on exact schema',()=>{
 const f=fixture();
 for(const change of [
  {...f.records[0].body,privateKey:'SECRET'},
  {...f.records[0].body,signedUrl:'https://example.invalid/secret'},
  {...f.records[0].body,releaseDecision:'GO'},
  {...f.records[0].body,authorityState:'AUTHENTICATED'},
  {...f.records[0].body,sourceRole:'PROVIDER_ADMIN'},
  {...f.records[0].body,subjectSha256:'0'.repeat(64)},
  {...f.records[0].body,expiresAt:'2026-11-17T18:00:00.000Z'}
 ])assert.throws(()=>phase1BbSignedBytes(change));
});
test('expired, future, and duplicate reviewer identities quarantine internal batch',()=>{
 for(const change of [
  {expiresAt:'2026-11-16T17:45:00.000Z'},
  {issuedAt:'2026-11-16T20:00:00.000Z',expiresAt:'2026-11-16T20:30:00.000Z'},
  {sourceRef:'witness-first-001'}
 ]){
  const f=fixture();
  Object.assign(f.records[1].body,change);
  const r=assess(f);
  assert.equal(r.internalEvidenceConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
