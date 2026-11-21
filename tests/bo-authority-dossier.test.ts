import test from 'node:test';
import assert from 'node:assert/strict';
import {assessCandidateExternalAuthorityDossier,
 candidateExternalAuthorityDossierDigest} from '../server/commercialIntegrity/quoteAuthorityDossier';
import {boFixtureNow,boExpectedFixture,boDossierFixture,boFixtureSha,boClone}
 from './bo-dossier-fixtures';

const check=(dossier=boDossierFixture(boExpectedFixture()),
 expected=boExpectedFixture(),now=boFixtureNow)=>
 assessCandidateExternalAuthorityDossier({dossier,expected,now});
test('BO: internally consistent four-role candidate dossier never becomes an external authority',()=>{
 const expected=boExpectedFixture(),dossier=boDossierFixture(expected),result=check(dossier,expected);
 assert.equal(result.candidateDossierInternallyConsistent,true,
  result.candidateDossierAnomalyCodes.join(','));
 assert.match(result.candidateDossierSha256!,/^[a-f0-9]{64}$/);
 for(const flag of ['independentProviderAgreementAuthenticated',
  'independentKeyEnrollmentAuthenticated','trustedOutOfBandPublicationHeadVerified',
  'independentWormRetentionVerified','independentRevocationAndCrlOcspVerified',
  'actualEncryptedDrWitnessed','legalSignatoryIdentityVerified',
  'independentReleaseSignoffsVerified','externalAuthorityApproved',
  'productionReleaseAuthorized'] as const)assert.equal(result[flag],false,flag);
 assert.equal(result.releaseDecision,'HOLD');
 assert.equal(result.productionReleaseBlocked,true);
 const clone=boClone(dossier);
 clone.reviews=[...clone.reviews].reverse();
 assert.notEqual(candidateExternalAuthorityDossierDigest(clone),
  candidateExternalAuthorityDossierDigest(dossier));
});
test('BO: mismatch of BN packet, BM signed candidate or quote source fails closed',()=>{
 const expected=boExpectedFixture();
 for(const mutate of [
  (d:ReturnType<typeof boDossierFixture>)=>{d.bnPacketSha256=boFixtureSha('e');},
  (d:ReturnType<typeof boDossierFixture>)=>{d.bmReceiptSha256=boFixtureSha('e');},
  (d:ReturnType<typeof boDossierFixture>)=>{d.quoteSourceSha256=boFixtureSha('e');},
  (d:ReturnType<typeof boDossierFixture>)=>{d.candidatePinsetSha256=boFixtureSha('e');},
  (d:ReturnType<typeof boDossierFixture>)=>{d.quoteId='00000000-0000-4000-8000-000000000000';}
 ]){
  const d=boDossierFixture(expected);mutate(d);
  const result=check(d,expected);
  assert.ok(result.candidateDossierAnomalyCodes.includes(
   'BO_UPSTREAM_BM_BN_HEAD_OR_PINSET_MISMATCH'));
  assert.equal(result.productionReleaseAuthorized,false);
 }
});
test('BO: claimed external retained head, stale/future publication or fake trust state cannot bypass',()=>{
 const e=boExpectedFixture();
 for(const change of [
  {claimedHeadSha256:boFixtureSha('f')},
  {observedAt:'2026-11-17T12:00:00.000Z'},
  {observedAt:'2026-11-17T15:05:00.000Z'},
  {retentionUntil:'2026-11-18T15:00:00.000Z'},
  {publicationState:'VERIFIED' as any}
 ]){
  const d=boDossierFixture(e);Object.assign(d.publication,change);
  const r=check(d,e);
  assert.equal(r.candidateDossierInternallyConsistent,false,JSON.stringify(change));
  assert.equal(r.trustedOutOfBandPublicationHeadVerified,false);
 }
});
test('BO: internally supplied CRL/OCSP evidence is not issuer authentication',()=>{
 const e=boExpectedFixture();
 for(const change of [
  {epoch:3},
  {thisUpdate:'2026-11-17T12:00:00.000Z'},
  {nextUpdate:'2026-11-17T14:00:00.000Z'},
  {revokedKeyIds:['witness-a','witness-a']},
  {revocationState:'AUTHENTICATED' as any},
  {issuerId:''}
 ]){
  const d=boDossierFixture(e);Object.assign(d.revocation,change);
  const r=check(d,e);
  assert.equal(r.candidateDossierInternallyConsistent,false,JSON.stringify(change));
  assert.equal(r.independentRevocationAndCrlOcspVerified,false);
 }
});
test('BO: claimed encrypted DR transcript cannot conceal rollback, fork or fake actual recovery',()=>{
 const e=boExpectedFixture();
 for(const change of [
  {recoveredSequence:1},
  {recoveredSequence:3},
  {restoredReceiptSha256:boFixtureSha('e')},
  {restoredSourceSha256:boFixtureSha('f')},
  {rehearsedAt:'2026-11-16T14:59:00.000Z'},
  {operatorId:'same-witness',witnessId:'same-witness'},
  {recoveryState:'PRODUCTION_VERIFIED' as any},
  {rtoSeconds:-5}
 ]){
  const d=boDossierFixture(e);Object.assign(d.disasterRecovery,change);
  const r=check(d,e);
  assert.equal(r.candidateDossierInternallyConsistent,false,JSON.stringify(change));
  assert.equal(r.actualEncryptedDrWitnessed,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BO: owner/security/legal/operations separation and unverified reviewer decisions are mandatory',()=>{
 const e=boExpectedFixture();
 const wrongs=[
  (d:ReturnType<typeof boDossierFixture>)=>{d.reviews=d.reviews.slice(0,3);},
  (d:ReturnType<typeof boDossierFixture>)=>{d.reviews[0].actorId=d.reviews[1].actorId;},
  (d:ReturnType<typeof boDossierFixture>)=>{d.reviews[0].actorId=d.disasterRecovery.operatorId;},
  (d:ReturnType<typeof boDossierFixture>)=>{d.reviews[0].role='LEGAL';},
  (d:ReturnType<typeof boDossierFixture>)=>{(d.reviews[0] as any).decision='PRODUCTION_APPROVED';},
  (d:ReturnType<typeof boDossierFixture>)=>{(d.reviews[0] as any).signatureTrusted=true;}
 ];
 for(const mutate of wrongs){
  const d=boDossierFixture(e);mutate(d);
  const result=check(d,e);
  assert.ok(result.candidateDossierAnomalyCodes.includes(
   'BO_REVIEW_SEPARATION_OR_AUTHORITY_CLAIM_INVALID'));
 }
});
test('BO: locally quarantined BN/BM and forged trust promotion remain HOLD',()=>{
 const e=boExpectedFixture(),d=boDossierFixture(e);
 for(const override of [
  {bmLocallyConsistent:false},{bnLocallyConsistent:false},
  {bnGovernanceState:'QUARANTINED' as const},
  {bmGovernanceState:'QUARANTINED' as const},
  {bmSequence:0},{bnRevocationEpoch:0}
 ]){
  const r=check(d,boExpectedFixture(override));
  assert.ok(r.candidateDossierAnomalyCodes.includes('BO_INTERNAL_UPSTREAM_NOT_ACCEPTABLE'));
  assert.equal(r.externalAuthorityApproved,false);
 }
 const illegal=boClone(d) as any;illegal.externalSendAllowed=true;
 assert.ok(check(illegal,e).candidateDossierAnomalyCodes.includes(
  'BO_DOSSIER_SHAPE_OR_BINDING_INVALID'));
});
