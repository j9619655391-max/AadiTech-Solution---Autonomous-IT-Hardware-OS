import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {candidateQuotePinsetDigest,canonicalCandidateQuoteObservation,
 canonicalCandidateQuoteRollover,assessCandidateQuoteHeadReconciliation,
 candidateQuoteReconciliationDigest,type CandidateHeadObservation,
 type CandidateHeadObservationBody,type CandidateKeyRolloverBody}
 from '../server/commercialIntegrity/quoteHeadReconciliation';
import type {CandidatePinnedKey} from '../server/commercialIntegrity/quoteAnchors';

const quote='11111111-1111-4111-8111-111111111111';
const sha=(c:string)=>c.repeat(64);
const receipt=sha('a'),source=sha('b');
const now=new Date('2026-11-17T12:05:00.000Z');
const clone=<T>(x:T):T=>structuredClone(x);
function key(id:string){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pin:CandidatePinnedKey={
  keyId:id,publicKeySpkiPem:publicKey.export({type:'spki',format:'pem'}).toString(),
  status:'ACTIVE',validFrom:'2026-01-01T00:00:00.000Z',
  validUntil:'2028-01-01T00:00:00.000Z'
 };
 return {pin,privateKey};
}
const a=key('candidate-a'),b=key('candidate-b'),c=key('candidate-new');
function observe(w:ReturnType<typeof key>,sourceId:string,change:Record<string,any>={}){
 const body:CandidateHeadObservationBody={
  format:'aaditech-quote-head-observation-v1',quoteId:quote,
  sourceId,keyId:w.pin.keyId,sequence:2,receiptSha256:receipt,sourceSha256:source,
  publishedAt:'2026-11-17T12:00:00.000Z',observedAt:'2026-11-17T12:04:00.000Z',
  revocationEpoch:4,revokedKeyIds:[],
  revocationThisUpdate:'2026-11-17T11:50:00.000Z',
  revocationNextUpdate:'2026-11-17T12:20:00.000Z',...change
 };
 return {body,signatureBase64:sign(null,
  Buffer.from(canonicalCandidateQuoteObservation(body)),w.privateKey).toString('base64')};
}
function args(){
 return {quoteId:quote,checkpointSequence:2,checkpointReceiptSha256:receipt,
  checkpointSourceSha256:source,observations:[
   observe(a,'candidate-witness-one'),observe(b,'candidate-witness-two')],
  pinnedKeys:[a.pin,b.pin],now};
}
const evaluate=(input:ReturnType<typeof args>)=>assessCandidateQuoteHeadReconciliation(input);
test('BN: two self-signed candidate claims and exact DR comparison remain untrusted HOLD',()=>{
 const x=args();
 const pass=assessCandidateQuoteHeadReconciliation({...x,
  recoverySnapshot:{sequence:2,receiptSha256:receipt,sourceSha256:source}});
 assert.equal(pass.candidateReconciliationConsistent,true,
  pass.candidateReconciliationAnomalyCodes.join(','));
 assert.equal(pass.candidateDrRehearsalInspected,true);
 assert.equal(pass.independentlyPublishedHeadVerified,false);
 assert.equal(pass.authenticatedRevocationAuthorityVerified,false);
 assert.equal(pass.realEncryptedDrRecoveryWitnessed,false);
 assert.equal(pass.independentRollbackProofVerified,false);
 assert.equal(pass.productionReleaseAuthorized,false);
 assert.equal(pass.releaseDecision,'HOLD');
 assert.match(candidateQuoteReconciliationDigest({observations:x.observations}),
  /^[a-f0-9]{64}$/);
 assert.equal(candidateQuotePinsetDigest([a.pin,b.pin]),
  candidateQuotePinsetDigest([b.pin,a.pin]));
});
test('BN: mutually signed split heads, stale/forward source and quote mixup fail closed',()=>{
 const x=args();
 for(const change of [
  {receiptSha256:sha('f')},
  {sequence:1},
  {sequence:3},
  {sourceSha256:sha('f')},
  {quoteId:'00000000-0000-4000-8000-000000000000'},
  {publishedAt:'2026-11-16T12:00:00.000Z'},
  {observedAt:'2026-11-17T12:07:00.000Z'}
 ]){
  const result=evaluate({...x,observations:[
   x.observations[0],observe(b,'candidate-witness-two',change)]});
  assert.equal(result.candidateReconciliationConsistent,false,JSON.stringify(change));
  assert.equal(result.productionReleaseAuthorized,false);
 }
});
test('BN: revocation disagreements, expired windows, revoked signer and signer collision reject',()=>{
 const x=args();
 const cases=[
  [x.observations[0],observe(b,'candidate-witness-two',{revocationEpoch:5})],
  [x.observations[0],observe(b,'candidate-witness-two',
   {revokedKeyIds:['candidate-b']})],
  [x.observations[0],observe(b,'candidate-witness-two',
   {revocationNextUpdate:'2026-11-17T12:00:00.000Z'})],
  [x.observations[0],observe(a,'other-claimed-source')],
  [x.observations[0],observe(b,'candidate-witness-one')]
 ];
 for(const observations of cases){
  const result=evaluate({...x,observations});
  assert.equal(result.candidateReconciliationConsistent,false);
  assert.equal(result.authenticatedRevocationAuthorityVerified,false);
 }
 const forged=clone(x.observations[1]);forged.signatureBase64=Buffer.alloc(64,5).toString('base64');
 assert.ok(evaluate({...x,observations:[x.observations[0],forged]}).
  candidateReconciliationAnomalyCodes.includes('BN_OBSERVATION_SIGNATURE_INVALID'));
 const shadow=clone(x.observations[1]) as any;shadow.body.dispatchAllowed=true;
 assert.ok(evaluate({...x,observations:[x.observations[0],shadow]}).
  candidateReconciliationAnomalyCodes.includes('BN_OBSERVATION_SHAPE_INVALID'));
});
test('BN: dual-signed candidate rollover is not an independent approval',()=>{
 const x=args(),body:CandidateKeyRolloverBody={
  format:'aaditech-quote-key-rollover-v1',quoteId:quote,
  oldKeyId:'candidate-a',newKeyId:'candidate-new',
  receiptSha256:receipt,effectiveAt:'2026-11-17T12:02:00.000Z',
  reason:'Candidate dual-control rollover rehearsal'
 };
 const rollover={
  body,oldSignatureBase64:sign(null,
   Buffer.from(canonicalCandidateQuoteRollover(body)),a.privateKey).toString('base64'),
  newSignatureBase64:sign(null,
   Buffer.from(canonicalCandidateQuoteRollover(body)),c.privateKey).toString('base64')
 };
 const pass=assessCandidateQuoteHeadReconciliation({...x,
  pinnedKeys:[a.pin,b.pin,c.pin],rollover});
 assert.equal(pass.candidateReconciliationConsistent,true,
  pass.candidateReconciliationAnomalyCodes.join(','));
 assert.equal(pass.candidateRolloverSignaturesConsistent,true);
 assert.equal(pass.authenticatedWitnessAuthorityVerified,false);
 assert.equal(pass.productionReleaseAuthorized,false);
 const tampered=clone(rollover);tampered.newSignatureBase64=rollover.oldSignatureBase64;
 const denied=assessCandidateQuoteHeadReconciliation({...x,
  pinnedKeys:[a.pin,b.pin,c.pin],rollover:tampered});
 assert.ok(denied.candidateReconciliationAnomalyCodes.includes(
  'BN_ROLLOVER_DUAL_SIGNATURE_INVALID'));
 const revoked=assessCandidateQuoteHeadReconciliation({...x,
  pinnedKeys:[a.pin,b.pin,{...c.pin,status:'REVOKED'}],rollover});
 assert.ok(revoked.candidateReconciliationAnomalyCodes.includes(
  'BN_ROLLOVER_KEY_INACTIVE_OR_REVOKED'));
});
test('BN: candidate DR rehearsals refuse restore-point rollback and forged restored head',()=>{
 const x=args();
 const older=assessCandidateQuoteHeadReconciliation({...x,
  recoverySnapshot:{sequence:1,receiptSha256:sha('c'),sourceSha256:source}});
 assert.ok(older.candidateReconciliationAnomalyCodes.includes(
  'BN_DR_REHEARSAL_ROLLBACK_DETECTED'));
 const fork=assessCandidateQuoteHeadReconciliation({...x,
  recoverySnapshot:{sequence:2,receiptSha256:sha('f'),sourceSha256:source}});
 assert.ok(fork.candidateReconciliationAnomalyCodes.includes(
  'BN_DR_REHEARSAL_HEAD_MISMATCH'));
 const future=assessCandidateQuoteHeadReconciliation({...x,
  recoverySnapshot:{sequence:4,receiptSha256:sha('f'),sourceSha256:source}});
 assert.ok(future.candidateReconciliationAnomalyCodes.includes(
  'BN_DR_REHEARSAL_HEAD_MISMATCH'));
 assert.equal(future.realEncryptedDrRecoveryWitnessed,false);
});
test('BN: malformed pinset, missing candidate source and wrong signature cannot attest release',()=>{
 const x=args();
 assert.equal(evaluate({...x,observations:[x.observations[0]]}).
  candidateReconciliationConsistent,false);
 const dup=evaluate({...x,pinnedKeys:[a.pin,a.pin]});
 assert.ok(dup.candidateReconciliationAnomalyCodes.includes('BN_PINSET_INVALID'));
 const unpinned=evaluate({...x,pinnedKeys:[a.pin,c.pin]});
 assert.ok(unpinned.candidateReconciliationAnomalyCodes.includes(
  'BN_WITNESS_KEY_REVOKED_OR_UNPINNED'));
 assert.throws(()=>candidateQuotePinsetDigest([]));
});
