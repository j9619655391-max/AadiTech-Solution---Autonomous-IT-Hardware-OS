import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {REPO} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {candidateSigningBytes,assessDetachedCandidate}
 from '../scripts/phase1cv-policy-freeze-detached-candidate.mjs';
import {
 ROLES,EXTERNAL_ROLES,claimSigningBytes,
 assessCrossRunRecoveryCandidate
} from '../scripts/phase1cw-crossrun-revocation-recovery-candidate.mjs';

const NOW='2026-11-19T22:41:00.000Z',HEAD='a'.repeat(40),
 BASE='b'.repeat(40),POLICY='c'.repeat(64),NONCE='1'.repeat(64);
const hash=x=>createHash('sha256').update(x).digest('hex');
const signed=(role,kind,statement,privateKeys,roster)=>({
 role,keyId:roster[role].keyId,algorithm:'Ed25519',
 signature:sign(null,claimSigningBytes(kind,statement),privateKeys[role])
  .toString('base64')
});
function fixture(){
 const privateKeys={},roster={},operatorPins={},cvRegistry={};
 for(const role of ROLES){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const pem=publicKey.export({format:'pem',type:'spki'}).toString();
  const spki=hash(publicKey.export({format:'der',type:'spki'}));
  const keyId=role.toLowerCase().replaceAll('_','-')+'-v1';
  privateKeys[role]=privateKey;
  roster[role]={keyId,publicKeyPem:pem,spkiSha256:spki,
   validFrom:'2026-11-19T21:00:00.000Z',
   validUntil:'2026-11-20T23:00:00.000Z'};
  operatorPins[role]=spki;
  if(['SECURITY_WITNESS','BUSINESS_WITNESS'].includes(role))
   cvRegistry[role]={...roster[role],revoked:false};
 }
 const snapshot={phase:'1CV',technicalSnapshotConsistent:true,
  currentHeadSha:HEAD,mainBaseSha:BASE,
  pushRunId:101,prRunId:102,
  policyFingerprintSha256:POLICY,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 const cvStatement={schemaVersion:1,kind:'CANDIDATE_OFFREPO_POLICY_FREEZE',
  repository:REPO,sourceHeadSha:HEAD,mainBaseSha:BASE,
  pushRunId:101,prRunId:102,
  policyFingerprintSha256:POLICY,nonce:'d'.repeat(64),
  epoch:43,previousDigest:'e'.repeat(64),
  issuedAt:'2026-11-19T22:36:00.000Z',
  expiresAt:'2026-11-19T22:44:00.000Z',
  releaseDecision:'HOLD'};
 const cvSignatures=['SECURITY_WITNESS','BUSINESS_WITNESS'].map(role=>({
  role,keyId:roster[role].keyId,algorithm:'Ed25519',
  signature:sign(null,candidateSigningBytes(cvStatement),privateKeys[role])
   .toString('base64')
 }));
 const cvEvidence={
  before:structuredClone(snapshot),after:structuredClone(snapshot),
  statement:cvStatement,signatures:cvSignatures,
  registry:cvRegistry,
  checkpoint:{epoch:42,lastDigest:'e'.repeat(64),
   observedAt:'2026-11-19T22:29:00.000Z'}
 };
 const cv=assessDetachedCandidate({...cvEvidence,now:NOW});
 const previous={
  epoch:43,checkpointDigest:cv.detachedCandidateSha256,
  revocationVersion:4,revocationDigest:'f'.repeat(64),
  observedAt:'2026-11-19T22:36:00.000Z'
 };
 const checkpoint={
  schemaVersion:1,repository:REPO,sourceHeadSha:HEAD,
  mainBaseSha:BASE,policyFingerprintSha256:POLICY,
  cvCandidateSha256:cv.detachedCandidateSha256,
  pushRunId:101,prRunId:102,epoch:44,
  previousDigest:cv.detachedCandidateSha256,
  nonce:NONCE,objectVersion:'version_12345',
  archiveDigest:POLICY,primaryRegion:'ap-south-1',
  issuedAt:'2026-11-19T22:37:00.000Z',
  expiresAt:'2026-11-19T22:44:00.000Z'
 };
 const ckDigest=hash(claimSigningBytes('checkpoint',checkpoint));
 const revStatement={schemaVersion:1,repository:REPO,
  checkpointDigest:ckDigest,version:5,previousVersion:4,
  previousDigest:'f'.repeat(64),revokedKeyIds:[],
  issuedAt:'2026-11-19T22:38:00.000Z',
  expiresAt:'2026-11-19T22:46:00.000Z'};
 const revocation={
  statement:revStatement,
  signature:signed('REVOCATION_AUTHORITY','revocation',revStatement,privateKeys,roster)
 };
 const revDigest=hash(claimSigningBytes('revocation',revStatement));
 const witnesses=['CHECKPOINT_WITNESS_A','CHECKPOINT_WITNESS_B'].map(
 (role,index)=>{
  const statement={schemaVersion:1,role,repository:REPO,
   sourceHeadSha:HEAD,checkpointDigest:ckDigest,
   revocationDigest:revDigest,epoch:44,nonce:NONCE,
   endpointHost:index===0?'witness-a.example.org':'witness-b.example.net',
   observedAt:'2026-11-19T22:39:00.000Z',
   expiresAt:'2026-11-19T22:45:00.000Z'
  };
  return {statement,signature:signed(role,'observation',statement,privateKeys,roster)};
 });
 const recStatement={schemaVersion:1,repository:REPO,
  sourceHeadSha:HEAD,checkpointDigest:ckDigest,
  revocationDigest:revDigest,objectVersion:'version_12345',
  archiveDigest:POLICY,primaryRegion:'ap-south-1',
  recoveryRegion:'ap-southeast-1',
  restoreObservedAt:'2026-11-19T22:40:00.000Z',
  retentionUntil:'2027-01-20T22:41:00.000Z',
  restoreSucceeded:true,restoreHashMatches:true,deleteDeniedClaim:true};
 const recovery={statement:recStatement,
  signature:signed('RECOVERY_AUDITOR','recovery',recStatement,privateKeys,roster)};
 return {cvEvidence,roster,operatorPins,previous,checkpoint,
  revocation,witnesses,recovery,now:NOW};
}
const assess=fn=>{const f=fixture();fn?.(f);return assessCrossRunRecoveryCandidate(f)};
function denied(fn,code){
 const r=assess(fn);
 assert.equal(r.candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent,
  false,'unexpected pass');
 assert.ok(r.anomalyCodes.includes(code),
  'wanted '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('CW: six-role fixture, current CV signatures, revocation plus two witnesses and DR remain HOLD',()=>{
 const r=assess();
 assert.equal(r.candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent,
  true,r.anomalyCodes.join('|'));
 assert.equal(r.prior1CVCandidateMathematicallyConsistent,true);
 assert.equal(r.candidateSignedWitnessCount,2);
 assert.match(r.candidateCheckpointDigest,/^[0-9a-f]{64}$/);
 assert.match(r.candidateRevocationDigest,/^[0-9a-f]{64}$/);
 assert.match(r.candidateSnapshotFingerprintSha256,/^[0-9a-f]{64}$/);
 for(const key of [
  'keysAndPinsIndependentlyEnrolledAndRoleMandated',
  'liveSignedRevocationSourceAndRevokedSerialsAuthenticated',
  'independentlyRetrievedDurableMonotonicOffsiteAnchorVerified',
  'separateWitnessEndpointTlsAndOrganizationAuthenticated',
  'crossRunForkOrReplayExternallyQuarantined',
  'actualWormComplianceLockAndDeleteDenialMeasured',
  'offsiteRecoveryRestoreRtoRpoIndependentlyValidated',
  'approvedEmudhraCcaRcaiMcaOrStagingVerified',
  'genuineOidcSlsaWorkloadAttestationVerified',
  'productionReleaseAuthorized'
 ])assert.equal(r[key],false,key);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CW: canonical claim source is domain separated and forbids unsupported input',()=>{
 assert.equal(claimSigningBytes('checkpoint',{z:2,a:1}).toString(),
  'aaditech/phase1cw/checkpoint/v1\n{"a":1,"z":2}');
 assert.throws(()=>claimSigningBytes('evil',{a:1}),/CW_UNSUPPORTED_KIND/);
 assert.throws(()=>claimSigningBytes('checkpoint',{a:1.25}),/CV_UNSUPPORTED_CANONICAL/);
 assert.throws(()=>claimSigningBytes('checkpoint',{a:'x'.repeat(9000)}),
  /CW_UNSUPPORTED_KIND_OR_OVERSIZE/);
});
test('CW: missing or forged preceding CV receipt cannot bootstrap checkpoint',()=>{
 for(const f of [
  x=>{x.cvEvidence.statement.sourceHeadSha='0'.repeat(40)},
  x=>{x.cvEvidence.signatures[0].signature=x.cvEvidence.signatures[1].signature},
  x=>{x.cvEvidence.before.currentHeadSha='9'.repeat(40)},
  x=>{x.cvEvidence.checkpoint.epoch++}
 ])denied(f,'CW_PRECEDING_1CV_CANDIDATE_MATHEMATICS_INVALID');
});
test('CW: candidate from an old source, run pair, archive fingerprint or base denied',()=>{
 for(const change of [
  x=>{x.checkpoint.sourceHeadSha='9'.repeat(40)},
  x=>{x.checkpoint.mainBaseSha='8'.repeat(40)},
  x=>{x.checkpoint.policyFingerprintSha256='7'.repeat(64)},
  x=>{x.checkpoint.archiveDigest='6'.repeat(64)},
  x=>{x.checkpoint.pushRunId=999},
  x=>{x.checkpoint.prRunId=777},
  x=>{x.checkpoint.cvCandidateSha256='5'.repeat(64)}
 ])denied(change,'CW_CHECKPOINT_NOT_BOUND_TO_1CV_SIGNED_FREEZE');
});
test('CW: missing operator pin, unpinned substitution or expired key is refused',()=>{
 for(const fn of [
  x=>{delete x.operatorPins.RECOVERY_AUDITOR},
  x=>{x.operatorPins.CHECKPOINT_WITNESS_A='a'.repeat(64)},
  x=>{x.roster.REVOCATION_AUTHORITY.validUntil='2026-11-19T21:00:00.000Z'},
  x=>{x.roster.BUSINESS_WITNESS.validFrom='2026-11-20T01:00:00.000Z'},
  x=>{x.roster.RECOVERY_AUDITOR.publicKeyPem='invalid'}
 ]){
  const r=assess(fn);
  assert.equal(r.candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CW: CV signer's pinned public key cannot be substituted midstream',()=>{
 denied(x=>{x.cvEvidence.registry.SECURITY_WITNESS.spkiSha256='b'.repeat(64)},
  'CW_PRECEDING_1CV_CANDIDATE_MATHEMATICS_INVALID');
 denied(x=>{x.roster.BUSINESS_WITNESS.keyId='different-business-id'},
  'CW_CV_SIGNER_KEY_OR_PIN_SUBSTITUTED_BUSINESS_WITNESS');
});
test('CW: same key material or key ID across different roles is collusion, not independence',()=>{
 denied(x=>{x.roster.CHECKPOINT_WITNESS_B={...x.roster.CHECKPOINT_WITNESS_A};
  x.operatorPins.CHECKPOINT_WITNESS_B=x.roster.CHECKPOINT_WITNESS_A.spkiSha256},
  'CW_ROLE_KEY_ID_REUSED');
 denied(x=>{x.roster.RECOVERY_AUDITOR.spkiSha256=
  x.roster.REVOCATION_AUTHORITY.spkiSha256;
  x.roster.RECOVERY_AUDITOR.publicKeyPem=
   x.roster.REVOCATION_AUTHORITY.publicKeyPem;
  x.operatorPins.RECOVERY_AUDITOR=x.roster.RECOVERY_AUDITOR.spkiSha256},
  'CW_PIN_KEY_EXPIRY_REVOCATION_OR_ROLE_COLLISION_RECOVERY_AUDITOR');
});
test('CW: old, repeated, skipped or forged checkpoint epoch never passes',()=>{
 for(const fn of [
  x=>{x.checkpoint.epoch=43},
  x=>{x.checkpoint.epoch=45},
  x=>{x.checkpoint.previousDigest='0'.repeat(64)},
  x=>{x.previous.epoch=44},
  x=>{x.previous.checkpointDigest='f'.repeat(64)},
  x=>{x.previous.observedAt='2026-11-19T22:38:00.000Z'}
 ])denied(fn,'CW_CROSS_RUN_CHECKPOINT_REPLAY_ROLLBACK_OR_GAP');
});
test('CW: nonce replay, invalid source schema, expired checkpoint cannot promote',()=>{
 for(const fn of [
  x=>{x.checkpoint.nonce='0'.repeat(64)},
  x=>{x.checkpoint.nonce='not-a-nonce'},
  x=>{x.checkpoint.expiresAt='2026-11-19T22:40:00.000Z'},
  x=>{x.checkpoint.issuedAt='2026-11-19T23:20:00.000Z'},
  x=>{x.checkpoint.repository='other/repo'},
  x=>{x.checkpoint.extra='approve'}
 ])denied(fn,'CW_CHECKPOINT_SOURCE_NONCE_SCHEMA_OR_TTL_INVALID');
});
test('CW: revoked signing key freezes entire chain regardless of other valid signatures',()=>{
 denied(x=>{x.revocation.statement.revokedKeyIds=[
  x.roster.SECURITY_WITNESS.keyId]},
  'CW_ACTIVE_SIGNER_REVOKED_BY_CURRENT_REVOCATION');
 denied(x=>{x.revocation.statement.revokedKeyIds=[
  x.roster.RECOVERY_AUDITOR.keyId]},
  'CW_ACTIVE_SIGNER_REVOKED_BY_CURRENT_REVOCATION');
});
test('CW: revocation source missing, expired, rollback or wrong previous digest denied',()=>{
 for(const fn of [
  x=>{x.revocation.statement.version=4},
  x=>{x.revocation.statement.previousVersion=9},
  x=>{x.revocation.statement.previousDigest='0'.repeat(64)},
  x=>{x.revocation.statement.issuedAt='2026-11-19T22:33:00.000Z'},
  x=>{x.revocation.statement.expiresAt='2026-11-19T22:40:00.000Z'},
  x=>{x.revocation.statement.checkpointDigest='0'.repeat(64)}
 ])denied(fn,'CW_REVOCATION_SOURCE_VERSION_OR_FRESHNESS_INVALID');
});
test('CW: revocation list must be bounded, sorted, distinct, valid key IDs',()=>{
 for(const fn of [
  x=>{x.revocation.statement.revokedKeyIds=['z_revoked','a_revoked']},
  x=>{x.revocation.statement.revokedKeyIds=['a_revoked','a_revoked']},
  x=>{x.revocation.statement.revokedKeyIds=['not valid']},
  x=>{x.revocation.statement.revokedKeyIds=Array.from({length:13},(_,i)=>'key_'+i)},
  x=>{x.revocation.statement.revokedKeyIds='all'}
 ])denied(fn,'CW_REVOCATION_LIST_MALFORMED_OR_DUPLICATE');
});
test('CW: malicious signature, algorithm or detached publisher key is denied',()=>{
 for(const fn of [
  x=>{x.revocation.signature.signature=x.witnesses[0].signature.signature},
  x=>{x.revocation.signature.algorithm='RSA-PSS'},
  x=>{x.revocation.signature.keyId='false-publisher'},
  x=>{x.revocation.signature.signature='a'.repeat(88)}
 ])denied(fn,'CW_REVOCATION_PUBLISHER_SIGNATURE_INVALID');
});
test('CW: witness A/B different hashes are treated as fork or source substitution',()=>{
 for(const fn of [
  x=>{x.witnesses[0].statement.checkpointDigest='0'.repeat(64)},
  x=>{x.witnesses[0].statement.revocationDigest='1'.repeat(64)},
  x=>{x.witnesses[0].statement.sourceHeadSha='0'.repeat(40)},
  x=>{x.witnesses[1].statement.nonce='2'.repeat(64)},
  x=>{x.witnesses[1].statement.epoch=43},
  x=>{x.witnesses[1].statement.observedAt='2026-11-19T22:37:00.000Z'}
 ])denied(fn,'CW_WITNESS_SOURCE_FORK_NONCE_OR_CLOCK_INVALID_'+(
  fn.toString().includes('witnesses[0]')?'CHECKPOINT_WITNESS_A':'CHECKPOINT_WITNESS_B'));
});
test('CW: self-duplicated witness, shared endpoint or wrong witness key denied',()=>{
 denied(x=>{x.witnesses[1].statement.role='CHECKPOINT_WITNESS_A'},
  'CW_UNREVIEWED_OR_DUPLICATED_WITNESS_ROLE');
 denied(x=>{x.witnesses[1].statement.endpointHost=
  x.witnesses[0].statement.endpointHost},'CW_SAME_ASSERTED_WITNESS_ENDPOINT');
 denied(x=>{x.witnesses[0].signature.signature=
  x.witnesses[1].signature.signature},
  'CW_WITNESS_DETACHED_SIGNATURE_INVALID_CHECKPOINT_WITNESS_A');
});
test('CW: absence or extra witness is invalid even if one signature passes',()=>{
 for(const fn of [
  x=>{x.witnesses.pop()},
  x=>{x.witnesses.push(structuredClone(x.witnesses[0]))}
 ])denied(fn,'CW_INDEPENDENT_WITNESS_COUNT_NOT_EXACT_TWO');
});
test('CW: fake recovery, stock/version swap, no retention or no cross-region remains HOLD',()=>{
 for(const fn of [
  x=>{x.recovery.statement.objectVersion='old_version'},
  x=>{x.recovery.statement.archiveDigest='0'.repeat(64)},
  x=>{x.recovery.statement.recoveryRegion='ap-south-1'},
  x=>{x.recovery.statement.retentionUntil='2026-11-25T22:00:00.000Z'},
  x=>{x.recovery.statement.restoreSucceeded=false},
  x=>{x.recovery.statement.restoreHashMatches=false},
  x=>{x.recovery.statement.deleteDeniedClaim=false},
  x=>{x.recovery.statement.restoreObservedAt='2026-11-19T22:38:00.000Z'}
 ])denied(fn,'CW_RECOVERY_VERSION_REGION_RETENTION_OR_RESTORE_INVALID');
});
test('CW: forged independent recovery auditor signature fails even on true claim flags',()=>{
 for(const fn of [
  x=>{x.recovery.signature.signature=x.revocation.signature.signature},
  x=>{x.recovery.signature.keyId='wrong-auditor-id'},
  x=>{x.recovery.signature.algorithm='HS256'}
 ])denied(fn,'CW_RECOVERY_AUDITOR_SIGNATURE_INVALID');
});
test('CW: missing, truncated or random packet never grants GO',()=>{
 for(const x of [{},{now:'not-a-date'},{roster:{},operatorPins:{}},
  {cvEvidence:{statement:{}}},{witnesses:'not-an-array'}]){
  const r=assessCrossRunRecoveryCandidate(x);
  assert.equal(r.candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('CW: no key material or external credentials written into result',()=>{
 const f=fixture(),receipt=assessCrossRunRecoveryCandidate(f);
 const serialized=JSON.stringify(receipt);
 assert.equal(serialized.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(serialized.includes(f.roster.SECURITY_WITNESS.keyId),false);
 assert.equal(serialized.includes(f.roster.REVOCATION_AUTHORITY.keyId),false);
 assert.equal(receipt.productionReleaseBlocked,true);
});
