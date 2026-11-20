import test from 'node:test';
import assert from 'node:assert/strict';
import {sign} from 'node:crypto';
import {assessMandateForkRecoveryCandidate}
 from '../scripts/phase1cz-corporate-mandate-incident-quarantine.mjs';
import {
 STAGES,EVENT_SIGNERS,DOMAIN,evidenceSigningBytes,ledgerEventDigest,
 assessAppendOnlyIncidentReplay
} from '../scripts/phase1da-appendonly-incident-replay-ledger.mjs';
import {fixture as candidateFixture}
 from './helpers/phase1da-candidate-fixture.mjs';

const NOW='2026-11-20T00:00:00.000Z';
function signed(kind,role,statement,key){
 return {role,keyId:key.keyId,algorithm:'Ed25519',
  signature:sign(null,evidenceSigningBytes(kind,role,statement),key.privateKey)
   .toString('base64')};
}
function fixture(){
 const input=candidateFixture();
 const {
  ephemeralTestOnlyOfficerKeys:officerKeys,
  ephemeralTestOnlyPriorWitnessKeys:oldWitnessKeys,
  ...czEvidence
 }=input;
 const prior=assessMandateForkRecoveryCandidate(czEvidence);
 assert.equal(prior.candidateMandateIncidentRecoveryMathematicallyConsistent,
  true,prior.anomalyCodes.join('|'));
 const incident=czEvidence.incident,cy=czEvidence.cyEvidence;
 const anchor={
  schemaVersion:1,repository:incident.repository,
  sourceHeadSha:incident.sourceHeadSha,incidentId:incident.incidentId,
  storeId:'external-candidate-ledger-v1',ledgerVersion:10,
  ledgerDigest:'a'.repeat(64),
  checkpointDigest:incident.nextCheckpointDigest,
  observedAt:'2026-11-19T23:59:00.000Z',
  retentionUntil:'2027-01-20T00:00:00.000Z'
 };
 const evidence=[
  prior.unsignedCandidateIncidentDigestSha256,
  prior.unsignedCandidateMandateDigestSha256,
  prior.unsignedCandidateRecoveryDigestSha256,
  prior.unsignedCandidateIncidentDigestSha256
 ];
 const times=['2026-11-19T23:59:30.000Z',
  '2026-11-19T23:59:35.000Z',
  '2026-11-19T23:59:40.000Z',
  '2026-11-19T23:59:45.000Z'];
 const events=[];let previous=anchor.ledgerDigest;
 for(let i=0;i<STAGES.length;i++){
  const stage=STAGES[i];
  const statement={
   schemaVersion:1,stage,repository:incident.repository,
   sourceHeadSha:incident.sourceHeadSha,
   mainBaseSha:cy.manifest.mainBaseSha,
   incidentId:incident.incidentId,sequence:anchor.ledgerVersion+i+1,
   previousDigest:previous,checkpointDigest:incident.nextCheckpointDigest,
   archiveEvidenceSha256:incident.archiveEvidenceSha256,
   objectVersion:czEvidence.recovery.statement.objectVersion,
   evidenceDigest:evidence[i],recordedAt:times[i],
   decision:i===0?'QUARANTINE':'HOLD'
  };
  const signatures=EVENT_SIGNERS[stage].map(role=>
   signed('incident-event',role,statement,officerKeys[role]));
  events.push({statement,signatures});
  previous=ledgerEventDigest(statement);
 }
 const witnessHeads=['WITNESS_A','WITNESS_B'].map(role=>{
  const statement={
   schemaVersion:1,role,repository:incident.repository,
   sourceHeadSha:incident.sourceHeadSha,incidentId:incident.incidentId,
   ledgerVersion:anchor.ledgerVersion+4,ledgerDigest:previous,
   previousLedgerDigest:anchor.ledgerDigest,
   checkpointDigest:incident.nextCheckpointDigest,
   nonce:cy.manifest.nonce,
   observedAt:'2026-11-19T23:59:50.000Z',decision:'QUARANTINE'
  };
  return {statement,signature:signed('witness-head',role,statement,
   oldWitnessKeys[role])};
 });
 const replay={
  schemaVersion:1,kind:'CANDIDATE_READ_ONLY_REPLAY_HOLD',
  repository:incident.repository,sourceHeadSha:incident.sourceHeadSha,
  incidentId:incident.incidentId,
  startingVersion:anchor.ledgerVersion,startingDigest:anchor.ledgerDigest,
  endingVersion:anchor.ledgerVersion+4,endingDigest:previous,
  archiveEvidenceSha256:incident.archiveEvidenceSha256,
  objectVersion:czEvidence.recovery.statement.objectVersion,
  startedAt:'2026-11-19T23:59:55.000Z',
  finishedAt:'2026-11-19T23:59:58.000Z',
  rollbackAttempt:false,unquarantineRequested:false,releaseDecision:'HOLD'
 };
 const replaySignatures=['INCIDENT_COMMANDER','RECOVERY_AUDITOR'].map(role=>
  signed('replay',role,replay,officerKeys[role]));
 return {czEvidence,anchor,events,witnessHeads,replay,replaySignatures,
  incidentState:{status:'QUARANTINED',forkReports:[],
   releaseRequested:false,restoredExternally:false},
  now:NOW};
}
const assess=edit=>{const x=fixture();edit?.(x);
 return assessAppendOnlyIncidentReplay(x)};
function denied(edit,code){
 const r=assess(edit);
 assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,
  false,'bad packet unexpectedly accepted');
 assert.ok(r.anomalyCodes.includes(code),
  'wanted '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.quarantineRequired,true);
 assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('DA: positive 4-event+12-signature candidate only: always quarantine HOLD',()=>{
 const x=assess();
 assert.equal(x.candidateAppendOnlyIncidentLineageMathematicallyConsistent,true,
  x.anomalyCodes.join('|'));
 assert.equal(x.prior1CZCandidateMathematicallyConsistent,true);
 assert.equal(x.candidateDetachedSignaturesMatched,12);
 assert.equal(x.proposedAnchorVersion,10);
 assert.match(x.proposedFinalLedgerDigestSha256,/^[a-f0-9]{64}$/);
 assert.match(x.candidateIncidentBindingSha256,/^[a-f0-9]{64}$/);
 assert.equal(x.quarantineRequired,true);
 for(const k of [
  'automaticRecoveryOrUnquarantineAllowed',
  'independentlyAuthenticatedCorporateMandateSource',
  'externallyImmutableAppendOnlyLedgerAndCasVerified',
  'independentlyAuthenticatedWitnessArchiveAndForkGossip',
  'actualWormObjectLockDeleteDenialAndRestorationVerified',
  'independentlyApprovedIncidentBreakGlassAndLegalSignoffs',
  'independentCcaRcaiEmudhraMcaCrLOcspProvenanceVerified',
  'actualGithubRulesetsCodeownersNonauthorApprovalsVerified',
  'oidcSlsaCiAndApprovedStagingVerified',
  'productionReleaseAuthorized'
 ])assert.equal(x[k],false,k);
 assert.equal(x.releaseDecision,'HOLD');
});
test('DA: canonical event digest and signature separation enforce exact bytes',()=>{
 const x={z:2,a:1};
 assert.equal(evidenceSigningBytes('replay','RECOVERY_AUDITOR',x).toString(),
  DOMAIN+'replay/RECOVERY_AUDITOR/v1\n{"a":1,"z":2}');
 assert.match(ledgerEventDigest(x),/^[a-f0-9]{64}$/);
 assert.notEqual(ledgerEventDigest({a:1,z:3}),ledgerEventDigest(x));
 assert.throws(()=>evidenceSigningBytes('unsafe','RECOVERY_AUDITOR',x),
  /DA_UNTRUSTED_ROLE_OR_OVERSIZE/);
 assert.throws(()=>evidenceSigningBytes('replay','ROOT',x),
  /DA_UNTRUSTED_ROLE_OR_OVERSIZE/);
 assert.throws(()=>ledgerEventDigest({n:0.3}),/CX_UNSUPPORTED_CANDIDATE/);
 assert.throws(()=>ledgerEventDigest({t:'x'.repeat(9000)}),
  /DA_UNBOUNDED_EVENT_STATEMENT/);
});
test('DA: broken raw CZ root, stale source head or forged signed incident never bootstrap',()=>{
 for(const edit of [
  f=>{f.czEvidence.incident.decision='RELEASE'},
  f=>{f.czEvidence.mandateSignature.signature='a'.repeat(88)},
  f=>{f.czEvidence.cyEvidence.manifest.currentHeadSha='0'.repeat(40)},
  f=>{f.czEvidence.recovery.signatures.pop()},
  f=>{f.czEvidence.forkWitnesses[0].statement.nonce='0'.repeat(64)}
 ])denied(edit,'DA_PRECEDING_1CZ_MANDATE_OR_QUARANTINE_INVALID');
});
test('DA: anchored previous version/ledger hash/store/head/retention must be valid',()=>{
 for(const edit of [
  f=>{f.anchor.schemaVersion=2},
  f=>{f.anchor.ledgerVersion=-1},
  f=>{f.anchor.ledgerDigest='bad'},
  f=>{f.anchor.sourceHeadSha='0'.repeat(40)},
  f=>{f.anchor.checkpointDigest='0'.repeat(64)},
  f=>{f.anchor.storeId='not valid'},
  f=>{f.anchor.retentionUntil='2026-11-25T00:00:00.000Z'},
  f=>{f.anchor.observedAt='2026-11-19T22:00:00.000Z'},
  f=>{f.anchor.extra='PRODUCTION_GO'}
 ])denied(edit,'DA_APPLICANT_HIGHWATERMARK_OR_RETENTION_INVALID');
});
test('DA: replayed old sequence, skipped sequence, duplicate version and false predecessor rejected',()=>{
 for(const edit of [
  f=>{f.events[0].statement.sequence=10},
  f=>{f.events[1].statement.sequence=99},
  f=>{f.events[1].statement.sequence=11},
  f=>{f.events[1].statement.previousDigest='0'.repeat(64)},
  f=>{f.events[2].statement.previousDigest='0'.repeat(64)},
  f=>{f.events[3].statement.sequence=f.events[2].statement.sequence}
 ])denied(edit,'DA_APPEND_EVENT_SEQ_PREDECESSOR_BINDING_OR_CLOCK_INVALID_'+(
  edit.toString().includes('events[0]')?'INCIDENT_OPENED':
  edit.toString().includes('events[1]')?'EVIDENCE_SEALED':
  edit.toString().includes('events[3]')?'RELEASE_DENIED':
  edit.toString().includes('events[2]')?'RECOVERY_REHEARSED':'RELEASE_DENIED'));
});
test('DA: dropped, extra, reordered or duplicated audit event never forms append-only chain',()=>{
 for(const edit of [
  f=>{f.events.pop()},
  f=>{f.events.push(structuredClone(f.events[3]))},
  f=>{[f.events[1],f.events[2]]=[f.events[2],f.events[1]]},
  f=>{f.events[2]=structuredClone(f.events[1])}
 ]){
  const r=assess(edit);
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('DA: immutable four-stage names and decisions cannot be promoted into release',()=>{
 for(const edit of [
  f=>{f.events[0].statement.decision='GO'},
  f=>{f.events[1].statement.decision='UNQUARANTINE'},
  f=>{f.events[3].statement.decision='PRODUCTION_APPROVED'},
  f=>{f.events[2].statement.stage='RECOVERY_SUCCEEDED'},
  f=>{f.events[0].statement.extra='skip-check'}
 ]){
  const r=assess(edit);
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
 }
});
test('DA: event source SHA, base, incident, archive, object and signed evidence cannot drift',()=>{
 for(const prop of ['sourceHeadSha','mainBaseSha','incidentId',
  'checkpointDigest','archiveEvidenceSha256','objectVersion','evidenceDigest']){
  const r=assess(f=>{f.events[2].statement[prop]='altered'});
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,false,prop);
 }
});
test('DA: event clocks cannot regress, replay future or precede prior anchor',()=>{
 for(const [idx,time] of [
  [0,'2026-11-19T23:58:00.000Z'],
  [1,'2026-11-19T23:59:29.000Z'],
  [2,'2026-11-19T22:00:00.000Z'],
  [3,'2026-11-20T02:00:00.000Z']
 ])denied(f=>{f.events[idx].statement.recordedAt=time},
  'DA_APPEND_EVENT_SEQ_PREDECESSOR_BINDING_OR_CLOCK_INVALID_'+STAGES[idx]);
});
test('DA: missing, role-swapped, forged or duplicated signed event approval denies custody',()=>{
 const edits=[
  f=>{f.events[0].signatures.pop()},
  f=>{f.events[0].signatures[0].role='RECOVERY_AUDITOR'},
  f=>{f.events[1].signatures[1].signature=f.events[2].signatures[1].signature},
  f=>{f.events[2].signatures[1].algorithm='HS256'},
  f=>{f.events[3].signatures[0].keyId='wrong-identity'},
  f=>{f.events[3].signatures[1].signature='a'.repeat(88)}
 ];
 for(const edit of edits){
  const r=assess(edit);
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('DA: exact prior witness role quorum required, no duplicate or missing role',()=>{
 denied(f=>{f.witnessHeads.pop()},
  'DA_EXACT_TWO_PREVIOUS_WITNESS_HIGHWATERMARKS_REQUIRED');
 denied(f=>{f.witnessHeads[1].statement.role='WITNESS_A'},
  'DA_DUPLICATE_OR_UNREVIEWED_WITNESS_ROLE');
 denied(f=>{f.witnessHeads.push(structuredClone(f.witnessHeads[0]))},
  'DA_EXACT_TWO_PREVIOUS_WITNESS_HIGHWATERMARKS_REQUIRED');
});
test('DA: witness pin must bind terminal ledger digest, version, previous hash and nonce',()=>{
 for(const prop of ['ledgerVersion','ledgerDigest','previousLedgerDigest',
  'checkpointDigest','nonce','sourceHeadSha','incidentId']){
  const value=prop==='ledgerVersion'?11:'0'.repeat(prop==='sourceHeadSha'?40:64);
  denied(f=>{f.witnessHeads[0].statement[prop]=value},
   'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_WITNESS_A');
 }
});
test('DA: witness signatures are checked against previous source SPKI only',()=>{
 denied(f=>{f.witnessHeads[1].signature.signature=
  f.witnessHeads[0].signature.signature},
  'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_WITNESS_B');
 denied(f=>{f.witnessHeads[0].signature.keyId='surrogate-key'},
  'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_WITNESS_A');
 denied(f=>{f.witnessHeads[1].statement.decision='NO_FORK'},
  'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_WITNESS_B');
});
test('DA: witness timestamps stale, future or before last appended event deny',()=>{
 for(const time of [
  '2026-11-19T23:59:44.000Z',
  '2026-11-19T22:00:00.000Z',
  '2026-11-20T01:00:00.000Z'
 ])denied(f=>{f.witnessHeads[0].statement.observedAt=time},
  'DA_HISTORICAL_WITNESS_LEDGER_GOSSIP_UNVERIFIABLE_WITNESS_A');
});
test('DA: replay cannot silently roll back starting epoch/digest or final head',()=>{
 for(const prop of ['startingVersion','startingDigest','endingVersion',
  'endingDigest','sourceHeadSha','incidentId','archiveEvidenceSha256',
  'objectVersion']){
  denied(f=>{f.replay[prop]=prop.includes('Version')?1:'bad'},
   'DA_REPLAY_ROLLBACK_ARCHIVE_OR_HOLD_INVALID');
 }
});
test('DA: operator replay declares no unquarantine, no rollback, and HOLD only',()=>{
 for(const edit of [
  f=>{f.replay.rollbackAttempt=true},
  f=>{f.replay.unquarantineRequested=true},
  f=>{f.replay.releaseDecision='GO'},
  f=>{f.replay.kind='PRODUCTION_RESTORE'},
  f=>{f.replay.extra='clear-incident'}
 ])denied(edit,'DA_REPLAY_ROLLBACK_ARCHIVE_OR_HOLD_INVALID');
});
test('DA: replay started after both witnesses and finished in bounded window',()=>{
 for(const edit of [
  f=>{f.replay.startedAt='2026-11-19T23:59:49.000Z'},
  f=>{f.replay.finishedAt='2026-11-19T23:59:00.000Z'},
  f=>{f.replay.finishedAt='2026-11-20T01:00:00.000Z'}
 ])denied(edit,'DA_REPLAY_ROLLBACK_ARCHIVE_OR_HOLD_INVALID');
});
test('DA: replay requires commander and recovery auditor distinct valid signatures',()=>{
 for(const edit of [
  f=>{f.replaySignatures.pop()},
  f=>{f.replaySignatures[1].role='SECURITY_OFFICER'},
  f=>{f.replaySignatures[0].signature=
   f.events[0].signatures[0].signature},
  f=>{f.replaySignatures[1].algorithm='RSA-PSS'},
  f=>{f.replaySignatures[0].keyId='false-identity'}
 ]){
  const r=assess(edit);
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('DA: reported fork, cleared state or external restore claim cannot lift quarantine',()=>{
 for(const edit of [
  f=>{f.incidentState.status='CLEAR'},
  f=>{f.incidentState.forkReports=[{fork:'divergence'}]},
  f=>{f.incidentState.releaseRequested=true},
  f=>{f.incidentState.restoredExternally=true},
  f=>{f.incidentState.extra='OK'}
 ])denied(edit,'DA_FORK_REPORT_OR_UNAUTHORIZED_RELEASE_QUARANTINED');
});
test('DA: empty or malformed files cannot be accepted by convenient defaults',()=>{
 for(const input of [{},{now:'bad'},{czEvidence:{}},{events:[]},
  {anchor:{ledgerVersion:42}},{incidentState:{status:'QUARANTINED'}}]){
  const r=assessAppendOnlyIncidentReplay(input);
  assert.equal(r.candidateAppendOnlyIncidentLineageMathematicallyConsistent,
   false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('DA: result contains no PEM, signer login, private key or external authorization',()=>{
 const x=fixture(),r=assessAppendOnlyIncidentReplay(x),out=JSON.stringify(r);
 assert.equal(out.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(out.includes('candidate-security'),false);
 assert.equal(out.includes(x.czEvidence.authority.root.publicKeyPem),false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
