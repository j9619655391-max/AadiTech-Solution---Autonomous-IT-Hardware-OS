import assert from 'node:assert/strict';
import {sign} from 'node:crypto';
import {assessMandateForkRecoveryCandidate} from '../../scripts/phase1cz-corporate-mandate-incident-quarantine.mjs';
import {STAGES,EVENT_SIGNERS,evidenceSigningBytes,ledgerEventDigest} from '../../scripts/phase1da-appendonly-incident-replay-ledger.mjs';
import {fixture as candidateFixture} from './phase1da-candidate-fixture.mjs';
const NOW='2026-11-20T00:00:00.000Z';
function signed(kind,role,statement,key){
 return {role,keyId:key.keyId,algorithm:'Ed25519',
  signature:sign(null,evidenceSigningBytes(kind,role,statement),key.privateKey)
   .toString('base64')};
}
export function fixture(){
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
  now:NOW,ephemeralTestOnlyOfficerKeys:officerKeys,
  ephemeralTestOnlyPriorWitnessKeys:oldWitnessKeys};
}