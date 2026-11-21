import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {canonical,REPO}
 from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {assessOperatorPinLifecycle}
 from '../scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs';
import {OFFICERS,signedBytes,assessMandateForkRecoveryCandidate}
 from '../scripts/phase1cz-corporate-mandate-incident-quarantine.mjs';
import {fixture as cyFixture}
 from './helpers/phase1cz-candidate-fixture.mjs';
const NOW='2026-11-20T00:00:00.000Z';
const sha=x=>createHash('sha256').update(x).digest('hex');
const makeKey=id=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const publicKeyPem=publicKey.export({type:'spki',format:'pem'}).toString();
 const spkiSha256=sha(publicKey.export({type:'spki',format:'der'}));
 return {keyId:id,privateKey,publicKeyPem,spkiSha256};
};
const sig=(kind,role,statement,key)=>({
 role,keyId:key.keyId,algorithm:'Ed25519',
 signature:sign(null,signedBytes(kind,role,statement),key.privateKey).toString('base64')
});
function fixture(){
 const cy=cyFixture(),keys={},org='aaditech-candidate-organization';
 const root=makeKey('corporate-root-candidate-v1');
 const prior=cy.previous.officers;
 const officers={
  SECURITY_OFFICER:structuredClone(prior.SECURITY_OFFICER),
  BUSINESS_OFFICER:structuredClone(prior.BUSINESS_OFFICER)
 };
 keys.SECURITY_OFFICER=cy.privateState.officerKeys.SECURITY_OFFICER;
 keys.BUSINESS_OFFICER=cy.privateState.officerKeys.BUSINESS_OFFICER;
 for(const [role,login] of [
  ['INCIDENT_COMMANDER','candidate-incident'],
  ['RECOVERY_AUDITOR','candidate-recovery']
 ]){
  const k=makeKey(role.toLowerCase().replaceAll('_','-')+'-v1');
  keys[role]=k;
  officers[role]={role,organizationId:org,githubLogin:login,
   mandateDigest:role==='INCIDENT_COMMANDER'?'8'.repeat(64):'9'.repeat(64),
   keyId:k.keyId,publicKeyPem:k.publicKeyPem,spkiSha256:k.spkiSha256,
   validFrom:'2026-11-19T22:00:00.000Z',
   validUntil:'2026-11-21T00:00:00.000Z',revoked:false};
 }
 const authority={root:{
  keyId:root.keyId,publicKeyPem:root.publicKeyPem,
  spkiSha256:root.spkiSha256,organizationId:org,
  enrollmentEvidenceSha256:'3'.repeat(64),
  enrolledAt:'2026-11-19T22:00:00.000Z',
  expiresAt:'2026-11-21T00:00:00.000Z',revoked:false
 },officers};
 const {privateState,...cyEvidence}=cy;
 const assessment=assessOperatorPinLifecycle(cyEvidence);
 const mandate={schemaVersion:1,kind:'CANDIDATE_CORPORATE_MANDATE_HOLD',
  repository:REPO,sourceHeadSha:cy.manifest.currentHeadSha,
  mainBaseSha:cy.manifest.mainBaseSha,
  cyTransitionDigest:assessment.candidateTransitionDigestSha256,
  organizationId:org,officerRosterSha256:sha(canonical(officers)),
  nonce:cy.manifest.nonce,issuedAt:'2026-11-19T23:57:00.000Z',
  expiresAt:'2026-11-20T00:06:00.000Z',decision:'HOLD'};
 const mandateSignature=sig('mandate','ROOT',mandate,root);
 const incident={schemaVersion:1,kind:'FORK_OR_COMPROMISE_REVIEW_ONLY',
  incidentId:'incident-candidate-001',repository:REPO,
  sourceHeadSha:cy.manifest.currentHeadSha,
  previousCheckpointDigest:cy.previous.anchor.checkpointDigest,
  nextCheckpointDigest:cy.observations.REVOCATION.data.statement.checkpointDigest,
  cyTransitionDigest:assessment.candidateTransitionDigestSha256,
  sourceRosterSha256:cy.statement.nextSourceDigest,
  archiveEvidenceSha256:'5'.repeat(64),
  nonce:cy.manifest.nonce,issuedAt:'2026-11-19T23:58:00.000Z',
  expiresAt:'2026-11-20T00:07:00.000Z',decision:'QUARANTINE'};
 const officerApprovals=OFFICERS.map(r=>sig('incident',r,incident,keys[r]));
 const forkWitnesses=['WITNESS_A','WITNESS_B'].map(role=>{
  const s={schemaVersion:1,role,incidentId:incident.incidentId,
   repository:REPO,sourceHeadSha:incident.sourceHeadSha,
   previousCheckpointDigest:incident.previousCheckpointDigest,
   nextCheckpointDigest:incident.nextCheckpointDigest,
   nonce:incident.nonce,
   observedAt:'2026-11-19T23:59:00.000Z',
   decision:'FORK_REVIEW_PENDING'};
  return {statement:s,signature:sig('fork',role,s,
   privateState.priorKeys[role])};
 });
 const rec={schemaVersion:1,kind:'READ_ONLY_REHEARSAL',
  incidentId:incident.incidentId,sourceHeadSha:incident.sourceHeadSha,
  archiveEvidenceSha256:incident.archiveEvidenceSha256,
  objectVersion:'remote-version-123',restoreRegion:'ap-south-1',
  restoreObservedAt:'2026-11-19T23:59:30.000Z',
  restoreHashMatchesClaim:true,deleteDeniedClaim:true,decision:'HOLD'};
 const recovery={statement:rec,
  signatures:['INCIDENT_COMMANDER','RECOVERY_AUDITOR'].map(r=>
   sig('recovery',r,rec,keys[r]))};
 return {cyEvidence,authority,mandate,mandateSignature,
  incident,officerApprovals,forkWitnesses,recovery,now:NOW};
}
function check(change){
 const f=fixture();change?.(f);
 return assessMandateForkRecoveryCandidate(f);
}
function denied(change,code){
 const r=check(change);
 assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes(code),
  'expected '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.quarantineRequired,true);
 assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
}
test('CZ: synthetic root, 4 officers, 2 old witnesses and 2 recovery signatures are candidate-only',()=>{
 const r=check();
 assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.prior1CYOperatorCandidateMathematicallyConsistent,true);
 assert.equal(r.candidateDetachedSignaturesVerified,8);
 assert.match(r.unsignedCandidateMandateDigestSha256,/^[a-f0-9]{64}$/);
 assert.match(r.unsignedCandidateIncidentDigestSha256,/^[a-f0-9]{64}$/);
 assert.match(r.unsignedCandidateRecoveryDigestSha256,/^[a-f0-9]{64}$/);
 assert.equal(r.quarantineRequired,true);
 for(const k of [
  'independentCorporateRootOrLegalKeyEnrollmentVerified',
  'independentSecurityBusinessAndIncidentOfficerMandatesVerified',
  'realNonauthorLatestHeadGithubApprovalsVerified',
  'independentlyFetchedHistoricalWitnessAndForkLogsVerified',
  'immutableCrossRunHighWatermarkOrExternallyEnforcedCasVerified',
  'witnessedActualStorageObjectLockDeleteDenialAndDrRestoreVerified',
  'genuineExternalProviderCaOcspCrlMcaSignatoryAuthorityVerified',
  'signedOidcSlsaSupplyChainAndApprovedStagingVerified',
  'automaticRecoveryOrUnquarantineAllowed','productionReleaseAuthorized'
 ])assert.equal(r[k],false,k);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CZ: role-specific domain separation rejects alternate domain, noninteger JSON and oversize claim',()=>{
 assert.equal(signedBytes('mandate','ROOT',{z:2,a:1}).toString(),
  'aaditech/phase1cz/mandate-incident-quarantine/v1/mandate/ROOT/v1\n{"a":1,"z":2}');
 assert.throws(()=>signedBytes('bad','ROOT',{a:1}),/CZ_UNKNOWN_OR_OVERSIZE/);
 assert.throws(()=>signedBytes('mandate','UNREVIEWED',{a:1}),/CZ_UNKNOWN_OR_OVERSIZE/);
 assert.throws(()=>signedBytes('mandate','ROOT',{x:1.5}),/CX_UNSUPPORTED_CANDIDATE/);
 assert.throws(()=>signedBytes('mandate','ROOT',{x:'x'.repeat(9000)}),
  /CZ_UNKNOWN_OR_OVERSIZE/);
});
test('CZ: counterfeit 1CY receipt, modified source or reported fork never bootstraps mandate',()=>{
 for(const edit of [
  f=>{f.cyEvidence.incidents.status='QUARANTINED'},
  f=>{f.cyEvidence.statement.decision='GO'},
  f=>{f.cyEvidence.manifest.currentHeadSha='0'.repeat(40)},
  f=>{f.cyEvidence.historicalWitnesses.pop()},
  f=>{f.cyEvidence.observations.REVOCATION.data.statement.nonce='0'.repeat(64)}
 ])denied(edit,'CZ_PRECEDING_1CY_CANDIDATE_REVALIDATION_FAILED');
});
test('CZ: unsigned root and forged root candidate signature denied',()=>{
 for(const edit of [
  f=>{f.authority.root.spkiSha256='0'.repeat(64)},
  f=>{f.authority.root.revoked=true},
  f=>{f.authority.root.expiresAt='2026-11-19T23:00:00.000Z'},
  f=>{f.authority.root.publicKeyPem='not-a-public-key'}
 ])denied(edit,'CZ_SELF_SUPPLIED_ROOT_SCHEMA_OR_EXPIRY_INVALID');
 denied(f=>{f.mandateSignature.signature=f.officerApprovals[0].signature},
  'CZ_CANDIDATE_ROOT_MANDATE_SIGNATURE_INVALID');
});
test('CZ: four independent role appointments; no spoofed author, duplicated identities or keys',()=>{
 for(const edit of [
  f=>{f.authority.officers.INCIDENT_COMMANDER.githubLogin='j9619655391-max'},
  f=>{f.authority.officers.INCIDENT_COMMANDER.githubLogin='candidate-security'},
  f=>{f.authority.officers.RECOVERY_AUDITOR.spkiSha256=
   f.authority.officers.INCIDENT_COMMANDER.spkiSha256},
  f=>{f.authority.officers.SECURITY_OFFICER.revoked=true},
  f=>{f.authority.officers.BUSINESS_OFFICER.organizationId='unauthorized-org'},
  f=>{f.authority.officers.RECOVERY_AUDITOR.validUntil='2026-11-19T23:00:00.000Z'}
 ]){
  const r=check(edit);
  assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
 }
});
test('CZ: original Security and Business signer mandates cannot be swapped after CY approval',()=>{
 denied(f=>{f.authority.officers.SECURITY_OFFICER.mandateDigest='0'.repeat(64)},
  'CZ_EXISTING_SECURITY_BUSINESS_MANDATE_SUBSTITUTED_SECURITY_OFFICER');
 denied(f=>{f.authority.officers.BUSINESS_OFFICER.githubLogin='candidate-incident'},
  'CZ_EXISTING_SECURITY_BUSINESS_MANDATE_SUBSTITUTED_BUSINESS_OFFICER');
});
test('CZ: self-provided enrollment digest is not a real authenticated corporate registry',()=>{
 const r=check();
 assert.equal(r.independentCorporateRootOrLegalKeyEnrollmentVerified,false);
 assert.equal(r.independentSecurityBusinessAndIncidentOfficerMandatesVerified,false);
 assert.equal(r.genuineExternalProviderCaOcspCrlMcaSignatoryAuthorityVerified,false);
});
test('CZ: signed mandate must bind exact CY source, main, corporate organization and roster',()=>{
 for(const field of ['sourceHeadSha','mainBaseSha','cyTransitionDigest',
  'organizationId','officerRosterSha256','nonce']){
  denied(f=>{f.mandate[field]='0'.repeat(
   ['sourceHeadSha','mainBaseSha'].includes(field)?40:64)},
   'CZ_ROOT_SIGNED_CORPORATE_MANDATE_SOURCE_INVALID');
 }
});
test('CZ: unknown GO, added field, expired mandate or future issue causes quarantine',()=>{
 for(const edit of [
  f=>{f.mandate.decision='GO'},
  f=>{f.mandate.kind='PRODUCTION_APPROVED'},
  f=>{f.mandate.extra='skip-custody'},
  f=>{f.mandate.issuedAt='2026-11-20T01:00:00.000Z'},
  f=>{f.mandate.expiresAt='2026-11-19T23:59:00.000Z'}
 ])denied(edit,'CZ_ROOT_SIGNED_CORPORATE_MANDATE_SOURCE_INVALID');
});
test('CZ: incident must always be QUARANTINE; substitutions never authorize release',()=>{
 for(const edit of [
  f=>{f.incident.decision='RELEASE'},
  f=>{f.incident.kind='AUTO_RECOVERY'},
  f=>{f.incident.sourceHeadSha='0'.repeat(40)},
  f=>{f.incident.previousCheckpointDigest='0'.repeat(64)},
  f=>{f.incident.nextCheckpointDigest='0'.repeat(64)},
  f=>{f.incident.cyTransitionDigest='0'.repeat(64)},
  f=>{f.incident.sourceRosterSha256='0'.repeat(64)},
  f=>{f.incident.extra='approval'}
 ])denied(edit,'CZ_INCIDENT_CUSTODY_BINDING_OR_QUARANTINE_INVALID');
});
test('CZ: old incident or unknown archive hash is an unbound recovery attempt',()=>{
 denied(f=>{f.incident.archiveEvidenceSha256='not-a-hash'},
  'CZ_INCIDENT_CUSTODY_BINDING_OR_QUARANTINE_INVALID');
 denied(f=>{f.incident.issuedAt='2026-11-19T23:20:00.000Z'},
  'CZ_INCIDENT_CUSTODY_BINDING_OR_QUARANTINE_INVALID');
});
test('CZ: four signer quorum missing, duplicates, wrong role and swapped detached signatures refused',()=>{
 for(const edit of [
  f=>{f.officerApprovals.pop()},
  f=>{f.officerApprovals[1].role='SECURITY_OFFICER'},
  f=>{f.officerApprovals[2].keyId='wrong-id'},
  f=>{f.officerApprovals[0].signature=f.officerApprovals[3].signature},
  f=>{f.officerApprovals[0].algorithm='RSA-PSS'}
 ]){
  const r=check(edit);
  assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
 }
});
test('CZ: previously enrolled source witness must sign fork snapshot, not a new-key surrogate',()=>{
 for(const edit of [
  f=>{f.forkWitnesses[0].signature.signature=f.officerApprovals[0].signature},
  f=>{f.forkWitnesses[0].statement.checkpointDigest='0'.repeat(64)},
  f=>{f.forkWitnesses[0].statement.sourceHeadSha='0'.repeat(40)}
 ]){
  const r=check(edit);
  assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
 }
});
test('CZ: fork witness identity, duplicate or missing prior witness breaks cross-source custody',()=>{
 denied(f=>{f.forkWitnesses[0].statement.nextCheckpointDigest='0'.repeat(64)},
  'CZ_WITNESS_A_HISTORICAL_FORK_CORROBORATION_INVALID');
 denied(f=>{f.forkWitnesses[1].statement.nonce='0'.repeat(64)},
  'CZ_WITNESS_B_HISTORICAL_FORK_CORROBORATION_INVALID');
 denied(f=>{f.forkWitnesses[1].statement.role='WITNESS_A'},
  'CZ_DUPLICATE_OR_UNKNOWN_FORK_WITNESS');
 denied(f=>{f.forkWitnesses.pop()},
  'CZ_TWO_DISTINCT_PREVIOUS_WITNESS_FORK_STATEMENTS_REQUIRED');
});
test('CZ: unsupported fork observation decisions or times quarantine stale evidence',()=>{
 for(const edit of [
  f=>{f.forkWitnesses[0].statement.decision='NO_FORK'},
  f=>{f.forkWitnesses[0].statement.observedAt='2026-11-19T22:00:00.000Z'},
  f=>{f.forkWitnesses[0].statement.observedAt='2026-11-20T01:00:00.000Z'}
 ])denied(edit,'CZ_WITNESS_A_HISTORICAL_FORK_CORROBORATION_INVALID');
});
test('CZ: recovery drill version, region and claimed archive hash cannot be substituted',()=>{
 for(const edit of [
  f=>{f.recovery.statement.archiveEvidenceSha256='0'.repeat(64)},
  f=>{f.recovery.statement.objectVersion='?'},
  f=>{f.recovery.statement.restoreRegion='localhost'},
  f=>{f.recovery.statement.restoreHashMatchesClaim=false},
  f=>{f.recovery.statement.deleteDeniedClaim=false},
  f=>{f.recovery.statement.decision='GO'},
  f=>{f.recovery.statement.restoreObservedAt='2026-11-19T23:00:00.000Z'}
 ])denied(edit,'CZ_RECOVERY_DRY_RUN_ARCHIVE_OR_TIME_INVALID');
});
test('CZ: only commander and auditor may approve dry-run, no auto-unquarantine',()=>{
 for(const edit of [
  f=>{f.recovery.signatures.pop()},
  f=>{f.recovery.signatures[1].role='SECURITY_OFFICER'},
  f=>{f.recovery.signatures[0].signature=f.officerApprovals[1].signature},
  f=>{f.recovery.signatures[0].algorithm='HS256'}
 ]){
  const r=check(edit);
  assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 }
});
test('CZ: missing incumbent root, claims or source never promoted by a fallback',()=>{
 for(const part of [
  {},{authority:{}},{cyEvidence:{}},{mandate:{}},
  {incident:{decision:'QUARANTINE'}},{forkWitnesses:[]}
 ]){
  const r=assessMandateForkRecoveryCandidate(part);
  assert.equal(r.candidateMandateIncidentRecoveryMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('CZ: issued assessment does not disclose candidate signer keys, personal logins or PEM',()=>{
 const f=fixture(),r=assessMandateForkRecoveryCandidate(f);
 const output=JSON.stringify(r);
 assert.equal(output.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(output.includes('candidate-security'),false);
 assert.equal(output.includes(f.authority.root.spkiSha256),false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.quarantineRequired,true);
});
