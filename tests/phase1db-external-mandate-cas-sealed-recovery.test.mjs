import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {canonical,REPO}
 from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {assessMandateForkRecoveryCandidate}
 from '../scripts/phase1cz-corporate-mandate-incident-quarantine.mjs';
import {assessAppendOnlyIncidentReplay}
 from '../scripts/phase1da-appendonly-incident-replay-ledger.mjs';
import {
 ROLES,DOMAIN,signingBytes,sealedContentDigest,assessSealedOffsiteCasCandidate
} from '../scripts/phase1db-external-mandate-cas-sealed-recovery.mjs';
import {fixture as daFixture} from './helpers/phase1db-candidate-fixture.mjs';

const NOW='2026-11-20T00:00:00.000Z';
const hash=x=>createHash('sha256').update(x).digest('hex');
function keyRecord(keyId){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const publicKeyPem=publicKey.export({type:'spki',format:'pem'}).toString();
 return {privateKey,keyId,publicKeyPem,
  spkiSha256:hash(publicKey.export({type:'spki',format:'der'}))};
}
function signed(kind,role,statement,key){
 return {role,keyId:key.keyId,algorithm:'Ed25519',
  signature:sign(null,signingBytes(kind,role,statement),key.privateKey)
   .toString('base64')};
}
function fixture(){
 const prior=daFixture();
 const {ephemeralTestOnlyOfficerKeys,
  ephemeralTestOnlyPriorWitnessKeys,...daEvidence}=prior;
 const d=assessAppendOnlyIncidentReplay(daEvidence);
 assert.equal(d.candidateAppendOnlyIncidentLineageMathematicallyConsistent,true,
  d.anomalyCodes.join('|'));
 const cz=daEvidence.czEvidence,cy=cz.cyEvidence,inc=cz.incident;
 const czR=assessMandateForkRecoveryCandidate(cz);
 const sources={},testKeys={};
 const names=[
  'mandate.custody-example.com',
  'journal-primary.custody-example.net',
  'journal-replica.custody-example.org',
  'archive.custody-example.io'
 ];
 const organizations=[
  'candidate-independent-registrar',
  'candidate-journal-primary-org',
  'candidate-journal-replica-org',
  'candidate-archive-auditor-org'
 ];
 for(const [i,role] of ROLES.entries()){
  const key=keyRecord(role.toLowerCase().replaceAll('_','-')+'-candidate-v1');
  testKeys[role]=key;
  sources[role]={
   role,organizationId:organizations[i],host:names[i],
   keyId:key.keyId,publicKeyPem:key.publicKeyPem,
   spkiSha256:key.spkiSha256,tlsSpkiSha256:String(i+3).repeat(64),
   authorityEvidenceSha256:['7','8','9','a'][i].repeat(64),
   validFrom:'2026-11-19T22:00:00.000Z',
   validUntil:'2026-11-21T00:00:00.000Z',revoked:false
  };
 }
 const authorization={
  statement:{
   schemaVersion:1,kind:'EXTERNAL_MANDATE_EVIDENCE_CANDIDATE_HOLD',
   repository:REPO,sourceHeadSha:cy.manifest.currentHeadSha,
   mainBaseSha:cy.manifest.mainBaseSha,incidentId:inc.incidentId,
   mandateDigest:czR.unsignedCandidateMandateDigestSha256,
   officerRosterDigest:hash(canonical(cz.authority.officers)),
   rootSpkiSha256:cz.authority.root.spkiSha256,
   issuerEvidenceSha256:sources.MANDATE_REGISTRAR.authorityEvidenceSha256,
   challengeNonce:cy.manifest.nonce,
   issuedAt:'2026-11-19T23:59:58.500Z',
   expiresAt:'2026-11-20T00:07:00.000Z',decision:'HOLD'
  },signature:null
 };
 authorization.signature=signed('mandate','MANDATE_REGISTRAR',
  authorization.statement,testKeys.MANDATE_REGISTRAR);
 const casReceipts=['JOURNAL_PRIMARY','JOURNAL_REPLICA'].map((role,i)=>{
  const statement={
   schemaVersion:1,kind:'CANDIDATE_CONDITIONAL_CAS_RECEIPT',role,
   repository:REPO,sourceHeadSha:cy.manifest.currentHeadSha,
   incidentId:inc.incidentId,storeId:daEvidence.anchor.storeId,
   challengeNonce:cy.manifest.nonce,
   expectedVersion:daEvidence.anchor.ledgerVersion,
   expectedDigest:daEvidence.anchor.ledgerDigest,
   committedVersion:daEvidence.anchor.ledgerVersion+4,
   committedDigest:d.proposedFinalLedgerDigestSha256,
   archiveDigest:inc.archiveEvidenceSha256,
   objectVersion:cz.recovery.statement.objectVersion,
   precondition:'IF_MATCH_EXACT_DIGEST',
   outcome:'CANDIDATE_CONDITIONAL_COMMIT',
   observedAt:i===0?'2026-11-19T23:59:59.000Z':
    '2026-11-19T23:59:59.100Z',
   decision:'QUARANTINE'
  };
  return {statement,signature:signed('cas',role,statement,testKeys[role])};
 });
 const contentDigest=sealedContentDigest({
  ledgerDigest:d.proposedFinalLedgerDigestSha256,
  archiveEvidenceSha256:inc.archiveEvidenceSha256,
  objectVersion:cz.recovery.statement.objectVersion,
  sourceHeadSha:cy.manifest.currentHeadSha,
  incidentId:inc.incidentId
 });
 const statement={
  schemaVersion:1,kind:'SEALED_RECOVERY_PACKET_CANDIDATE_HOLD',
  repository:REPO,sourceHeadSha:cy.manifest.currentHeadSha,
  incidentId:inc.incidentId,storeId:daEvidence.anchor.storeId,
  committedVersion:daEvidence.anchor.ledgerVersion+4,
  committedDigest:d.proposedFinalLedgerDigestSha256,
  archiveDigest:inc.archiveEvidenceSha256,
  objectVersion:cz.recovery.statement.objectVersion,
  contentDigest,retentionUntil:daEvidence.anchor.retentionUntil,
  lockMode:'COMPLIANCE',legalHoldClaim:true,deleteDeniedClaim:true,
  restoreHashMatchesClaim:true,challengeNonce:cy.manifest.nonce,
  observedAt:'2026-11-19T23:59:59.500Z',
  decision:'HOLD'
 };
 const sealedRecovery={
  statement,signature:signed('sealed-recovery','ARCHIVE_AUDITOR',
   statement,testKeys.ARCHIVE_AUDITOR)
 };
 return {daEvidence,sources,authorization,casReceipts,sealedRecovery,
  dispute:{status:'QUARANTINED',forkReports:[],
   compromisedKeyIds:[],rollbackObserved:false,
   releaseRequested:false,manualOverrideRequested:false},
  now:NOW};
}
const assess=fn=>{const x=fixture();fn?.(x);return assessSealedOffsiteCasCandidate(x);};
function denied(fn,code){
 const r=assess(fn);
 assert.equal(r.candidateFourIndependentSourceSignaturesMathematicallyConsistent,
  false,'unexpected candidate success');
 assert.ok(r.anomalyCodes.includes(code),
  'expected '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.quarantineRequired,true);
 assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('DB: mathematically signed four candidate sources produce HOLD, never independent enrollment',()=>{
 const r=assess();
 assert.equal(r.candidateFourIndependentSourceSignaturesMathematicallyConsistent,
  true,r.anomalyCodes.join('|'));
 assert.equal(r.previous1DAIncidentLedgerCandidateMathematicallyConsistent,true);
 assert.equal(r.locallyVerifiedCandidateSignatures,4);
 assert.match(r.candidateSealedContentDigestSha256,/^[a-f0-9]{64}$/);
 assert.match(r.candidatePreviousLedgerDigest,/^[a-f0-9]{64}$/);
 assert.match(r.candidateCommittedLedgerDigest,/^[a-f0-9]{64}$/);
 for(const k of [
  'independentlyAuthenticatedRegistrarOrganizationAndMandate',
  'sourceSpkiAndTlsPinsExternallyEnrolledAndAuthenticated',
  'externalProviderConditionalCasWritesActuallyExecuted',
  'durableImmutableOffsiteAppendOnlyReadbackAndForkGossipVerified',
  'providerVerifiedObjectLockComplianceDeleteDenialAndDr',
  'legalSecurityBusinessIncidentAndOwnerApprovalsVerified',
  'githubMainRulesetsCodeownersLatestHeadReviewsVerified',
  'caRcaiCcaEmudhraOcspCrlMcaAndStagingVerified',
  'independentOidcSlsaSupplyChainAttestationVerified',
  'productionReleaseAuthorized','automaticRecoveryOrUnquarantineAllowed'
 ])assert.equal(r[k],false,k);
 assert.equal(r.quarantineRequired,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('DB: role-domain separated canonical signing, integer-only and size fail closed',()=>{
 assert.equal(signingBytes('cas','JOURNAL_PRIMARY',{b:2,a:1}).toString(),
  DOMAIN+'cas/JOURNAL_PRIMARY/v1\n{"a":1,"b":2}');
 assert.throws(()=>signingBytes('cas','UNKNOWN',{a:1}),
  /DB_INVALID_DOMAIN_ROLE_OR_SIZE/);
 assert.throws(()=>signingBytes('recovery','ARCHIVE_AUDITOR',{a:1}),
  /DB_INVALID_DOMAIN_ROLE_OR_SIZE/);
 assert.throws(()=>signingBytes('cas','JOURNAL_PRIMARY',{n:0.4}),
  /CX_UNSUPPORTED_CANDIDATE/);
 assert.throws(()=>sealedContentDigest({data:'x'.repeat(3000)}),
  /DB_SEALED_CONTENT_NOT_BOUNDED/);
});
test('DB: full prior DA signature or ledger tamper prevents external source preflight',()=>{
 for(const change of [
  x=>{x.daEvidence.events[1].statement.previousDigest='0'.repeat(64)},
  x=>{x.daEvidence.czEvidence.mandateSignature.signature='a'.repeat(88)},
  x=>{x.daEvidence.incidentState.status='CLEAR'},
  x=>{x.daEvidence.replay.rollbackAttempt=true},
  x=>{x.daEvidence.anchor.ledgerVersion=11}
 ])denied(change,'DB_PRECEDING_1DA_LEDGER_CANDIDATE_FAILED');
});
test('DB: missing, extra or malformed source roster never acts as independent authority',()=>{
 for(const change of [
  x=>{delete x.sources.JOURNAL_REPLICA},
  x=>{x.sources.NEW_ISSUER=structuredClone(x.sources.MANDATE_REGISTRAR)},
  x=>{x.sources='remote approved'},
  x=>{x.sources.MANDATE_REGISTRAR.extra='trusted'}
 ]){
  const r=assess(change);
  assert.equal(r.candidateFourIndependentSourceSignaturesMathematicallyConsistent,false);
 }
});
test('DB: source host cannot be loopback, metadata, URL userinfo or unapproved scheme',()=>{
 for(const host of [
  '127.0.0.1','localhost','169.254.169.254','metadata.internal',
  'bad..org','evil@localhost.com','HOST.example.net',
  'a.com:443','http://foo.example.net','foo.test','internal.local'
 ])denied(x=>{x.sources.MANDATE_REGISTRAR.host=host},
  'DB_SOURCE_PIN_ENROLLMENT_PACKET_INVALID_MANDATE_REGISTRAR');
});
test('DB: source public signing SPKI, TLS pin, role, key ID or expired key invalid',()=>{
 for(const change of [
  x=>{x.sources.JOURNAL_PRIMARY.spkiSha256='0'.repeat(64)},
  x=>{x.sources.JOURNAL_PRIMARY.tlsSpkiSha256='bad'},
  x=>{x.sources.JOURNAL_PRIMARY.role='ARCHIVE_AUDITOR'},
  x=>{x.sources.JOURNAL_PRIMARY.keyId='a bad key'},
  x=>{x.sources.JOURNAL_PRIMARY.publicKeyPem='bad-pem'},
  x=>{x.sources.JOURNAL_PRIMARY.revoked=true},
  x=>{x.sources.JOURNAL_PRIMARY.validUntil='2026-11-19T00:00:00.000Z'}
 ])denied(change,'DB_SOURCE_PIN_ENROLLMENT_PACKET_INVALID_JOURNAL_PRIMARY');
});
test('DB: source operator, organizations, hosts, TLS pins and signing keys must be distinct',()=>{
 for(const key of [
  'organizationId','host','keyId','tlsSpkiSha256','spkiSha256'
 ])denied(x=>{x.sources.JOURNAL_REPLICA[key]=x.sources.JOURNAL_PRIMARY[key]},
  'DB_SOURCE_ORGANIZATION_HOST_OR_KEY_NOT_INDEPENDENT');
});
test('DB: source signer cannot reuse company root, officer or previous witness key',()=>{
 denied(x=>{const r=x.daEvidence.czEvidence.authority.root;
  x.sources.ARCHIVE_AUDITOR.publicKeyPem=r.publicKeyPem;
  x.sources.ARCHIVE_AUDITOR.spkiSha256=r.spkiSha256},
  'DB_SOURCE_REUSES_OFFICER_ROOT_OR_HISTORICAL_WITNESS_KEY');
 denied(x=>{const r=x.daEvidence.czEvidence.authority.officers.SECURITY_OFFICER;
  x.sources.ARCHIVE_AUDITOR.publicKeyPem=r.publicKeyPem;
  x.sources.ARCHIVE_AUDITOR.spkiSha256=r.spkiSha256},
  'DB_SOURCE_REUSES_OFFICER_ROOT_OR_HISTORICAL_WITNESS_KEY');
 denied(x=>{const r=x.daEvidence.czEvidence.cyEvidence.previous.sources.WITNESS_A;
  x.sources.ARCHIVE_AUDITOR.publicKeyPem=r.publicKeyPem;
  x.sources.ARCHIVE_AUDITOR.spkiSha256=r.signerSpkiSha256},
  'DB_SOURCE_REUSES_OFFICER_ROOT_OR_HISTORICAL_WITNESS_KEY');
});
test('DB: registrar receipt must bind existing signed CZ root mandate and officer roster',()=>{
 for(const field of [
  'sourceHeadSha','mainBaseSha','incidentId','mandateDigest',
  'officerRosterDigest','rootSpkiSha256','challengeNonce',
  'issuerEvidenceSha256'
 ])denied(x=>{x.authorization.statement[field]='0'.repeat(64)},
  'DB_EXTERNAL_MANDATE_BOUND_SOURCE_AND_FRESHNESS_INVALID');
});
test('DB: source registrar issuance TTL, GO or extra approval fields denied',()=>{
 for(const change of [
  x=>{x.authorization.statement.kind='PRODUCTION_CLEARED'},
  x=>{x.authorization.statement.decision='GO'},
  x=>{x.authorization.statement.extra='approved'},
  x=>{x.authorization.statement.issuedAt='2026-11-19T22:00:00.000Z'},
  x=>{x.authorization.statement.expiresAt='2026-11-19T23:59:00.000Z'},
  x=>{x.authorization.statement.issuedAt='2026-11-20T00:45:00.000Z'}
 ])denied(change,'DB_EXTERNAL_MANDATE_BOUND_SOURCE_AND_FRESHNESS_INVALID');
});
test('DB: fake registrar key, signature, algorithm or issuer key cannot pass',()=>{
 for(const change of [
  x=>{x.authorization.signature.signature=x.casReceipts[0].signature.signature},
  x=>{x.authorization.signature.keyId='forged-registry-key'},
  x=>{x.authorization.signature.algorithm='HS256'},
  x=>{x.authorization.signature.signature='a'.repeat(88)},
  x=>{delete x.authorization.signature}
 ])denied(change,'DB_EXTERNAL_REGISTRAR_DETACHED_SIGNATURE_INVALID');
});
test('DB: exactly two different conditional-CAS receipts and zero unchecked roles',()=>{
 denied(x=>{x.casReceipts.pop()},
  'DB_EXACT_TWO_CANDIDATE_CAS_RECEIPTS_REQUIRED');
 denied(x=>{x.casReceipts.push(structuredClone(x.casReceipts[0]))},
  'DB_EXACT_TWO_CANDIDATE_CAS_RECEIPTS_REQUIRED');
 denied(x=>{x.casReceipts[1].statement.role='JOURNAL_PRIMARY'},
  'DB_DUPLICATE_OR_UNREVIEWED_CAS_ROLE');
 denied(x=>{x.casReceipts[1].statement.role='INCIDENT_COMMANDER'},
  'DB_DUPLICATE_OR_UNREVIEWED_CAS_ROLE');
});
test('DB: CAS refuses old-version replay, skipped version and wrong predecessor hash',()=>{
 for(const field of [
  'expectedVersion','expectedDigest','committedVersion','committedDigest'
 ])denied(x=>{x.casReceipts[0].statement[field]=
  field.includes('Version')?1:'f'.repeat(64)},
  'DB_CAS_VERSION_IF_MATCH_FORK_OR_CLOCK_INVALID_JOURNAL_PRIMARY');
});
test('DB: CAS IF_MATCH precondition, applied status, nonce, store, archive or head changes fail',()=>{
 for(const field of [
  'precondition','outcome','challengeNonce','storeId','sourceHeadSha',
  'incidentId','archiveDigest','objectVersion','decision'
 ])denied(x=>{x.casReceipts[0].statement[field]='attacker'},
  'DB_CAS_VERSION_IF_MATCH_FORK_OR_CLOCK_INVALID_JOURNAL_PRIMARY');
});
test('DB: CAS witness replica forked hash, version or object causes divergence',()=>{
 for(const field of [
  'committedDigest','expectedDigest','objectVersion','storeId'
 ])denied(x=>{x.casReceipts[1].statement[field]='different'},
  'DB_DIVERGENT_CAS_PRIMARY_REPLICA_HIGHWATERMARK');
});
test('DB: CAS timestamp before replay, future clock or before registrar prohibited',()=>{
 for(const time of [
  '2026-11-19T23:59:57.000Z','2026-11-19T22:00:00.000Z',
  '2026-11-20T01:00:00.000Z'
 ])denied(x=>{x.casReceipts[1].statement.observedAt=time},
  'DB_CAS_VERSION_IF_MATCH_FORK_OR_CLOCK_INVALID_JOURNAL_REPLICA');
});
test('DB: signed CAS cannot borrow a registrar or opposite-role signature',()=>{
 for(const change of [
  x=>{x.casReceipts[0].signature.signature=x.authorization.signature.signature},
  x=>{x.casReceipts[0].signature.signature=x.casReceipts[1].signature.signature},
  x=>{x.casReceipts[0].signature.algorithm='RSA-PSS'},
  x=>{x.casReceipts[0].signature.keyId='another-key'}
 ])denied(change,'DB_CAS_DETACHED_SIGNATURE_INVALID_JOURNAL_PRIMARY');
});
test('DB: sealed recovery binds two signed CAS receipts and exact DA object version',()=>{
 for(const field of [
  'committedVersion','committedDigest','archiveDigest','objectVersion',
  'contentDigest','storeId','sourceHeadSha','incidentId'
 ])denied(x=>{x.sealedRecovery.statement[field]='0'.repeat(64)},
  'DB_SEALED_RETENTION_ARCHIVE_CAS_BINDING_INVALID');
});
test('DB: signed package retention, WORM claims, recorded time and HOLD fail closed',()=>{
 for(const change of [
  x=>{x.sealedRecovery.statement.retentionUntil='2026-11-21T00:00:00.000Z'},
  x=>{x.sealedRecovery.statement.lockMode='GOVERNANCE'},
  x=>{x.sealedRecovery.statement.legalHoldClaim=false},
  x=>{x.sealedRecovery.statement.deleteDeniedClaim=false},
  x=>{x.sealedRecovery.statement.restoreHashMatchesClaim=false},
  x=>{x.sealedRecovery.statement.decision='GO'},
  x=>{x.sealedRecovery.statement.observedAt='2026-11-19T23:59:59.000Z'},
  x=>{x.sealedRecovery.statement.extra='approval'}
 ])denied(change,'DB_SEALED_RETENTION_ARCHIVE_CAS_BINDING_INVALID');
});
test('DB: forged archive auditor signature, key and role never grant accepted package',()=>{
 for(const change of [
  x=>{x.sealedRecovery.signature.signature=x.casReceipts[1].signature.signature},
  x=>{x.sealedRecovery.signature.role='JOURNAL_REPLICA'},
  x=>{x.sealedRecovery.signature.keyId='wrong-auditor'},
  x=>{x.sealedRecovery.signature.algorithm='RSA'}
 ])denied(change,'DB_SEALED_ARCHIVE_DETACHED_SIGNATURE_INVALID');
});
test('DB: fork report, compromised key, observed rollback or override forces quarantine',()=>{
 for(const change of [
  x=>{x.dispute.forkReports=[{observed:'fork'}]},
  x=>{x.dispute.compromisedKeyIds=['some-key']},
  x=>{x.dispute.rollbackObserved=true},
  x=>{x.dispute.releaseRequested=true},
  x=>{x.dispute.manualOverrideRequested=true},
  x=>{x.dispute.status='CLEAR'},
  x=>{x.dispute.extra='root-override'}
 ])denied(change,'DB_FORK_DISPUTE_COMPROMISE_OR_RELEASE_REQUEST_QUARANTINE');
});
test('DB: no packet or malformed operator evidence ever auto-unquarantines',()=>{
 for(const packet of [
  {},{now:'bad'},{daEvidence:{}},{sources:{}},
  {casReceipts:[]},{sealedRecovery:{statement:{}}},
  {authorization:null},{dispute:{status:'QUARANTINED'}}
 ]){
  const r=assessSealedOffsiteCasCandidate(packet);
  assert.equal(r.candidateFourIndependentSourceSignaturesMathematicallyConsistent,
   false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('DB: output excludes source organizations, source SPKIs, PEM and private keys',()=>{
 const p=fixture(),r=assessSealedOffsiteCasCandidate(p),txt=JSON.stringify(r);
 assert.equal(txt.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(txt.includes('candidate-journal-primary-org'),false);
 assert.equal(txt.includes(p.sources.MANDATE_REGISTRAR.spkiSha256),false);
 assert.equal(txt.includes(p.sources.JOURNAL_PRIMARY.host),false);
 assert.equal(r.productionReleaseBlocked,true);
});
