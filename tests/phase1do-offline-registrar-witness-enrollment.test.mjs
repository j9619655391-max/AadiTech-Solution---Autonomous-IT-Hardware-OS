import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {ROLES,candidateSigningBytes,
 assessOfflineCorporateAppointmentCandidate}
 from '../scripts/phase1dm-corporate-appointment-challenge-handoff.mjs';
import {deriveEphemeralReviewerRoleBinding,
 assessEphemeralReviewerHandoffContinuity}
 from '../scripts/phase1dl-ephemeral-reviewer-handoff-continuity.mjs';
import {assessInProcessAppointmentReviewerBinding}
 from '../scripts/phase1dn-corporate-role-session-reconciliation.mjs';
import {DOMAIN,WITNESS_ROLES,witnessSigningBytes,
 assessRegistrarEnrollmentWitnessCandidate}
 from '../scripts/phase1do-offline-registrar-witness-enrollment.mjs';

const HEAD='a'.repeat(40),MAIN='b'.repeat(40),REG='c'.repeat(64);
const NONCE='d'.repeat(64),NOW='2026-11-20T14:00:00.000Z';
const SEC='security-appointee',BUS='business-appointee';
const KEY=Buffer.alloc(32,0x19);
const held={productionReleaseAuthorized:false,
 productionReleaseBlocked:true,releaseDecision:'HOLD'};
const hash=x=>createHash('sha256').update(x).digest('hex');
function newKey(keyId){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {keyId,privateKey,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  spkiSha256:hash(publicKey.export({format:'der',type:'spki'}))};
}
const pub=k=>({keyId:k.keyId,publicKeyPem:k.publicKeyPem,
 spkiSha256:k.spkiSha256});
const signDm=(role,s,k)=>sign(null,candidateSigningBytes(role,s),
 k.privateKey).toString('base64');
const signDo=(role,s,k)=>sign(null,witnessSigningBytes(role,s),
 k.privateKey).toString('base64');
const q=h=>({
 phase:'1CO',schemaVersion:1,repository:REPO,currentDevHead:HEAD,
 prReadBeforeAndAfterStable:true,actualGithubReviewPaginationComplete:true,
 securityNominatedAccountActuallyApprovedCurrentHead:true,
 businessNominatedAccountActuallyApprovedCurrentHead:true,
 actualNominatedReviewerWritePermissionsObserved:true,
 twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:true,
 realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated:false,
 opaqueReviewerRoleSessionHmacSha256:h,anomalyCodes:[],...held
});
const df=h=>({phase:'1DF',schemaVersion:1,repository:REPO,
 currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
 roleBoundNomineeContinuityOnly:true,
 candidateCrossSourceTechnicalApprovalJoinOnly:true,
 effectiveBaseMainGovernanceReadableOnly:true,
 opaqueReviewerRoleSessionHmacSha256:h,...held});
const dg=()=>({phase:'1DG',schemaVersion:1,repository:REPO,
 currentDevelopmentHeadSha:HEAD,pinnedBaseMainSha:MAIN,
 effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly:true,
 exactTwoNominatedAccountsInEachAcceptedRuleOnly:true,
 anomalyCodes:[],...held});
const di=()=>({phase:'1DI',schemaVersion:1,repository:REPO,
 checkedSourceHeadSha:HEAD,checkedBaseMainSha:MAIN,
 wholeOperatorReadWindowTechnicallyConsistentOnly:true,
 reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly:true,
 noReviewerUsernamesOrOperatorTokenRetained:true,
 anomalyCodes:[],...held});
function session(){
 const h=deriveEphemeralReviewerRoleBinding({
  sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN
 });
 return {sessionKey:Buffer.from(KEY),
  roleQuorumFirst:q(h),roleQuorumSecond:q(h),roleJoin:df(h),
  pinnedOwners:dg(),terminalNominatedReview:q(h),terminalReadback:di()};
}
function fixture(){
 const keys={ROOT:newKey('registrar-root-key'),
  SECURITY_OFFICER:newKey('security-officer-key'),
  BUSINESS_OFFICER:newKey('business-officer-key'),
  LEGAL_WITNESS:newKey('legal-witness-key'),
  REGISTRY_WITNESS:newKey('registry-witness-key')};
 const app={
  schemaVersion:1,kind:'CANDIDATE_CORPORATE_APPOINTMENT_NOT_AUTHORIZED',
  repository:REPO,sourceHeadSha:HEAD,mainBaseSha:MAIN,
  organizationId:'corporate-org-1',registryEvidenceSha256:REG,
  nonce:NONCE,issuedAt:'2026-11-20T13:59:00.000Z',
  expiresAt:'2026-11-20T14:09:00.000Z',decision:'HOLD',
  officers:{
   SECURITY_OFFICER:{githubLogin:SEC,
    keyId:keys.SECURITY_OFFICER.keyId,
    spkiSha256:keys.SECURITY_OFFICER.spkiSha256},
   BUSINESS_OFFICER:{githubLogin:BUS,
    keyId:keys.BUSINESS_OFFICER.keyId,
    spkiSha256:keys.BUSINESS_OFFICER.spkiSha256}
  }
 };
 const packet={appointment:app,registrarKey:pub(keys.ROOT),
  registrarSignature:null,officerKeys:{
   SECURITY_OFFICER:pub(keys.SECURITY_OFFICER),
   BUSINESS_OFFICER:pub(keys.BUSINESS_OFFICER)
  },officerProofs:{}};
 function resignCandidate(){
  packet.registrarSignature=signDm('ROOT',app,keys.ROOT);
  const signedDigest=hash(candidateSigningBytes('ROOT',app));
  for(const role of ROLES){
   const statement={schemaVersion:1,
    kind:'CANDIDATE_OFFICER_KEY_POSSESSION_HOLD',repository:REPO,
    sourceHeadSha:app.sourceHeadSha,mainBaseSha:app.mainBaseSha,
    organizationId:app.organizationId,role,
    githubLogin:app.officers[role].githubLogin,
    nonce:app.nonce,appointmentDigestSha256:signedDigest,
    assertedAt:NOW,decision:'HOLD'};
   packet.officerProofs[role]={
    statement,signature:signDm(role,statement,keys[role])};
  }
 }
 resignCandidate();
 const previousCheckpoint={sequence:0,checkpointSha256:'0'.repeat(64)};
 const manifest={schemaVersion:1,
  kind:'UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE',
  repository:REPO,organizationId:app.organizationId,
  sourceHeadSha:HEAD,mainBaseSha:MAIN,
  registrarSpkiSha256:keys.ROOT.spkiSha256,
  registryEvidenceSha256:REG,
  appointmentDigestSha256:hash(candidateSigningBytes('ROOT',app)),
  nonce:NONCE,sequence:1,previousCheckpointSha256:'0'.repeat(64),
  issuedAt:'2026-11-20T13:59:00.000Z',
  expiresAt:'2026-11-20T14:09:00.000Z',decision:'HOLD'};
 const witnesses={
  LEGAL_WITNESS:{...pub(keys.LEGAL_WITNESS),signature:null},
  REGISTRY_WITNESS:{...pub(keys.REGISTRY_WITNESS),signature:null}};
 const resignWitnesses=()=>{for(const role of WITNESS_ROLES)
  witnesses[role].signature=signDo(role,manifest,keys[role]);};
 resignWitnesses();
 const x={candidatePacket:packet,
  expectedExternalPins:{registrarSpkiSha256:keys.ROOT.spkiSha256,
   registryEvidenceSha256:REG},
  operatorSession:session(),manifest,witnesses,
  witnessComparisonPins:{
   legalWitnessSpkiSha256:keys.LEGAL_WITNESS.spkiSha256,
   registryWitnessSpkiSha256:keys.REGISTRY_WITNESS.spkiSha256,
   expectedOrganizationId:app.organizationId,
   previousCheckpointSha256:'0'.repeat(64)
  },
  previousCheckpoint,now:NOW};
 return {x,keys,resignWitnesses,resignCandidate};
}
const assess=fn=>{const f=fixture();fn?.(f);
 return assessRegistrarEnrollmentWitnessCandidate(f.x);};
function hold(a){
 assert.equal(a.productionReleaseAuthorized,false);
 assert.equal(a.productionReleaseBlocked,true);
 assert.equal(a.releaseDecision,'HOLD');
 assert.equal(a.independentRootOrLegalRegistryChannelAuthenticated,false);
 assert.equal(a.independentlyAppointedSecurityBusinessOfficerMandatesVerified,false);
 assert.equal(a.externallyDurableAntiReplayCheckpointOrCasVerified,false);
 assert.equal(a.liveMcaLegalSignatoryOrRcaiCcaEmudhraTrustVerified,false);
 assert.equal(a.canWriteMainRequestReviewsActivateProvidersOrDeploy,false);
}
function deny(fn,code){
 const r=assess(fn);hold(r);
 assert.equal(r.candidateRegistrarRootEnrollmentChainMathematicallyConsistentOnly,false);
 assert.equal(r.unsignedNextEnrollmentCheckpointSha256,null);
 assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join(' | '));
 return r;
}
test('DO five synthetic Ed25519 signatures and two role-ordered witnesses still HARD HOLD',()=>{
 const a=assess();hold(a);
 assert.equal(a.candidateRegistrarRootEnrollmentChainMathematicallyConsistentOnly,true,
  a.anomalyCodes.join('|'));
 assert.equal(a.localLegalAndRegistryWitnessSignaturesVerifiedOnly,2);
 assert.match(a.unsignedNextEnrollmentCheckpointSha256,/^[0-9a-f]{64}$/);
 assert.deepEqual(a.anomalyCodes,[]);
});
test('DO recomputes original 1DN from signed appointment and session, no public boolean shortcut',()=>{
 const f=fixture();
 const a=assessInProcessAppointmentReviewerBinding({
  candidatePacket:f.x.candidatePacket,
  expectedExternalPins:f.x.expectedExternalPins,
  operatorSession:f.x.operatorSession,now:NOW});
 assert.equal(a.inProcessCrossPhaseCandidateContractConsistentOnly,true,
  a.anomalyCodes.join('|'));
 const d=assessRegistrarEnrollmentWitnessCandidate(f.x);
 assert.equal(d.originalGithubNomineesToOfficerSignaturesRecheckedInProcessOnly,true);
 hold(d);
});
test('DO two signatures domain-separated, stable canonical order',()=>{
 const a={a:1,b:2},b={b:2,a:1};
 assert.deepEqual(witnessSigningBytes('LEGAL_WITNESS',a),
  witnessSigningBytes('LEGAL_WITNESS',b));
 assert.notDeepEqual(witnessSigningBytes('LEGAL_WITNESS',a),
  witnessSigningBytes('REGISTRY_WITNESS',a));
 assert.equal(DOMAIN.startsWith('aaditech/phase1do/'),true);
});
test('DO missing explicit now fails: no hard-coded November 2026 clock fallback',()=>{
 deny(f=>{delete f.x.now;},'DO_EXPLICIT_CURRENT_VERIFICATION_CLOCK_REQUIRED');
 const f=fixture();
 const noClock=assessOfflineCorporateAppointmentCandidate({
  packet:f.x.candidatePacket,
  expectedExternalPins:f.x.expectedExternalPins,
  terminalContinuity:assessEphemeralReviewerHandoffContinuity({
   ...f.x.operatorSession,securityLogin:SEC,businessLogin:BUS}),
  securityLogin:SEC,businessLogin:BUS});
 assert.equal(noClock.productionReleaseAuthorized,false);
 assert.equal(noClock.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,
  false);
 assert.ok(noClock.anomalyCodes.includes('DM_VERIFICATION_CLOCK_INVALID'));
 const dn=assessInProcessAppointmentReviewerBinding({
  candidatePacket:f.x.candidatePacket,expectedExternalPins:f.x.expectedExternalPins,
  operatorSession:f.x.operatorSession});
 assert.equal(dn.productionReleaseAuthorized,false);
 assert.equal(dn.inProcessCrossPhaseCandidateContractConsistentOnly,false);
});
test('DO malformed verification timestamp fails closed',()=>{
 deny(f=>{f.x.now='yesterday';},
  'DO_EXPLICIT_CURRENT_VERIFICATION_CLOCK_REQUIRED');
});
test('DO expired witness, future witness and >15-minute TTL fail',()=>{
 for(const val of [
  ['issuedAt','2026-11-20T12:00:00.000Z'],
  ['issuedAt','2026-11-20T14:08:00.000Z'],
  ['expiresAt','2026-11-20T14:40:00.000Z'],
  ['expiresAt','2026-11-20T13:55:00.000Z']
 ])deny(f=>{f.x.manifest[val[0]]=val[1];f.resignWitnesses();},
  'DO_WITNESS_MANIFEST_STALE_FUTURE_OR_TOO_LONG');
});
test('DO missing witnesses, unknown status fields or unsupported role fail closed',()=>{
 deny(f=>{f.x.witnesses=null;},
  'DO_TWO_DISTINCT_PINNED_ED25519_WITNESS_KEYS_REQUIRED');
 deny(f=>{f.x.witnesses.EVIL={};},
  'DO_TWO_DISTINCT_PINNED_ED25519_WITNESS_KEYS_REQUIRED');
});
test('DO Legal detached signature cannot impersonate Registry witness',()=>{
 deny(f=>{f.x.witnesses.REGISTRY_WITNESS.signature=
  f.x.witnesses.LEGAL_WITNESS.signature;},
  'DO_REGISTRY_WITNESS_SIGNED_WITNESS_CLAIM_INVALID');
});
test('DO Legal signature corruption denied despite valid Registry witness',()=>{
 deny(f=>{f.x.witnesses.LEGAL_WITNESS.signature=
  'A'.repeat(86)+'==';},
  'DO_LEGAL_WITNESS_SIGNED_WITNESS_CLAIM_INVALID');
});
test('DO malicious substituted witness root pin fails',()=>{
 deny(f=>{f.x.witnessComparisonPins.legalWitnessSpkiSha256='f'.repeat(64);},
  'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
});
test('DO missing independently supplied candidate witness pins fails',()=>{
 deny(f=>{f.x.witnessComparisonPins=null;},
  'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
});
test('DO legal and registry comparison pins swapped fail even when signatures valid',()=>{
 deny(f=>{const p=f.x.witnessComparisonPins;
  [p.legalWitnessSpkiSha256,p.registryWitnessSpkiSha256]=
  [p.registryWitnessSpkiSha256,p.legalWitnessSpkiSha256];},
  'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
});
test('DO witness public keys must be distinct from each other and registrar',()=>{
 deny(f=>{f.x.witnesses.REGISTRY_WITNESS.spkiSha256=
  f.x.witnesses.LEGAL_WITNESS.spkiSha256;},
  'DO_TWO_DISTINCT_PINNED_ED25519_WITNESS_KEYS_REQUIRED');
 deny(f=>{f.x.witnesses.LEGAL_WITNESS.keyId=
  f.x.witnesses.REGISTRY_WITNESS.keyId;},
  'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
});
test('DO public key PEM altered or wrong algorithm is denied',()=>{
 deny(f=>{f.x.witnesses.LEGAL_WITNESS.publicKeyPem='FAKE PEM';},
  'DO_TWO_DISTINCT_PINNED_ED25519_WITNESS_KEYS_REQUIRED');
});
test('DO organization pin mismatch cannot masquerade MCA registry intake',()=>{
 deny(f=>{f.x.witnessComparisonPins.expectedOrganizationId='other-company';},
  'DO_WITNESS_PINS_OR_DISTINCT_ROLE_KEYS_NOT_MATCHED');
});
test('DO signed candidate appointment hash is bound to both witness assertions',()=>{
 deny(f=>{f.x.manifest.appointmentDigestSha256='f'.repeat(64);
  f.resignWitnesses();},
  'DO_REGISTRAR_OR_SOURCE_NOT_EQUAL_SIGNED_APPOINTMENT');
});
test('DO applicant source HEAD mutation even with new witness signatures denied',()=>{
 deny(f=>{f.x.manifest.sourceHeadSha='f'.repeat(40);
  f.resignWitnesses();},
  'DO_REGISTRAR_OR_SOURCE_NOT_EQUAL_SIGNED_APPOINTMENT');
});
test('DO applicant main base mutation even with new witness signatures denied',()=>{
 deny(f=>{f.x.manifest.mainBaseSha='f'.repeat(40);
  f.resignWitnesses();},
  'DO_REGISTRAR_OR_SOURCE_NOT_EQUAL_SIGNED_APPOINTMENT');
});
test('DO appointment nonce modification invalidates witness root join',()=>{
 deny(f=>{f.x.manifest.nonce='f'.repeat(64);f.resignWitnesses();},
  'DO_REGISTRAR_OR_SOURCE_NOT_EQUAL_SIGNED_APPOINTMENT');
});
test('DO copied witness signatures cannot validate modified manifest even if source matches',()=>{
 deny(f=>{f.x.manifest.issuedAt='2026-11-20T13:58:00.000Z';},
  'DO_LEGAL_WITNESS_SIGNED_WITNESS_CLAIM_INVALID');
});
test('DO applicant injected GO or claim of independently enrolled root rejected',()=>{
 deny(f=>{f.x.manifest.productionReleaseAuthorized=true;},
  'DO_REGISTRAR_ENROLLMENT_SCOPE_OR_MANIFEST_SCHEMA_INVALID');
});
test('DO genesis checkpoint must start at zero digest with sequence one',()=>{
 deny(f=>{f.x.previousCheckpoint.sequence=0;
  f.x.previousCheckpoint.checkpointSha256='f'.repeat(64);
  f.x.witnessComparisonPins.previousCheckpointSha256='f'.repeat(64);
  f.x.manifest.previousCheckpointSha256='f'.repeat(64);
  f.resignWitnesses();},
  'DO_MONOTONIC_PREVIOUS_CHECKPOINT_NOT_OBSERVED');
});
test('DO sequence cannot skip a level, roll back, repeat or overflow',()=>{
 for(const seq of [0,2,-1,Number.MAX_SAFE_INTEGER]){
  deny(f=>{f.x.manifest.sequence=seq;f.resignWitnesses();},
   'DO_MONOTONIC_PREVIOUS_CHECKPOINT_NOT_OBSERVED');
 }
});
test('DO caller-supplied expected checkpoint mismatch denies replay',()=>{
 deny(f=>{f.x.witnessComparisonPins.previousCheckpointSha256='f'.repeat(64);},
  'DO_MONOTONIC_PREVIOUS_CHECKPOINT_NOT_OBSERVED');
});
test('DO after-bootstrap checkpoint must increment exactly one generation',()=>{
 const a=assess(f=>{
  const prev='e'.repeat(64);f.x.previousCheckpoint.sequence=1;
  f.x.previousCheckpoint.checkpointSha256=prev;
  f.x.witnessComparisonPins.previousCheckpointSha256=prev;
  f.x.manifest.sequence=2;f.x.manifest.previousCheckpointSha256=prev;
  f.resignWitnesses();
 });
 hold(a);
 assert.equal(a.candidateRegistrarRootEnrollmentChainMathematicallyConsistentOnly,true,
  a.anomalyCodes.join('|'));
});
test('DO old session key, fake reviewer permission, changed CODEOWNERS all denied',()=>{
 for(const fn of [
  f=>{f.x.operatorSession.sessionKey=Buffer.alloc(32,0x55);},
  f=>{f.x.operatorSession.terminalNominatedReview.actualNominatedReviewerWritePermissionsObserved=false;},
  f=>{f.x.operatorSession.pinnedOwners.exactTwoNominatedAccountsInEachAcceptedRuleOnly=false;}
 ])deny(fn,'DO_ORIGINAL_1DN_OFFICER_GITHUB_SESSION_NOT_VERIFIED');
});
test('DO expired signed corporate appointment cannot be rescued by two valid witnesses',()=>{
 deny(f=>{f.x.candidatePacket.appointment.expiresAt='2026-11-20T13:59:30.000Z';},
  'DO_ORIGINAL_1DN_OFFICER_GITHUB_SESSION_NOT_VERIFIED');
});
test('DO missing signed officer signature cannot be rescued by witness credentials',()=>{
 deny(f=>{f.x.candidatePacket.officerProofs.SECURITY_OFFICER.signature=null;},
  'DO_ORIGINAL_1DN_OFFICER_GITHUB_SESSION_NOT_VERIFIED');
});
test('DO self-issued Registrar plus two applicant-controlled witness keys still NOT independent',()=>{
 const f=fixture();const a=assessRegistrarEnrollmentWitnessCandidate(f.x);
 assert.equal(a.candidateRegistrarRootEnrollmentChainMathematicallyConsistentOnly,true);
 assert.equal(a.independentRootOrLegalRegistryChannelAuthenticated,false);
 assert.equal(a.externallyDurableAntiReplayCheckpointOrCasVerified,false);
 hold(a);
});
test('DO output contains no HMAC, named officer, public PEM, nonce or signatures',()=>{
 const f=fixture();const out=JSON.stringify(
  assessRegistrarEnrollmentWitnessCandidate(f.x));
 const h=deriveEphemeralReviewerRoleBinding({sessionKey:KEY,
  securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN});
 for(const secret of [SEC,BUS,NONCE,REG,KEY.toString('hex'),h,
  f.x.witnesses.LEGAL_WITNESS.signature,
  f.x.witnesses.REGISTRY_WITNESS.publicKeyPem,
  f.x.candidatePacket.registrarSignature])
  assert.equal(out.includes(secret),false);
});
test('DO no GitHub/admin/production writes, no hard-coded success or secret IO',()=>{
 const text=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1do-offline-registrar-witness-enrollment.mjs'),'utf8');
 assert.equal(/fetch\s*\(|writeFileSync|readFileSync|process\.env/.test(text),false);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(text),false);
 assert.equal(text.includes('productionReleaseAuthorized:true'),false);
 assert.ok(text.includes('assessInProcessAppointmentReviewerBinding('));
});
