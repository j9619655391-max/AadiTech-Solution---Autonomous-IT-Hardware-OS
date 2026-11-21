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
import {assessInProcessAppointmentReviewerBinding,
 OPERATOR_SESSION_FIELDS}
 from '../scripts/phase1dn-corporate-role-session-reconciliation.mjs';

const HEAD='a'.repeat(40),MAIN='b'.repeat(40),REG='c'.repeat(64);
const NONCE='d'.repeat(64),NOW='2026-11-20T14:00:00.000Z';
const SEC='security-appointee',BUS='business-appointee';
const KEY=Buffer.alloc(32,0x13),KEY2=Buffer.alloc(32,0x27);
const held={productionReleaseAuthorized:false,
 productionReleaseBlocked:true,releaseDecision:'HOLD'};
const sha=x=>createHash('sha256').update(x).digest('hex');
function signer(keyId){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const pem=publicKey.export({format:'pem',type:'spki'}).toString();
 const spkiSha256=sha(publicKey.export({format:'der',type:'spki'}));
 return {privateKey,keyId,publicKeyPem:pem,spkiSha256};
}
const pub=k=>({keyId:k.keyId,publicKeyPem:k.publicKeyPem,
 spkiSha256:k.spkiSha256});
const sig=(role,statement,k)=>sign(null,candidateSigningBytes(role,statement),
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
const df=h=>({
 phase:'1DF',schemaVersion:1,repository:REPO,
 currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
 roleBoundNomineeContinuityOnly:true,
 candidateCrossSourceTechnicalApprovalJoinOnly:true,
 effectiveBaseMainGovernanceReadableOnly:true,
 opaqueReviewerRoleSessionHmacSha256:h,anomalyCodes:[],...held
});
const dg=()=>({
 phase:'1DG',schemaVersion:1,repository:REPO,
 currentDevelopmentHeadSha:HEAD,pinnedBaseMainSha:MAIN,
 effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly:true,
 exactTwoNominatedAccountsInEachAcceptedRuleOnly:true,
 anomalyCodes:[],...held
});
const di=()=>({
 phase:'1DI',schemaVersion:1,repository:REPO,
 checkedSourceHeadSha:HEAD,checkedBaseMainSha:MAIN,
 wholeOperatorReadWindowTechnicallyConsistentOnly:true,
 reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly:true,
 noReviewerUsernamesOrOperatorTokenRetained:true,
 anomalyCodes:[],...held
});
const binding=(key=KEY,security=SEC,business=BUS)=>deriveEphemeralReviewerRoleBinding({
 sessionKey:key,securityLogin:security,businessLogin:business,
 currentDevHeadSha:HEAD,currentMainBaseSha:MAIN
});
function session(){
 const h=binding();
 return {sessionKey:Buffer.from(KEY),roleQuorumFirst:q(h),
  roleQuorumSecond:q(h),roleJoin:df(h),pinnedOwners:dg(),
  terminalNominatedReview:q(h),terminalReadback:di()};
}
function packetFixture(){
 const keys={
  ROOT:signer('registrar-key-1'),SECURITY_OFFICER:signer('security-key-1'),
  BUSINESS_OFFICER:signer('business-key-1')
 };
 const appointment={
  schemaVersion:1,kind:'CANDIDATE_CORPORATE_APPOINTMENT_NOT_AUTHORIZED',
  repository:REPO,sourceHeadSha:HEAD,mainBaseSha:MAIN,
  organizationId:'corp-root-1',registryEvidenceSha256:REG,
  nonce:NONCE,issuedAt:'2026-11-20T13:59:00.000Z',
  expiresAt:'2026-11-20T14:09:00.000Z',decision:'HOLD',
  officers:Object.fromEntries(ROLES.map((role,i)=>[role,{
   githubLogin:i===0?SEC:BUS,keyId:keys[role].keyId,
   spkiSha256:keys[role].spkiSha256
  }]))
 };
 const packet={
  appointment,registrarKey:pub(keys.ROOT),
  registrarSignature:null,
  officerKeys:Object.fromEntries(ROLES.map(role=>[role,pub(keys[role])])),
  officerProofs:{}
 };
 const pins={registrarSpkiSha256:keys.ROOT.spkiSha256,
  registryEvidenceSha256:REG};
 const x={candidatePacket:packet,expectedExternalPins:pins,
  operatorSession:session(),now:NOW};
 resign(x,keys);
 return {x,keys};
}
function resign(x,keys){
 const app=x.candidatePacket.appointment;
 x.candidatePacket.registrarSignature=sig('ROOT',app,keys.ROOT);
 const digest=sha(candidateSigningBytes('ROOT',app));
 for(const role of ROLES){
  const s={
   schemaVersion:1,kind:'CANDIDATE_OFFICER_KEY_POSSESSION_HOLD',
   repository:REPO,sourceHeadSha:app.sourceHeadSha,
   mainBaseSha:app.mainBaseSha,organizationId:app.organizationId,
   role,githubLogin:app.officers[role].githubLogin,
   nonce:app.nonce,appointmentDigestSha256:digest,
   assertedAt:'2026-11-20T14:00:00.000Z',decision:'HOLD'
  };
  x.candidatePacket.officerProofs[role]={
   statement:s,signature:sig(role,s,keys[role])
  };
 }
}
const assess=fn=>{
 const {x,keys}=packetFixture();
 if(fn)fn(x,keys);
 return assessInProcessAppointmentReviewerBinding(x);
};
const expectedHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.independentlyAuthenticatedCorporateRegistrarEnrollment,false);
 assert.equal(r.independentlyAuthenticatedMcaCorporateIdentityOrLegalMandates,false);
 assert.equal(r.actualSecurityBusinessCorporateAppointmentsIndependentlyVerified,false);
 assert.equal(r.providerSignedCaRevocationAndExternalWormOrStagingVerified,false);
 assert.equal(r.canRequestGithubReviewsInstallMainMergeOrDeploy,false);
};
function deny(fn,code){
 const v=assess(fn);expectedHold(v);
 assert.equal(v.inProcessCrossPhaseCandidateContractConsistentOnly,false);
 assert.ok(v.anomalyCodes.includes(code),v.anomalyCodes.join('|'));
}
test('DN real pure 1DL recomputation binds candidate nominees to 3 technical receipts',()=>{
 const f=packetFixture();const a=f.x.candidatePacket.appointment;
 const d=assessEphemeralReviewerHandoffContinuity({
  ...f.x.operatorSession,securityLogin:a.officers.SECURITY_OFFICER.githubLogin,
  businessLogin:a.officers.BUSINESS_OFFICER.githubLogin
 });
 assert.equal(d.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly,true,
  d.anomalyCodes.join('|'));
 expectedHold(assessInProcessAppointmentReviewerBinding(f.x));
});
test('DN mathematical 1DM+1DL cross-phase positive is ALWAYS production HOLD',()=>{
 const d=assess();expectedHold(d);
 assert.equal(d.inProcessCrossPhaseCandidateContractConsistentOnly,true,
  d.anomalyCodes.join('|'));
 assert.equal(d.signedOfficerRoleOrderMatchedAgainstActualSessionHmacOnly,true);
 assert.equal(d.applicantSignedRegistrarAndTwoOfficerSignaturesMathematicallyConsistentOnly,true);
 assert.deepEqual(d.anomalyCodes,[]);
});
test('DN old 1DM public boolean join cannot identify changed reviewer pair; DN rejects',()=>{
 const {x,keys}=packetFixture();
 x.candidatePacket.appointment.officers.SECURITY_OFFICER.githubLogin='other-security';
 resign(x,keys);
 const old=assessOfflineCorporateAppointmentCandidate({
  packet:x.candidatePacket,expectedExternalPins:x.expectedExternalPins,
  terminalContinuity:assessEphemeralReviewerHandoffContinuity({
   ...x.operatorSession,securityLogin:SEC,businessLogin:BUS
  }),
  securityLogin:'other-security',businessLogin:BUS,now:NOW
 });
 assert.equal(old.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,
  true,'This demonstrates the former unbound public 1DL receipt');
 const newer=assessInProcessAppointmentReviewerBinding(x);
 expectedHold(newer);
 assert.equal(newer.inProcessCrossPhaseCandidateContractConsistentOnly,false);
 assert.ok(newer.anomalyCodes.includes(
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION'));
});
test('DN fully re-signed different Business reviewer fails even with matching registrar',()=>{
 deny((x,keys)=>{
  x.candidatePacket.appointment.officers.BUSINESS_OFFICER.githubLogin='other-business';
  resign(x,keys);
 },'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN both nominees re-signed cannot borrow unrelated session, even same HEAD',()=>{
 deny((x,keys)=>{
  x.candidatePacket.appointment.officers.SECURITY_OFFICER.githubLogin='other-security';
  x.candidatePacket.appointment.officers.BUSINESS_OFFICER.githubLogin='other-business';
  resign(x,keys);
 },'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN role swap with re-signed ROOT and both proofs cannot borrow original session',()=>{
 deny((x,keys)=>{
  const o=x.candidatePacket.appointment.officers;
  [o.SECURITY_OFFICER.githubLogin,o.BUSINESS_OFFICER.githubLogin]=
   [o.BUSINESS_OFFICER.githubLogin,o.SECURITY_OFFICER.githubLogin];
  resign(x,keys);
 },'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN no operator session is not rescued by public good 1DL flags',()=>{
 deny(x=>{x.operatorSession=null;},
  'DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
});
test('DN no local key rejects even three apparently approved 1CO reports',()=>{
 deny(x=>{x.operatorSession.sessionKey=null;},
  'DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
});
test('DN invalid 31/33 byte, text or typed-array local keys rejected',()=>{
 for(const key of [Buffer.alloc(31),Buffer.alloc(33),'external',
  new Uint8Array(32)]){
  deny(x=>{x.operatorSession.sessionKey=key;},
   'DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
 }
});
test('DN operator extra fields or applicant forged verified marker rejected',()=>{
 deny(x=>{x.operatorSession.authorizedByMca=true;},
  'DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
});
test('DN same pair but different key material cannot reuse independent operator session',()=>{
 deny(x=>{x.operatorSession.sessionKey=Buffer.from(KEY2);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN one HMAC replaced with valid HMAC of another operator session fails',()=>{
 deny(x=>{x.operatorSession.roleQuorumFirst.opaqueReviewerRoleSessionHmacSha256=
  binding(KEY2);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN second reviewer read changed HMAC denies technical consistency',()=>{
 deny(x=>{x.operatorSession.roleQuorumSecond.opaqueReviewerRoleSessionHmacSha256=
  binding(KEY2);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN terminal reviewer read different role pair denies technical consistency',()=>{
 deny(x=>{x.operatorSession.terminalNominatedReview.opaqueReviewerRoleSessionHmacSha256=
  binding(KEY,SEC,'different-business');},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN role join returned HMAC not equal to same-session reporter proof fails',()=>{
 deny(x=>{x.operatorSession.roleJoin.opaqueReviewerRoleSessionHmacSha256=
  binding(KEY2);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN omitted actual first/second/terminal approvals fail closed',()=>{
 for(const name of ['roleQuorumFirst','roleQuorumSecond','terminalNominatedReview'])
  deny(x=>{x.operatorSession[name]=null;},
   'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN missing GitHub reviewer write evidence fails even with correct HMAC',()=>{
 deny(x=>{x.operatorSession.terminalNominatedReview.actualNominatedReviewerWritePermissionsObserved=false;},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN stale PR source review cannot match a valid appointment',()=>{
 deny(x=>{x.operatorSession.roleQuorumFirst.currentDevHead='f'.repeat(40);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN unrelated base-main HEAD from role join not accepted',()=>{
 deny(x=>{x.operatorSession.roleJoin.currentMainBaseSha='f'.repeat(40);},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN pinned actual main CODEOWNERS review false denies matching applicant proof',()=>{
 deny(x=>{x.operatorSession.pinnedOwners.exactTwoNominatedAccountsInEachAcceptedRuleOnly=false;},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN 1DI final governance read-window false is fail-closed even same HMAC',()=>{
 deny(x=>{x.operatorSession.terminalReadback.wholeOperatorReadWindowTechnicallyConsistentOnly=false;},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN 1DK review-history drift denies even 3 cryptographically good corporate signatures',()=>{
 deny(x=>{x.operatorSession.terminalReadback.reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly=false;},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN terminal report claimed corporate GO or true officer authentication denied',()=>{
 deny(x=>{x.operatorSession.terminalReadback.productionReleaseAuthorized=true;},
  'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN changed signed source HEAD and valid re-sign cannot escape mismatched session',()=>{
 deny((x,keys)=>{
  x.candidatePacket.appointment.sourceHeadSha='f'.repeat(40);
  resign(x,keys);
 },'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN changed signed base-main SHA and valid re-sign cannot escape mismatch',()=>{
 deny((x,keys)=>{
  x.candidatePacket.appointment.mainBaseSha='f'.repeat(40);
  resign(x,keys);
 },'DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
});
test('DN stale registrar pin fails separately from 1DL GitHub identity matching',()=>{
 deny(x=>{x.expectedExternalPins.registrarSpkiSha256='f'.repeat(64);},
  'DN_CORPORATE_SIGNATURE_AND_OFFICER_CHALLENGE_CANDIDATE_INVALID');
});
test('DN replaced officer detached signature fails even when HMAC pair unchanged',()=>{
 deny(x=>{x.candidatePacket.officerProofs.SECURITY_OFFICER.signature=
  x.candidatePacket.officerProofs.BUSINESS_OFFICER.signature;},
  'DN_CORPORATE_SIGNATURE_AND_OFFICER_CHALLENGE_CANDIDATE_INVALID');
});
test('DN expired corporate candidate never authorized by current GitHub reviewer approvals',()=>{
 deny(x=>{x.now='2026-11-20T14:20:00.000Z';},
  'DN_CORPORATE_SIGNATURE_AND_OFFICER_CHALLENGE_CANDIDATE_INVALID');
});
test('DN applicant self-issued registrar pin & signatures cannot prove legal MCA appointment',()=>{
 const r=assess();expectedHold(r);
 assert.equal(r.registrarSpkiAndCorporateRegistryPinsOperatorSuppliedOnly,true);
 assert.equal(r.independentlyAuthenticatedCorporateRegistrarEnrollment,false);
 assert.equal(r.independentlyAuthenticatedMcaCorporateIdentityOrLegalMandates,false);
});
test('DN no raw reviewer names, registrar PEM, HMAC, signature or nonce in report',()=>{
 const {x}=packetFixture();
 const z=JSON.stringify(assessInProcessAppointmentReviewerBinding(x));
 const privateValues=[SEC,BUS,NONCE,REG,binding(),KEY.toString('hex'),
  x.candidatePacket.registrarSignature,
  x.candidatePacket.registrarKey.publicKeyPem,
  x.candidatePacket.officerProofs.SECURITY_OFFICER.signature];
 for(const v of privateValues)assert.equal(z.includes(v),false);
});
test('DN report never exposes underlying 1DL or 1DM candidate payload',()=>{
 const r=assess();
 assert.equal('operatorSession' in r,false);
 assert.equal('candidatePacket' in r,false);
 assert.equal('publicKeyPem' in r,false);
 assert.equal('opaqueReviewerRoleSessionHmacSha256' in r,false);
});
test('DN fixed exact local operator session contract rejects unknown key paths',()=>{
 const fields=[...OPERATOR_SESSION_FIELDS];
 assert.deepEqual(fields,[
  'sessionKey','roleQuorumFirst','roleQuorumSecond','roleJoin',
  'pinnedOwners','terminalNominatedReview','terminalReadback'
 ]);
 deny(x=>{delete x.operatorSession.roleQuorumSecond;},
  'DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
});
test('DN no async live network, admin mutation, reviewer requests or embedded operator credentials',()=>{
 const file=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dn-corporate-role-session-reconciliation.mjs'),'utf8');
 assert.equal(/\bfetch\s*\(|writeFileSync|readFileSync|process\.env/.test(file),false);
 assert.equal(/method:\s*['"](?:POST|PATCH|PUT|DELETE)['"]/.test(file),false);
 assert.equal(file.includes('productionReleaseAuthorized:true'),false);
 assert.ok(file.includes('assessEphemeralReviewerHandoffContinuity('));
 assert.ok(file.includes('assessOfflineCorporateAppointmentCandidate('));
});
