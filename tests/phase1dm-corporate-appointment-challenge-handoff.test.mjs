import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {
 ROLES,DOMAIN,candidateSigningBytes,assessOfflineCorporateAppointmentCandidate
} from '../scripts/phase1dm-corporate-appointment-challenge-handoff.mjs';

const HEAD='a'.repeat(40),MAIN='b'.repeat(40),REG='c'.repeat(64);
const NONCE='d'.repeat(64),NOW='2026-11-20T14:00:00.000Z';
const SEC='security-appointee',BUS='business-appointee';
const HELD={productionReleaseAuthorized:false,
 productionReleaseBlocked:true,releaseDecision:'HOLD'};
const key=(keyId)=>{
 const pair=generateKeyPairSync('ed25519');
 const pem=pair.publicKey.export({format:'pem',type:'spki'}).toString();
 const spkiSha256=createHash('sha256')
  .update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex');
 return {keyId,publicKeyPem:pem,spkiSha256,
  privateKey:pair.privateKey};
};
const pub=k=>({
 keyId:k.keyId,publicKeyPem:k.publicKeyPem,spkiSha256:k.spkiSha256
});
const sig=(role,v,k)=>sign(null,candidateSigningBytes(role,v),
 k.privateKey).toString('base64');
const handoff=()=>({
 phase:'1DL',schemaVersion:1,
 kind:'EPHEMERAL_GITHUB_ROLE_NOMINEE_CROSS_PHASE_CONTINUITY_HARD_HOLD',
 repository:REPO,checkedSourceHeadSha:HEAD,checkedBaseMainSha:MAIN,
 threeCurrentHeadRoleSpecificActualReadbacksOnly:true,
 operatorSessionNomineePairBoundAcrossReadsOnly:true,
 initialAndTerminalGovernanceJoinConsistentOnly:true,
 technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly:true,
 opaqueSessionKeyAndReviewerIdentityExcludedFromOutput:true,
 independentCorporateOfficerAppointmentsOrMandatesAuthenticated:false,
 anomalyCodes:[],...HELD
});
function fixture(){
 const root=key('registrar-key-1'),security=key('security-key-1'),
  business=key('business-key-1');
 const appointment={
  schemaVersion:1,kind:'CANDIDATE_CORPORATE_APPOINTMENT_NOT_AUTHORIZED',
  repository:REPO,sourceHeadSha:HEAD,mainBaseSha:MAIN,
  organizationId:'corporate-org-1',registryEvidenceSha256:REG,
  nonce:NONCE,issuedAt:'2026-11-20T13:59:00.000Z',
  expiresAt:'2026-11-20T14:09:00.000Z',decision:'HOLD',
  officers:{
   SECURITY_OFFICER:{githubLogin:SEC,keyId:security.keyId,
    spkiSha256:security.spkiSha256},
   BUSINESS_OFFICER:{githubLogin:BUS,keyId:business.keyId,
    spkiSha256:business.spkiSha256}
  }
 };
 const packet={
  appointment,registrarKey:pub(root),
  registrarSignature:sig('ROOT',appointment,root),
  officerKeys:{SECURITY_OFFICER:pub(security),BUSINESS_OFFICER:pub(business)},
  officerProofs:{}
 };
 const keys={ROOT:root,SECURITY_OFFICER:security,BUSINESS_OFFICER:business};
 const input={
  packet,expectedExternalPins:{
   registrarSpkiSha256:root.spkiSha256,registryEvidenceSha256:REG
  },
  terminalContinuity:handoff(),
  securityLogin:SEC,businessLogin:BUS,now:NOW
 };
 populateProofs(input,keys);
 return {input,keys};
}
function populateProofs(input,keys){
 const a=input.packet.appointment;
 input.packet.registrarSignature=sig('ROOT',a,keys.ROOT);
 const digest=createHash('sha256').update(candidateSigningBytes('ROOT',a))
  .digest('hex');
 for(const role of ROLES){
  const v={
   schemaVersion:1,kind:'CANDIDATE_OFFICER_KEY_POSSESSION_HOLD',
   repository:REPO,sourceHeadSha:a.sourceHeadSha,mainBaseSha:a.mainBaseSha,
   organizationId:a.organizationId,role,githubLogin:a.officers[role].githubLogin,
   nonce:a.nonce,appointmentDigestSha256:digest,
   assertedAt:'2026-11-20T14:00:00.000Z',decision:'HOLD'
  };
  input.packet.officerProofs[role]={statement:v,signature:sig(role,v,keys[role])};
 }
}
const assess=(mutator=null)=>{
 const x=fixture();mutator?.(x);
 return assessOfflineCorporateAppointmentCandidate(x.input);
};
function hold(x){
 assert.equal(x.productionReleaseAuthorized,false);
 assert.equal(x.productionReleaseBlocked,true);
 assert.equal(x.releaseDecision,'HOLD');
 assert.equal(x.independentLegalCorporateRegistrarRootAuthorityAuthenticated,false);
 assert.equal(x.independentSecurityBusinessOfficerAppointmentsAuthenticated,false);
 assert.equal(x.independentlyAuthenticatedMcaRegistryOrLegalSignatory,false);
 assert.equal(x.canWriteGithubMainReviewMergeOrRelease,false);
 assert.equal(x.cannotConvertUntrustedCandidateIntoProductionAuthority,true);
}
function deny(mutator,expected){
 const x=assess(mutator);hold(x);
 assert.equal(x.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,false);
 assert.ok(x.anomalyCodes.includes(expected),x.anomalyCodes.join(';'));
 return x;
}
test('DM all three synthetic Ed25519 signatures verify but ALWAYS corporate HOLD',()=>{
 const x=assess();hold(x);
 assert.equal(x.candidateDetachedEd25519SignaturesVerifiedOnly,3,x.anomalyCodes.join(';'));
 assert.equal(x.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,true,x.anomalyCodes.join(';'));
 assert.equal(x.outOfBandExpectedPinsMatchedLocallyOnly,true);
 assert.equal(x.matchedRealGitHubRoleContinuityReceiptShapeOnly,true);
 assert.deepEqual(x.anomalyCodes,[]);
});
test('DM exact cryptographic domain and canonical signed byte binding',()=>{
 const a={a:'hello',b:2},b={b:2,a:'hello'};
 assert.deepEqual(candidateSigningBytes('ROOT',a),candidateSigningBytes('ROOT',b));
 assert.notDeepEqual(candidateSigningBytes('ROOT',a),
  candidateSigningBytes('SECURITY_OFFICER',a));
 assert.equal(DOMAIN.startsWith('aaditech/phase1dm/'),true);
});
test('DM rejects missing packet and malformed circular applicant JSON',()=>{
 const missing=assessOfflineCorporateAppointmentCandidate();hold(missing);
 assert.equal(missing.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,false);
 const x=fixture();x.input.packet.self=x.input.packet;
 const v=assessOfflineCorporateAppointmentCandidate(x.input);hold(v);
 assert.ok(v.anomalyCodes.includes('DM_UNBOUNDED_OR_UNSERIALIZABLE_OFFLINE_PACKET'));
});
test('DM rejects extra packet top-level fields, not implicit evidence authority',()=>{
 deny(x=>{x.input.packet.productionGo=true},'DM_UNTRUSTED_CORPORATE_PACKET_SCHEMA');
});
test('DM missing key pins cannot silently authenticate a self-signed root',()=>{
 deny(x=>{x.input.expectedExternalPins=null},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM substituted registrar key pin fails although packet signatures valid',()=>{
 deny(x=>{x.input.expectedExternalPins.registrarSpkiSha256='a'.repeat(64)},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM substituted MCA evidence digest pin fails with intact signatures',()=>{
 deny(x=>{x.input.expectedExternalPins.registryEvidenceSha256='a'.repeat(64)},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM unexpected independent authority claim is disallowed on pin schema',()=>{
 deny(x=>{x.input.expectedExternalPins.independentlyVerified=true},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM tampered registrar signature or fake signature is detected',()=>{
 for(const bad of ['a'.repeat(88),'','***',null]){
  deny(x=>{x.input.packet.registrarSignature=bad},
   'DM_ROOT_SIGNED_APPOINTMENT_NOT_AUTHENTICATED_MATHEMATICALLY');
 }
});
test('DM canonical Ed25519 signature cannot be substituted with other role key',()=>{
 deny(x=>{x.input.packet.registrarSignature=sig('ROOT',
  x.input.packet.appointment,x.keys.SECURITY_OFFICER)},
  'DM_ROOT_SIGNED_APPOINTMENT_NOT_AUTHENTICATED_MATHEMATICALLY');
});
test('DM attack swaps an appointed Security GitHub login but reuses old signature',()=>{
 deny(x=>{x.input.packet.appointment.officers.SECURITY_OFFICER.githubLogin=BUS},
  'DM_APPOINTED_ROLE_GITHUB_ACCOUNT_SWAP_OR_MISMATCH');
});
test('DM Security and Business labels cannot be swapped even with two valid logins',()=>{
 deny(x=>{const roles=x.input.packet.appointment.officers;
  const temp=roles.SECURITY_OFFICER;roles.SECURITY_OFFICER=roles.BUSINESS_OFFICER;
  roles.BUSINESS_OFFICER=temp;},
  'DM_APPOINTED_ROLE_GITHUB_ACCOUNT_SWAP_OR_MISMATCH');
});
test('DM author and identical Security/Business login are rejected',()=>{
 for(const [s,b] of [['j9619655391-max',BUS],[SEC,SEC],
  ['invalid name',BUS]]){
  deny(x=>{x.input.securityLogin=s;x.input.businessLogin=b},
   'DM_DISTINCT_NONAUTHOR_SECURITY_BUSINESS_NOMINEES_REQUIRED');
 }
});
test('DM changed PR HEAD invalidates signature OR terminal 1DL binding',()=>{
 const result=deny(x=>{x.input.packet.appointment.sourceHeadSha='f'.repeat(40)},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
 hold(result);
});
test('DM changed pinned main SHA invalidates 1DL binding',()=>{
 deny(x=>{x.input.packet.appointment.mainBaseSha='f'.repeat(40)},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
});
test('DM source HEAD must be valid 40 lowercase hex, not arbitrary release ID',()=>{
 for(const head of ['main','A'.repeat(40),'f'.repeat(39),null]){
  deny(x=>{x.input.packet.appointment.sourceHeadSha=head},
   'DM_SIGNED_APPOINTMENT_SCHEMA_SOURCE_OR_NONCE_INVALID');
 }
});
test('DM replayed challenge nonce or changed signed company registry fails',()=>{
 deny(x=>{x.input.packet.appointment.nonce='0'.repeat(64)},
  'DM_SIGNED_APPOINTMENT_SCHEMA_SOURCE_OR_NONCE_INVALID');
 deny(x=>{x.input.packet.appointment.registryEvidenceSha256='a'.repeat(64)},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM expired, excessive TTL, future issuance and invalid ISO clocks fail closed',()=>{
 for(const [from,until] of [
  ['2026-11-20T13:00:00.000Z','2026-11-20T13:20:00.000Z'],
  ['2026-11-20T13:59:00.000Z','2026-11-20T14:50:00.000Z'],
  ['2026-11-20T14:09:00.000Z','2026-11-20T14:19:00.000Z'],
  ['2026-11-20T13:59:00Z','2026-11-20T14:09:00.000Z']
 ]){
  deny(x=>{x.input.packet.appointment.issuedAt=from;
   x.input.packet.appointment.expiresAt=until},
  'DM_MANDATE_EXPIRED_NOT_YET_VALID_OR_EXCESSIVELY_LONG');
 }
});
test('DM malformed independent verifier clock fails even when signatures cryptographically valid',()=>{
 deny(x=>{x.input.now='yesterday'},'DM_VERIFICATION_CLOCK_INVALID');
});
test('DM applicant claims GO, authorizations or new fields reject signed scope',()=>{
 for(const key of ['productionReleaseAuthorized','independentlyAuthenticated','approveMain']){
  deny(x=>{x.input.packet.appointment[key]=true},
   'DM_SIGNED_APPOINTMENT_SCHEMA_SOURCE_OR_NONCE_INVALID');
 }
});
test('DM accidental reused registrar public key as a nominated officer is rejected',()=>{
 deny(x=>{const a=x.input.packet.appointment;
  const root=x.input.packet.registrarKey;
  x.input.packet.officerKeys.SECURITY_OFFICER=root;
  a.officers.SECURITY_OFFICER.keyId=root.keyId;
  a.officers.SECURITY_OFFICER.spkiSha256=root.spkiSha256;},
  'DM_REGISTRAR_OFFICER_KEY_COLLISION');
});
test('DM same public key used for Security and Business roles is rejected',()=>{
 deny(x=>{const a=x.input.packet.appointment;
  const k=x.input.packet.officerKeys.SECURITY_OFFICER;
  x.input.packet.officerKeys.BUSINESS_OFFICER=k;
  a.officers.BUSINESS_OFFICER.keyId=k.keyId;
  a.officers.BUSINESS_OFFICER.spkiSha256=k.spkiSha256;},
  'DM_REGISTRAR_OFFICER_KEY_COLLISION');
});
test('DM officer key substituted without updating signed appointment is rejected',()=>{
 deny(x=>{x.input.packet.officerKeys.SECURITY_OFFICER.spkiSha256='f'.repeat(64)},
  'DM_TWO_OFFICER_PUBLIC_KEY_BINDINGS_INVALID');
});
test('DM rejects signature replay across officer role domain',()=>{
 deny(x=>{x.input.packet.officerProofs.SECURITY_OFFICER.signature=
  x.input.packet.officerProofs.BUSINESS_OFFICER.signature},
  'DM_SECURITY_OFFICER_CHALLENGE_OR_SIGNATURE_INVALID');
});
test('DM falsified officer challenge role/identity/nonce/exact HEAD cannot pass',()=>{
 for(const [field,value] of [
  ['role','BUSINESS_OFFICER'],['githubLogin','other-user'],
  ['nonce','f'.repeat(64)],['sourceHeadSha','f'.repeat(40)],
  ['appointmentDigestSha256','f'.repeat(64)]
 ]){
  deny(x=>{x.input.packet.officerProofs.SECURITY_OFFICER.statement[field]=value},
   'DM_SECURITY_OFFICER_CHALLENGE_OR_SIGNATURE_INVALID');
 }
});
test('DM unknown fields in signed officer proof or missing proof denied',()=>{
 deny(x=>{x.input.packet.officerProofs.SECURITY_OFFICER.statement.go=true},
  'DM_SECURITY_OFFICER_CHALLENGE_OR_SIGNATURE_INVALID');
 deny(x=>{delete x.input.packet.officerProofs.BUSINESS_OFFICER},
  'DM_TWO_ROLE_SEPARATED_OFFICER_CHALLENGES_REQUIRED');
});
test('DM same two keys with stale officer challenge assertedAt fail',()=>{
 deny(x=>{x.input.packet.officerProofs.BUSINESS_OFFICER.statement.assertedAt=
  '2026-11-20T13:00:00.000Z'},
  'DM_BUSINESS_OFFICER_CHALLENGE_OR_SIGNATURE_INVALID');
});
test('DM no current terminal 1DL continuity permits candidate promotion',()=>{
 deny(x=>{x.input.terminalContinuity=null},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
 deny(x=>{x.input.terminalContinuity.checkedBaseMainSha='f'.repeat(40)},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
});
test('DM terminal 1DL technical quorum false or forged corporate authority forbidden',()=>{
 deny(x=>{x.input.terminalContinuity.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly=false},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
 deny(x=>{x.input.terminalContinuity.independentCorporateOfficerAppointmentsOrMandatesAuthenticated=true},
  'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
});
test('DM malformed or noncanonical signature and applicant key type denied',()=>{
 deny(x=>{x.input.packet.officerProofs.SECURITY_OFFICER.signature='!'+'a'.repeat(87)},
  'DM_SECURITY_OFFICER_CHALLENGE_OR_SIGNATURE_INVALID');
 deny(x=>{x.input.packet.registrarKey.publicKeyPem='RSA FAKE'},
  'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
});
test('DM no authentic external corporate identity even with applicant-root re-sign',()=>{
 const x=fixture();
 // An applicant who supplies all public keys, signatures and pins can
 // manufacture a mathematically consistent packet. This never proves
 // legal enrollment, MCA issuer authority or production release.
 const a=assessOfflineCorporateAppointmentCandidate(x.input);
 assert.equal(a.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly,true);
 assert.equal(a.independentLegalCorporateRegistrarRootAuthorityAuthenticated,false);
 assert.equal(a.independentSecurityBusinessOfficerAppointmentsAuthenticated,false);
 hold(a);
});
test('DM no raw nominees, PEM, applicant signatures or challenge nonce in report',()=>{
 const x=fixture();const report=JSON.stringify(
  assessOfflineCorporateAppointmentCandidate(x.input));
 for(const confidential of [SEC,BUS,NONCE,REG,
  x.input.packet.registrarSignature,
  x.input.packet.registrarKey.publicKeyPem,
  x.input.packet.officerProofs.SECURITY_OFFICER.signature])
  assert.equal(report.includes(confidential),false);
});
test('DM no network writes, privileged operator CLI, GitHub admin bypass or GO in source',()=>{
 const s=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dm-corporate-appointment-challenge-handoff.mjs'),'utf8');
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(s),false);
 assert.equal(s.includes('process.env.GITHUB_READ_TOKEN'),false);
 assert.equal(s.includes('writeFileSync'),false);
 assert.equal(s.includes('productionReleaseAuthorized:true'),false);
});
