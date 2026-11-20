import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {validateReviewerNominees}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';

// 1DM: an OFFLINE, UNTRUSTED signed corporate appointment *candidate*.
// No key/source may assert independent enrollment. An operator-provided
// matching SPKI or legal-registry digest cannot establish provenance.
export const ROLES=Object.freeze(['SECURITY_OFFICER','BUSINESS_OFFICER']);
export const DOMAIN='aaditech/phase1dm/appointment-to-github-role-candidate/v1/';
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/,
 LOGIN=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/,
 ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,names)=>own(x)&&Object.keys(x).length===names.length&&
 names.every(k=>Object.hasOwn(x,k));
const held=x=>x?.productionReleaseAuthorized===false&&
 x?.productionReleaseBlocked===true&&x?.releaseDecision==='HOLD';
const sha=x=>createHash('sha256').update(x).digest('hex');
const stamp=x=>{
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const ms=Date.parse(x);
 return Number.isFinite(ms)&&new Date(ms).toISOString()===x?ms:NaN;
};
const K=['keyId','publicKeyPem','spkiSha256'];
const T=['registrarSpkiSha256','registryEvidenceSha256'];
const O=['githubLogin','keyId','spkiSha256'];
const A=['schemaVersion','kind','repository','sourceHeadSha','mainBaseSha',
 'organizationId','registryEvidenceSha256','nonce','issuedAt','expiresAt',
 'decision','officers'];
const S=['schemaVersion','kind','repository','sourceHeadSha','mainBaseSha',
 'organizationId','role','githubLogin','nonce','appointmentDigestSha256',
 'assertedAt','decision'];
const P=['statement','signature'];
const PACKET=['appointment','registrarKey','registrarSignature',
 'officerKeys','officerProofs'];

function validKey(k){
 if(!exact(k,K)||!ID.test(k.keyId??'')||!
  HASH.test(k.spkiSha256??'')||
  typeof k.publicKeyPem!=='string'||k.publicKeyPem.length>4096)return false;
 try{
  const pub=createPublicKey(k.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   sha(pub.export({format:'der',type:'spki'}))===k.spkiSha256;
 }catch{return false;}
}
export function candidateSigningBytes(role,statement){
 if(!['ROOT',...ROLES].includes(role)||!own(statement)||
  JSON.stringify(statement).length>8192)
  throw Error('DM_UNKNOWN_ROLE_OR_UNBOUNDED_SIGNED_CLAIM');
 return Buffer.from(DOMAIN+role+'/v1\n'+canonical(statement),'utf8');
}
function verified(role,statement,signature,key){
 if(!validKey(key)||typeof signature!=='string'||!SIG.test(signature))
  return false;
 try{
  const sig=Buffer.from(signature,'base64');
  return sig.length===64&&sig.toString('base64')===signature&&
   verify(null,candidateSigningBytes(role,statement),
    createPublicKey(key.publicKeyPem),sig);
 }catch{return false;}
}
function safeRoleLogin(login){
 return typeof login==='string'&&LOGIN.test(login)&&
  login.toLowerCase()!=='j9619655391-max';
}
const result=(errors,head,main,registrarMatch,signatureCount,roleMatched,
 continuity)=>Object.freeze({
 phase:'1DM',schemaVersion:1,
 kind:'OFFLINE_UNTRUSTED_CORPORATE_APPOINTMENT_GITHUB_ROLE_CHALLENGE_HARD_HOLD',
 repository:REPO,
 currentDevelopmentHeadSha:SHA.test(head??'')?head:null,
 currentMainBaseSha:SHA.test(main??'')?main:null,
 outOfBandExpectedPinsMatchedLocallyOnly:registrarMatch,
 matchedRealGitHubRoleContinuityReceiptShapeOnly:continuity,
 roleNamesAndIndependentKeyPossessionProvenMathematicallyOnly:roleMatched,
 candidateDetachedEd25519SignaturesVerifiedOnly:signatureCount,
 candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly:
  errors.size===0&&signatureCount===3&&registrarMatch&&roleMatched&&continuity,
 applicantOrOperatorSuppliedRootPinsNotIndependentlyEnrolled:true,
 independentLegalCorporateRegistrarRootAuthorityAuthenticated:false,
 independentSecurityBusinessOfficerAppointmentsAuthenticated:false,
 independentlyAuthenticatedMcaRegistryOrLegalSignatory:false,
 noExternalCredentialOrPrivateOfficerDataExposed:true,
 cannotConvertUntrustedCandidateIntoProductionAuthority:true,
 canWriteGithubMainReviewMergeOrRelease:false,
 anomalyCodes:Object.freeze([...errors].sort()),
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});

/**
 * Input: applicant/offline public-key packet plus separately supplied
 * expected pinned registrar SPKI and registry document SHA. Even matching
 * them is not proof they were enrolled by corporate legal authorities.
 *
 * The in-memory 1DL terminal receipt is read-only; it too proves only
 * technical GitHub reviewer pair continuity and not real corporate roles.
 * Never emit username, PEM, nonce, private or public root key, signature,
 * applicant documents, or HMAC into the returned operator receipt.
 */
export function assessOfflineCorporateAppointmentCandidate({
 packet=null,expectedExternalPins=null,terminalContinuity=null,
 securityLogin=null,businessLogin=null,
 now='2026-11-20T14:00:00.000Z'
}={}){
 const errors=new Set();
 const add=(ok,id)=>{if(!ok)errors.add(id);};
 let size=Infinity;
 try{size=Buffer.byteLength(JSON.stringify(packet),'utf8');}catch{}
 add(size>=1&&size<=32768,'DM_UNBOUNDED_OR_UNSERIALIZABLE_OFFLINE_PACKET');
 const t=stamp(now);
 add(Number.isFinite(t),'DM_VERIFICATION_CLOCK_INVALID');
 const nominees=validateReviewerNominees(securityLogin,businessLogin).valid;
 add(nominees,'DM_DISTINCT_NONAUTHOR_SECURITY_BUSINESS_NOMINEES_REQUIRED');
 add(exact(packet,PACKET),'DM_UNTRUSTED_CORPORATE_PACKET_SCHEMA');
 const app=packet?.appointment,root=packet?.registrarKey;
 const pk=packet?.officerKeys,proofs=packet?.officerProofs;
 const head=app?.sourceHeadSha,main=app?.mainBaseSha;
 const roles=app?.officers;
 const at=stamp(app?.issuedAt),until=stamp(app?.expiresAt);
 const current=Number.isFinite(t)&&Number.isFinite(at)&&
  Number.isFinite(until)&&at>=t-900000&&at<=t+300000&&
  until>t&&until>at&&until<=at+900000;
 add(current,'DM_MANDATE_EXPIRED_NOT_YET_VALID_OR_EXCESSIVELY_LONG');
 const basic=exact(app,A)&&app.schemaVersion===1&&
  app.kind==='CANDIDATE_CORPORATE_APPOINTMENT_NOT_AUTHORIZED'&&
  app.repository===REPO&&SHA.test(head??'')&&SHA.test(main??'')&&
  ID.test(app.organizationId??'')&&
  HASH.test(app.registryEvidenceSha256??'')&&
  HASH.test(app.nonce??'')&&app.nonce!=='0'.repeat(64)&&
  app.decision==='HOLD'&&exact(roles,ROLES);
 add(basic,'DM_SIGNED_APPOINTMENT_SCHEMA_SOURCE_OR_NONCE_INVALID');
 const sameRoleLogin=nominees&&ROLES.every((role,i)=>
  exact(roles?.[role],O)&&
  safeRoleLogin(roles[role].githubLogin)&&
  roles[role].githubLogin.toLowerCase()===
   (i===0?securityLogin:businessLogin).toLowerCase()&&
  ID.test(roles[role].keyId??'')&&
  HASH.test(roles[role].spkiSha256??''));
 add(sameRoleLogin,'DM_APPOINTED_ROLE_GITHUB_ACCOUNT_SWAP_OR_MISMATCH');
 const expectedValid=exact(expectedExternalPins,T)&&
  HASH.test(expectedExternalPins.registrarSpkiSha256??'')&&
  HASH.test(expectedExternalPins.registryEvidenceSha256??'');
 const registrarMatch=Boolean(expectedValid&&validKey(root)&&
  expectedExternalPins.registrarSpkiSha256===root.spkiSha256&&
  expectedExternalPins.registryEvidenceSha256===app?.registryEvidenceSha256);
 add(registrarMatch,'DM_OUT_OF_BAND_ROOT_OR_REGISTRY_PIN_NOT_MATCHED');
 const keySchemas=exact(pk,ROLES)&&ROLES.every(role=>
  validKey(pk[role])&&
  roles?.[role]?.keyId===pk[role].keyId&&
  roles?.[role]?.spkiSha256===pk[role].spkiSha256);
 add(keySchemas,'DM_TWO_OFFICER_PUBLIC_KEY_BINDINGS_INVALID');
 const distinct=registrarMatch&&keySchemas&&
  new Set([root.spkiSha256,...ROLES.map(role=>pk[role].spkiSha256)]).size===3&&
  new Set([root.keyId,...ROLES.map(role=>pk[role].keyId)]).size===3;
 add(distinct,'DM_REGISTRAR_OFFICER_KEY_COLLISION');
 const bound=terminalContinuity?.phase==='1DL'&&
  terminalContinuity?.schemaVersion===1&&
  terminalContinuity?.repository===REPO&&held(terminalContinuity)&&
  terminalContinuity.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly===true&&
  terminalContinuity.operatorSessionNomineePairBoundAcrossReadsOnly===true&&
  terminalContinuity.initialAndTerminalGovernanceJoinConsistentOnly===true&&
  terminalContinuity.checkedSourceHeadSha===head&&
  terminalContinuity.checkedBaseMainSha===main&&
  terminalContinuity.opaqueSessionKeyAndReviewerIdentityExcludedFromOutput===true&&
  terminalContinuity.independentCorporateOfficerAppointmentsOrMandatesAuthenticated===false&&
  Array.isArray(terminalContinuity.anomalyCodes)&&
  terminalContinuity.anomalyCodes.length===0;
 add(bound,'DM_ACTUAL_GITHUB_NOMINEE_SESSION_AND_SOURCE_NOT_BOUND');
 const appGood=basic&&sameRoleLogin&&registrarMatch&&
  keySchemas&&distinct&&current&&size<=32768;
 const signedRoot=appGood&&verified('ROOT',app,packet?.registrarSignature,root);
 add(signedRoot,'DM_ROOT_SIGNED_APPOINTMENT_NOT_AUTHENTICATED_MATHEMATICALLY');
 let digest=null;
 try{if(appGood)digest=sha(candidateSigningBytes('ROOT',app));}catch{}
 add(exact(proofs,ROLES),'DM_TWO_ROLE_SEPARATED_OFFICER_CHALLENGES_REQUIRED');
 let verifiedCount=signedRoot?1:0;
 let officersSigned=true;
 for(const role of ROLES){
  const packetRole=proofs?.[role],statement=packetRole?.statement;
  const officer=roles?.[role];
  const row=exact(packetRole,P)&&exact(statement,S)&&
   statement.schemaVersion===1&&
   statement.kind==='CANDIDATE_OFFICER_KEY_POSSESSION_HOLD'&&
   statement.repository===REPO&&
   statement.sourceHeadSha===head&&statement.mainBaseSha===main&&
   statement.organizationId===app?.organizationId&&
   statement.role===role&&
   statement.githubLogin===officer?.githubLogin&&
   statement.nonce===app?.nonce&&
   statement.appointmentDigestSha256===digest&&
   statement.decision==='HOLD'&&
   Number.isFinite(stamp(statement.assertedAt))&&
   stamp(statement.assertedAt)>=at&&
   stamp(statement.assertedAt)<=t+300000&&
   stamp(statement.assertedAt)<until;
  const ok=row&&verified(role,statement,
   packetRole?.signature,pk?.[role]);
  if(!ok){
   errors.add('DM_'+role+'_CHALLENGE_OR_SIGNATURE_INVALID');
   officersSigned=false;
  }else verifiedCount++;
 }
 return result(errors,head,main,registrarMatch,verifiedCount,
  Boolean(sameRoleLogin&&keySchemas&&distinct&&officersSigned),bound);
}
