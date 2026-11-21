import {Buffer} from 'node:buffer';
import {createHmac,timingSafeEqual} from 'node:crypto';
import {REPO,AUTHOR,validateReviewerNominees}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';

// Phase 1DL: ephemeral, in-process reviewer-identity CONTINUITY ONLY.
// Session-key is created by the authorised human's local process and must
// NEVER be written to Git, stdout, issue, PR, logs or the signed evidence.
// An opaque HMAC cannot independently authenticate actual corporate officers,
// proof of legal delegation, or an external audit witness.
const SHA=/^[0-9a-f]{40}$/;
const HMAC=/^[0-9a-f]{64}$/;
const held=x=>x?.productionReleaseAuthorized===false&&
 x?.productionReleaseBlocked===true&&x?.releaseDecision==='HOLD';
export const DOMAIN='AADI-1DL-Ephemeral-Review-Nominee-Role-Binding-V1\n';

export function deriveEphemeralReviewerRoleBinding({
 sessionKey=null,securityLogin=null,businessLogin=null,
 currentDevHeadSha=null,currentMainBaseSha=null
}={}){
 if(!Buffer.isBuffer(sessionKey)||sessionKey.byteLength!==32||
  !validateReviewerNominees(securityLogin,businessLogin).valid||
  !SHA.test(currentDevHeadSha??'')||!SHA.test(currentMainBaseSha??''))
  return null;
 try{
  // Array order is MATERIAL: Security != Business. Never sort nominees.
  const data=JSON.stringify([
   REPO,1,'chore/phase0-foundation-20261106','main',
   currentDevHeadSha,currentMainBaseSha,
   'SECURITY_OFFICER',securityLogin.toLowerCase(),
   'BUSINESS_OFFICER',businessLogin.toLowerCase()
  ]);
  return createHmac('sha256',sessionKey).update(DOMAIN+data,'utf8')
   .digest('hex');
 }catch{return null;}
}
const equal=(a,b)=>HMAC.test(a??'')&&HMAC.test(b??'')&&
 timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));

/**
 * GET-only technical cross-phase read continuity.
 *
 * The initial two 1CO readings, 1DF join, exact base-main pinned 1DG
 * CODEOWNERS, final 1CO reading and 1DI's readback must all originate
 * from the SAME two role-specific GitHub logins, same source/base SHAs
 * and the same operator session. It is never a legal/corporate mandate.
 */
export function assessEphemeralReviewerHandoffContinuity({
 sessionKey=null,securityLogin=null,businessLogin=null,
 roleQuorumFirst=null,roleQuorumSecond=null,
 roleJoin=null,pinnedOwners=null,
 terminalNominatedReview=null,terminalReadback=null
}={}){
 const errors=new Set();
 const head=roleJoin?.currentDevelopmentHeadSha;
 const main=roleJoin?.currentMainBaseSha;
 const expected=deriveEphemeralReviewerRoleBinding({
  sessionKey,securityLogin,businessLogin,
  currentDevHeadSha:head,currentMainBaseSha:main
 });
 if(!expected)errors.add('DL_DISTINCT_AUTHORIZED_ROLE_PAIR_OR_SESSION_KEY_INVALID');
 const q=[roleQuorumFirst,roleQuorumSecond,terminalNominatedReview];
 const technical=q.every(t=>t?.phase==='1CO'&&t?.schemaVersion===1&&
  t?.repository===REPO&&t?.currentDevHead===head&&held(t)&&
  t.prReadBeforeAndAfterStable===true&&
  t.actualGithubReviewPaginationComplete===true&&
  t.securityNominatedAccountActuallyApprovedCurrentHead===true&&
  t.businessNominatedAccountActuallyApprovedCurrentHead===true&&
  t.actualNominatedReviewerWritePermissionsObserved===true&&
  t.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved===true&&
  t.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated===false&&
  Array.isArray(t.anomalyCodes)&&t.anomalyCodes.length===0);
 if(!technical)errors.add('DL_ALL_THREE_SOURCE_BOUND_NOMINEE_READS_REQUIRED');
 const bindings=Boolean(expected)&&q.every(t=>equal(
  t?.opaqueReviewerRoleSessionHmacSha256,expected))&&
  equal(roleJoin?.opaqueReviewerRoleSessionHmacSha256,expected);
 if(!bindings)errors.add('DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
 const join=roleJoin?.phase==='1DF'&&roleJoin?.schemaVersion===1&&
  roleJoin.repository===REPO&&held(roleJoin)&&
  roleJoin.roleBoundNomineeContinuityOnly===true&&
  roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly===true&&
  roleJoin.effectiveBaseMainGovernanceReadableOnly===true&&
  SHA.test(head??'')&&SHA.test(main??'');
 if(!join)errors.add('DL_INITIAL_ROLE_BOUND_HANDOFF_MISSING');
 const owners=pinnedOwners?.phase==='1DG'&&pinnedOwners?.schemaVersion===1&&
  pinnedOwners?.repository===REPO&&held(pinnedOwners)&&
  pinnedOwners.currentDevelopmentHeadSha===head&&
  pinnedOwners.pinnedBaseMainSha===main&&
  pinnedOwners.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly===true&&
  pinnedOwners.exactTwoNominatedAccountsInEachAcceptedRuleOnly===true&&
  Array.isArray(pinnedOwners.anomalyCodes)&&pinnedOwners.anomalyCodes.length===0;
 if(!owners)errors.add('DL_PINNED_CODEOWNER_NOMINEE_BINDING_NOT_VERIFIED');
 const terminal=terminalReadback?.phase==='1DI'&&
  terminalReadback?.schemaVersion===1&&
  terminalReadback?.repository===REPO&&held(terminalReadback)&&
  terminalReadback.checkedSourceHeadSha===head&&
  terminalReadback.checkedBaseMainSha===main&&
  terminalReadback.wholeOperatorReadWindowTechnicallyConsistentOnly===true&&
  terminalReadback.reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly===true&&
  terminalReadback.noReviewerUsernamesOrOperatorTokenRetained===true&&
  Array.isArray(terminalReadback.anomalyCodes)&&
  terminalReadback.anomalyCodes.length===0;
 if(!terminal)errors.add('DL_FINAL_MAIN_POLICY_REVIEW_HISTORY_HOLD_MISSING');
 const consistent=errors.size===0;
 return Object.freeze({
  phase:'1DL',schemaVersion:1,
  kind:'EPHEMERAL_GITHUB_ROLE_NOMINEE_CROSS_PHASE_CONTINUITY_HARD_HOLD',
  repository:REPO,
  checkedSourceHeadSha:SHA.test(head??'')?head:null,
  checkedBaseMainSha:SHA.test(main??'')?main:null,
  threeCurrentHeadRoleSpecificActualReadbacksOnly:technical,
  operatorSessionNomineePairBoundAcrossReadsOnly:bindings,
  initialAndTerminalGovernanceJoinConsistentOnly:Boolean(join&&owners&&terminal),
  technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly:consistent,
  // No HMAC, raw username, nonce, token or session key is emitted.
  opaqueSessionKeyAndReviewerIdentityExcludedFromOutput:true,
  cannotBeIndependentlyReplayedWithoutOriginalSessionKey:true,
  independentCorporateOfficerAppointmentsOrMandatesAuthenticated:false,
  externalSignerKeysAndMcaCaWormDrOidcStagingVerified:false,
  canInstallMainPolicyRequestReviewsMergeOrDeploy:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
