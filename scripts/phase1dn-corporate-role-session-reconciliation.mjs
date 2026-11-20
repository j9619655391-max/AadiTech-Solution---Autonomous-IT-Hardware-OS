import {Buffer} from 'node:buffer';
import {REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {assessOfflineCorporateAppointmentCandidate}
 from './phase1dm-corporate-appointment-challenge-handoff.mjs';
import {assessEphemeralReviewerHandoffContinuity}
 from './phase1dl-ephemeral-reviewer-handoff-continuity.mjs';

// Phase 1DN: explicit OFFLINE signed-candidate -> ORIGINAL in-memory
// role-bound GitHub reviewer session composition. A public 1DL report
// deliberately omits identities: its boolean alone CANNOT bind the
// corporate appointment to the actual Security/Business GitHub pair.
//
// Human operator session evidence must come from the same trusted
// local invocation; none of this independently enrolls legal trust.
const SHA=/^[0-9a-f]{40}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
export const OPERATOR_SESSION_FIELDS=Object.freeze([
 'sessionKey','roleQuorumFirst','roleQuorumSecond','roleJoin',
 'pinnedOwners','terminalNominatedReview','terminalReadback'
]);
const HELD=Object.freeze({
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD'
});

/**
 * This remains candidate-only: signer keys, out-of-band registrar pins,
 * GitHub session evidences and named roles are NOT authenticated by
 * independent corporate legal or CA authorities.
 *
 * No CLI, fetch, privileged GitHub mutation, private key persistence,
 * raw legal docs, usernames, MAC, PEM or nonce is emitted in the receipt.
 */
export function assessInProcessAppointmentReviewerBinding({
 candidatePacket=null,expectedExternalPins=null,operatorSession=null,
 now='2026-11-20T14:00:00.000Z'
}={}){
 const errors=new Set();
 const nominees=candidatePacket?.appointment?.officers;
 const securityLogin=nominees?.SECURITY_OFFICER?.githubLogin??null;
 const businessLogin=nominees?.BUSINESS_OFFICER?.githubLogin??null;
 const head=candidatePacket?.appointment?.sourceHeadSha??null;
 const main=candidatePacket?.appointment?.mainBaseSha??null;
 const inputComplete=exact(operatorSession,OPERATOR_SESSION_FIELDS)&&
  Buffer.isBuffer(operatorSession.sessionKey)&&
  operatorSession.sessionKey.byteLength===32;
 if(!inputComplete)
  errors.add('DN_OPERATOR_LOCAL_EXACT_SESSION_EVIDENCE_REQUIRED');
 // Never reflect credentials or raw error contents in downstream results.
 const technical=assessEphemeralReviewerHandoffContinuity({
  sessionKey:inputComplete?operatorSession.sessionKey:null,
  securityLogin,businessLogin,
  roleQuorumFirst:inputComplete?operatorSession.roleQuorumFirst:null,
  roleQuorumSecond:inputComplete?operatorSession.roleQuorumSecond:null,
  roleJoin:inputComplete?operatorSession.roleJoin:null,
  pinnedOwners:inputComplete?operatorSession.pinnedOwners:null,
  terminalNominatedReview:inputComplete?
   operatorSession.terminalNominatedReview:null,
  terminalReadback:inputComplete?operatorSession.terminalReadback:null
 });
 const sessionBound=inputComplete&&
  technical.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly===true&&
  technical.operatorSessionNomineePairBoundAcrossReadsOnly===true&&
  technical.initialAndTerminalGovernanceJoinConsistentOnly===true&&
  technical.opaqueSessionKeyAndReviewerIdentityExcludedFromOutput===true&&
  technical.checkedSourceHeadSha===head&&
  technical.checkedBaseMainSha===main&&
  technical.anomalyCodes.length===0;
 if(!sessionBound)
  errors.add('DN_SIGNED_ROLE_PAIR_NOT_BOUND_TO_ORIGINAL_GITHUB_OPERATOR_SESSION');
 const candidate=assessOfflineCorporateAppointmentCandidate({
  packet:candidatePacket,expectedExternalPins,
  terminalContinuity:technical,securityLogin,businessLogin,now
 });
 const signedCandidateComplete=
  candidate.candidateCorporateRegistrarAndTwoOfficerProofsStructurallyConsistentOnly===true&&
  candidate.candidateDetachedEd25519SignaturesVerifiedOnly===3&&
  candidate.outOfBandExpectedPinsMatchedLocallyOnly===true&&
  candidate.roleNamesAndIndependentKeyPossessionProvenMathematicallyOnly===true&&
  candidate.currentDevelopmentHeadSha===head&&
  candidate.currentMainBaseSha===main&&candidate.anomalyCodes.length===0;
 if(!signedCandidateComplete)
  errors.add('DN_CORPORATE_SIGNATURE_AND_OFFICER_CHALLENGE_CANDIDATE_INVALID');
 if(!SHA.test(head??'')||!SHA.test(main??''))
  errors.add('DN_UNPINNED_PR_HEAD_OR_MAIN_BASE_SHA');
 const joined=errors.size===0&&sessionBound&&signedCandidateComplete;
 return Object.freeze({
  phase:'1DN',schemaVersion:1,
  kind:'IN_PROCESS_SIGNED_CORPORATE_NOMINEE_GITHUB_SESSION_BINDING_HARD_HOLD',
  repository:REPO,
  checkedSourceHeadSha:SHA.test(head??'')?head:null,
  checkedBaseMainSha:SHA.test(main??'')?main:null,
  exactOperatorLocalSessionFieldsAndFreshKeyProvidedOnly:inputComplete,
  signedOfficerRoleOrderMatchedAgainstActualSessionHmacOnly:sessionBound,
  applicantSignedRegistrarAndTwoOfficerSignaturesMathematicallyConsistentOnly:
   signedCandidateComplete,
  inProcessCrossPhaseCandidateContractConsistentOnly:joined,
  // 1DN is a technical composition of two UNTRUSTED report families.
  // Even a true joined status must NOT be promoted to release authority.
  registrarSpkiAndCorporateRegistryPinsOperatorSuppliedOnly:true,
  independentlyAuthenticatedCorporateRegistrarEnrollment:false,
  independentlyAuthenticatedMcaCorporateIdentityOrLegalMandates:false,
  actualSecurityBusinessCorporateAppointmentsIndependentlyVerified:false,
  independentlyAuthenticatedGithubReviewWritePrivilegesOrPolicy:false,
  providerSignedCaRevocationAndExternalWormOrStagingVerified:false,
  sessionKeyRawGithubLoginsPemSignaturesAndNonceExcludedFromOutput:true,
  noOperatorSessionCanPromoteProductionRelease:true,
  canRequestGithubReviewsInstallMainMergeOrDeploy:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  ...HELD
 });
}
