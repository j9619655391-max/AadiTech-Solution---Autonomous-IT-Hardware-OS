import {createHash} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,canonical}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EXTERNAL_GATES,collectLiveActualGovernance}
 from './phase1dc-live-external-governance-readiness.mjs';

// Phase 1DD: produce a minimal actionable handoff from real GitHub reads.
// Corporate or provider evidence is never authenticated by a digest supplied
// by an applicant. This module never writes GitHub state or releases.
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const clock=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const digest=x=>createHash('sha256').update(x).digest('hex');
const recordKeys=['gate','custodianRole','evidenceClass',
 'recordDigestSha256','collectedAt','expiresAt','reviewState'];
const metaKeys=['schemaVersion','repository','sourceHeadSha','mainBaseSha',
 'createdAt','records'];
export const ACTIONS=Object.freeze([
 ['GOVERNANCE_SECURITY_AND_BUSINESS_NONAUTHOR_MANDATE',
  'CORPORATE_OWNER_AND_LEGAL','CORPORATE_MANDATE',
  'Independently appoint distinct nonauthor Security and Business officers and verify delegated authority outside Git/chat'],
 ['GOVERNANCE_ADMIN_INSTALL_MAIN_CODEOWNERS',
  'AUTHORIZED_GITHUB_ADMIN','MAIN_CODEOWNERS',
  'Independently check all base-main CODEOWNERS locations, then propose and authorize actual protected-main owner coverage'],
 ['GOVERNANCE_ADMIN_ENFORCE_BYPASS_FREE_MAIN_RULESETS',
  'AUTHORIZED_GITHUB_ADMIN','MAIN_BRANCH_RULESET',
  'Independently inspect full main branch protection, bypass actors, required checks and admin enforcement with approved admin permissions'],
 ['GOVERNANCE_INDEPENDENT_LATEST_HEAD_REVIEWERS',
  'INDEPENDENT_SECURITY_BUSINESS_REVIEWERS','GITHUB_LATEST_HEAD_REVIEWS',
  'Have both authenticated appointed nonauthor reviewers submit and verify current-HEAD approvals through normal review workflow'],
 ['CORPORATE_MCA_AND_LEGAL_SIGNATORY',
  'CORPORATE_LEGAL_COMPLIANCE','MCA_LEGAL_AUTHORITY',
  'Independently verify company registry and corporate authorized signatory documentation'],
 ['CA_CCA_RCAI_EMUDHRA_SIGNED_CHAIN_CRL_OCSP',
  'AUTHORIZED_CA_PROVIDER_AND_LEGAL','PROVIDER_CA_REVOCATION',
  'Obtain real approved eMudhra/RCAI/CCA trust chain, certificate policies and independently authenticated revocation responses'],
 ['PROVIDER_OFFICIAL_AUTHORIZED_ENDPOINTS_AND_REVOCATION',
  'AUTHORIZED_EXTERNAL_TRUST_PROVIDER','PROVIDER_TRUST_ENROLLMENT',
  'Confirm signed agreement, provider-issued source identities, authorized endpoint ownership and independently pinned issuer/TLS credentials'],
 ['EXTERNAL_IMMUTABLE_CAS_WORM_DR_INDEPENDENT_CHECK',
  'INDEPENDENT_STORAGE_SECURITY_AUDITOR','EXTERNAL_CAS_WORM_DR',
  'Witness real external atomic CAS and immutable readback, WORM COMPLIANCE denied deletion and independently tested DR restore'],
 ['OIDC_SLSA_AND_SECURITY_LEGAL_OWNER_OPS_STAGING',
  'INDEPENDENT_RELEASE_GOVERNANCE','STAGING_RELEASE_ACCEPTANCE',
  'Verify signed OIDC/SLSA provenance and independent Security, Legal, Ops and Owner staging signoffs']
]);
if(ACTIONS.length!==EXTERNAL_GATES.length||
   ACTIONS.some(([key],i)=>key!==EXTERNAL_GATES[i]))
 throw Error('DD_EXTERNAL_ACTION_REGISTER_DRIFT');
const evidenceRoles=new Map(ACTIONS.map(([key,role,cls])=>[key,{role,cls}]));
const nonneg=x=>Number.isSafeInteger(x)&&x>=0&&x<=100000;
function validateMetadata(metadata,head,base,time){
 if(metadata===null||metadata===undefined)
  return {provided:false,locallyValid:false,count:0,errors:[]};
 const errors=new Set(),add=(ok,s)=>{if(!ok)errors.add(s)};
 const top=exact(metadata,metaKeys);
 add(top,'DD_UNREVIEWED_INTAKE_METADATA_SCHEMA');
 add(metadata?.schemaVersion===1&&metadata?.repository===REPO&&
     metadata?.sourceHeadSha===head&&metadata?.mainBaseSha===base&&
     SHA.test(metadata?.sourceHeadSha??'')&&SHA.test(metadata?.mainBaseSha??''),
  'DD_INTAKE_REPOSITORY_OR_CURRENT_HEAD_MISMATCH');
 const t=clock(metadata?.createdAt);
 add(Number.isFinite(t)&&Number.isFinite(time)&&
     t>=time-900000&&t<=time+300000,
  'DD_INTAKE_METADATA_FRESHNESS_UNVERIFIED');
 const records=metadata?.records;
 add(Array.isArray(records)&&records.length===ACTIONS.length,
  'DD_EXACT_EXTERNAL_GATE_METADATA_SET_REQUIRED');
 const seen=new Set(),hashes=new Set();
 for(const rec of Array.isArray(records)?records.slice(0,12):[]){
  if(!exact(rec,recordKeys)){
   errors.add('DD_UNREVIEWED_EXTERNAL_RECORD_FIELDS');continue;
  }
  if(seen.has(rec.gate)||!evidenceRoles.has(rec.gate))
   errors.add('DD_DUPLICATE_OR_UNKNOWN_EXTERNAL_GATE');
  seen.add(rec.gate);
  const want=evidenceRoles.get(rec.gate);
  if(rec.custodianRole!==want?.role||rec.evidenceClass!==want?.cls||
     rec.reviewState!=='UNVERIFIED')
   errors.add('DD_EXTERNAL_CUSTODIAN_OR_REVIEW_ASSERTION_INVALID');
  if(!HASH.test(rec.recordDigestSha256??'')||
     rec.recordDigestSha256==='0'.repeat(64)||
     hashes.has(rec.recordDigestSha256))
   errors.add('DD_EVIDENCE_DIGEST_MISSING_REPEATED_OR_FORGED');
  hashes.add(rec.recordDigestSha256);
  const collected=clock(rec.collectedAt),end=clock(rec.expiresAt);
  if(!Number.isFinite(collected)||!Number.isFinite(end)||
     collected>time+300000||collected<time-900000||
     end<=time||end<=collected||end>time+365*86400000)
   errors.add('DD_EVIDENCE_TIMESTAMPS_UNREVIEWED');
 }
 if(seen.size!==ACTIONS.length)
  errors.add('DD_REQUIRED_EXTERNAL_GATE_METADATA_MISSING');
 // A metadata digest is an applicant-provided *reference*, never a signature,
 // corporate proof, immutable remote object, or approved record.
 return {provided:true,locallyValid:errors.size===0,
  count:Math.min(Array.isArray(records)?records.length:0,12),
  errors:[...errors].sort()};
}
export function assessIndependentOperatorHandoff({
 governance=null,metadata=null,now='2026-11-20T00:00:00.000Z'
}={}){
 const anomalies=new Set(),time=clock(now);
 if(!Number.isFinite(time))anomalies.add('DD_INVALID_OPERATOR_CLOCK');
 const safe=governance?.phase==='1DC'&&
  governance?.kind==='ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD'&&
  governance?.repository===REPO&&
  governance?.productionReleaseAuthorized===false&&
  governance?.productionReleaseBlocked===true&&governance?.releaseDecision==='HOLD';
 if(!safe)anomalies.add('DD_PRECEDING_GITHUB_READONLY_HOLD_REPORT_INVALID');
 const stable=safe&&governance.officialMainRefAndDraftPrStable===true&&
  SHA.test(governance.currentDevelopmentHeadSha??'')&&
  SHA.test(governance.currentMainBaseSha??'');
 if(!stable)anomalies.add('DD_OFFICIAL_HEAD_BASE_NOT_STABLY_VERIFIED');
 const counts=safe&&[
  governance.observedSubmittedReviewCount,
  governance.observedDistinctCurrentHeadNonauthorApprovals,
  governance.strictRootCoverageCodeownersFiles,
  governance.observedStrictBypassFreeMainRulesetCount,
  governance.observedActiveBranchRulesetCount
 ].every(nonneg);
 if(!counts)anomalies.add('DD_GITHUB_READONLY_COUNTS_MISSING_OR_UNTRUSTED');
 const technical=safe&&governance.technicallyObservedGithubPrerequisitesOnly===true;
 const reported=Array.isArray(governance?.anomalyCodes)&&
  governance.anomalyCodes.every(x=>typeof x==='string'&&x.startsWith('DC_')&&
   x.length<=110);
 if(!reported)anomalies.add('DD_UPSTREAM_GITHUB_ANOMALY_LIST_INVALID');
 const head=stable?governance.currentDevelopmentHeadSha:null,
  base=stable?governance.currentMainBaseSha:null;
 const priorCodes=reported?governance.anomalyCodes:[];
 const metadataResult=validateMetadata(metadata,head,base,time);
 for(const code of metadataResult.errors)anomalies.add(code);
 const reviews=counts?governance.observedDistinctCurrentHeadNonauthorApprovals:0,
  owners=counts?governance.strictRootCoverageCodeownersFiles:0,
  rules=counts?governance.observedStrictBypassFreeMainRulesetCount:0,
  branch=governance?.directMainBranchProtectionStatus,
  branch403=governance?.directMainBranchProtectionExplicitly403===true;
 if(!['read','access_denied','absent_or_hidden','unavailable','invalid'].includes(branch))
  anomalies.add('DD_MAIN_BRANCH_PROTECTION_STATUS_UNVERIFIED');
 if(branch403&&branch!=='access_denied')
  anomalies.add('DD_PROTECTION_403_NOT_PRESERVED_AS_UNKNOWN');
 const cases=[
  null,
  owners>0?'TECHNICALLY_OBSERVED_NOT_LEGALLY_APPROVED':'NOT_VERIFIABLY_INSTALLED',
  rules>0&&branch==='read'?'TECHNICALLY_OBSERVED_NOT_LEGALLY_APPROVED':
   branch==='access_denied'?'ADMIN_ACCESS_REQUIRED_UNKNOWN_PROTECTION':
   'NOT_VERIFIABLY_ENFORCED',
  reviews>=2?'TECHNICALLY_OBSERVED_NO_CORPORATE_MANDATE':'APPROVALS_MISSING_OR_STALE',
  null,null,null,null,null
 ];
 const statusRows=ACTIONS.map(([key,role,cls,action],i)=>({
  gate:key,custodianRole:role,evidenceClass:cls,
  technicalSignal:cases[i]??'INDEPENDENT_EXTERNAL_AUTHORITY_NOT_ONBOARDED',
  metadataReferencePresent:metadataResult.provided&&
   metadataResult.locallyValid,
  independentlyAuthenticated:false,
  requiredNextAction:action
 }));
 if(technical&&!stable)anomalies.add('DD_TECHNICAL_READY_WITH_UNSTABLE_OFFICIAL_SOURCE');
 if(technical&&priorCodes.length>0)
  anomalies.add('DD_TECHNICAL_READY_BUT_UPSTREAM_GITHUB_ANOMALIES');
 const receiptDigest=digest(Buffer.from(
  'aaditech/phase1dd/minimal-readonly-operator-handoff/v1\n'+
  canonical({repository:REPO,head,base,
   technical:technical&&stable,rows:statusRows.map(x=>({
    gate:x.gate,signal:x.technicalSignal
   }))}),'utf8'));
 return Object.freeze({
  phase:'1DD',schemaVersion:1,
  kind:'REAL_HUMAN_GITHUB_AND_EXTERNAL_AUTHORITY_HANDOFF_PERMANENT_HOLD',
  repository:REPO,currentDevelopmentHeadSha:head,
  currentMainBaseSha:base,
  precedingLiveGithubSnapshotStructurallyAccepted:stable&&counts&&reported,
  githubTechnicallyObservedOnly:technical&&stable,
  submittedHumanEvidenceMetadataLocallyWellFormedOnly:
   metadataResult.locallyValid,
  candidateMetadataReferenceCount:metadataResult.count,
  independentCorporateOrProviderEvidenceVerified:false,
  authorityIntakeComplete:false,
  acceptedLatestHeadIndependentReviewerMandates:false,
  externallyDurableWormCasOrCaTrustVerified:false,
  handoffIntegrityDigestSha256:receiptDigest,
  outstandingActions:Object.freeze(statusRows),
  anomalyCodes:Object.freeze([...anomalies].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function boundedFile(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('DD_OPERATOR_PATH_NOT_ACCEPTED');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>65536)
  throw Error('DD_CANDIDATE_METADATA_NOT_REGULAR_BOUNDED_OFFREPO_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||
    ![1,2].includes(args.length)||
    args[0]!=='--inspect-authorized-handoff')
  throw Error('DD_ONLY_EXPLICIT_HUMAN_READONLY_GITHUB_OPERATOR_HANDOFF');
 const governance=await collectLiveActualGovernance({
  token:process.env.GITHUB_READ_TOKEN??''
 });
 const metadata=args.length===2?boundedFile(args[1]):null;
 const report=assessIndependentOperatorHandoff({
  governance,metadata,now:new Date().toISOString()
 });
 console.log(JSON.stringify(report,null,2));
 if(!report.precedingLiveGithubSnapshotStructurallyAccepted)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('DD external human authority still unverified:',
   e instanceof Error?e.message:'Unknown');process.exitCode=1;
 });
