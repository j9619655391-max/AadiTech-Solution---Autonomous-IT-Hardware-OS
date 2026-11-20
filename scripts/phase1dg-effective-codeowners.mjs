import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {TextDecoder} from 'node:util';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1DG: read-only, exact-main-commit GitHub CODEOWNERS validation.
// Technical source checks NEVER grant corporate reviewer authority or release.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const CODEOWNERS_PRECEDENCE=Object.freeze([
 '.github/CODEOWNERS','CODEOWNERS','docs/CODEOWNERS'
]);
const KNOWN_PATTERNS=new Set([
 '*','/.github/CODEOWNERS','/.github/workflows/',
 '/docs/security/','/server/security/','/scripts/','/tests/'
]);
const SHA=/^[0-9a-f]{40}$/;
const LOGIN=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const author='j9619655391-max';
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const validLogin=x=>typeof x==='string'&&LOGIN.test(x)&&
 x.toLowerCase()!==author;
const held=x=>x?.productionReleaseAuthorized===false&&
 x?.productionReleaseBlocked===true&&x?.releaseDecision==='HOLD';

function decodeOwners(payload,path,securityLogin,businessLogin){
 if(!own(payload)||payload.type!=='file'||payload.path!==path||
  payload.encoding!=='base64'||!SHA.test(payload.sha??'')||
  !Number.isSafeInteger(payload.size)||payload.size<1||payload.size>65536||
  typeof payload.content!=='string'||payload.content.length>90000)
  return null;
 const encoded=payload.content.replace(/\s/g,'');
 if(!encoded||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
  return null;
 const bytes=Buffer.from(encoded,'base64');
 if(bytes.length!==payload.size||bytes.toString('base64')!==encoded)return null;
 const gitSha=createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0'))
  .update(bytes).digest('hex');
 if(gitSha!==payload.sha)return null;
 let content;
 try{content=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}
 catch{return null;}
 if(!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(content)||content.includes('\r')&&
    !/^([^\r]|\r\n)*$/.test(content))return null;
 const seen=new Set();let wildcard=false,rows=0;
 const want=[securityLogin.toLowerCase(),businessLogin.toLowerCase()].sort();
 for(const line of content.split(/\r?\n/)){
  const trimmed=line.trim();
  if(!trimmed||trimmed.startsWith('#'))continue;
  const fields=trimmed.split(/[\t ]+/);
  if(fields.length!==3||!KNOWN_PATTERNS.has(fields[0])||
     seen.has(fields[0])||!fields[1].startsWith('@')||
     !fields[2].startsWith('@'))return null;
  const ownerLogins=fields.slice(1).map(s=>s.slice(1));
  if(!ownerLogins.every(s=>validLogin(s))||
     ownerLogins[0].toLowerCase()===ownerLogins[1].toLowerCase()||
     JSON.stringify(ownerLogins.map(s=>s.toLowerCase()).sort())!==JSON.stringify(want))
   return null;
  seen.add(fields[0]);wildcard||=fields[0]==='*';rows++;
 }
 if(!wildcard||rows<1)return null;
 return {gitBlobSha:gitSha,patternCount:rows,allRulesSameTwoNominees:true};
}

// The only allowed read is one approved CODEOWNERS path on exact pinned main SHA.
// No network use in tests; operator supplies authorized read-only token at run time.
export async function readPinnedMainCodeowners(path,mainSha,token,fetchImpl=fetch){
 if(!CODEOWNERS_PRECEDENCE.includes(path)||!SHA.test(mainSha??''))
  throw Error('DG_REJECT_UNPINNED_MAIN_OR_UNAPPROVED_PATH');
 if(typeof token!=='string'||token.length<1||token.length>4096)
  return {status:'unavailable',data:null};
 const url='https://api.github.com/repos/'+REPO+'/contents/'+path+'?ref='+mainSha;
 const ctl=new AbortController(),timer=setTimeout(()=>ctl.abort(),6500);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:ctl.signal,
   headers:{Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1DG-PinnedCodeowners-ReadOnly-HOLD'}
  });
  if(response.status!==200)return {status:response.status===404?
   'absent_or_hidden':[401,403].includes(response.status)?
   'access_denied':'unavailable',data:null};
  if(response.redirected||response.url!==url||
     !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      response.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null};
  const length=response.headers?.get?.('content-length');
  if(length!==null&&length!==undefined&&
     (!/^\d+$/.test(length)||Number(length)>131072))
   return {status:'invalid',data:null};
  if(!response.body?.getReader)return {status:'invalid',data:null};
  let n=0;const chunks=[];const reader=response.body.getReader();
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array)||n+value.length>131072)
    return {status:'invalid',data:null};
   n+=value.length;chunks.push(Buffer.from(value));
  }
  const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  return own(data)?{status:'read',data}:{status:'invalid',data:null};
 }catch{return {status:'unavailable',data:null};}
 finally{clearTimeout(timer);}
}

export function assessPinnedMainCodeowners({
 roleJoin=null,securityLogin=null,businessLogin=null,
 observedFirst=null,observedSecond=null
}={}){
 const anomaly=new Set();
 const nominees=validLogin(securityLogin)&&validLogin(businessLogin)&&
  securityLogin.toLowerCase()!==businessLogin.toLowerCase();
 if(!nominees)anomaly.add('DG_DISTINCT_AUTHORIZED_NONAUTHOR_NOMINEES_REQUIRED');
 const joined=roleJoin?.phase==='1DF'&&roleJoin?.schemaVersion===1&&
  roleJoin?.repository===REPO&&held(roleJoin)&&
  roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly===true&&
  roleJoin.exactSourceAndMainStableAcrossOfficialReadsOnly===true&&
  roleJoin.effectiveBaseMainGovernanceReadableOnly===true&&
  SHA.test(roleJoin.currentDevelopmentHeadSha??'')&&
  SHA.test(roleJoin.currentMainBaseSha??'');
 if(!joined)anomaly.add('DG_INDEPENDENT_ROLE_SPECIFIC_TECHNICAL_JOIN_NOT_OBSERVED');
 const run=snapshot=>{
  if(!own(snapshot)||CODEOWNERS_PRECEDENCE.some(p=>
     !own(snapshot[p])||!['read','absent_or_hidden','access_denied','unavailable','invalid']
      .includes(snapshot[p].status)))return null;
  if(CODEOWNERS_PRECEDENCE.some(p=>!['read','absent_or_hidden'].includes(
     snapshot[p].status)))return null;
  const path=CODEOWNERS_PRECEDENCE.find(p=>snapshot[p].status==='read');
  if(!path)return {path:null,gitBlobSha:null,patternCount:0,missing:true};
  if(snapshot[path].status!=='read')return null;
  const parsed=nominees?decodeOwners(snapshot[path].data,path,
   securityLogin,businessLogin):null;
  return parsed?{path,...parsed,missing:false}:null;
 };
 const first=run(observedFirst),second=run(observedSecond);
 if(!first||!second)anomaly.add('DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
 if(first?.missing||second?.missing)
  anomaly.add('DG_NO_BASE_MAIN_CODEOWNERS_INSTALLED');
 const continuous=Boolean(first&&second&&!first.missing&&!second.missing&&
  first.path===second.path&&first.gitBlobSha===second.gitBlobSha&&
  first.patternCount===second.patternCount);
 if(!continuous)anomaly.add('DG_PINNED_CODEOWNERS_MISMATCH_OR_REPLACEMENT');
 const usable=joined&&nominees&&continuous;
 return Object.freeze({
  phase:'1DG',schemaVersion:1,repository:REPO,
  kind:'EXACT_BASE_MAIN_CODEOWNERS_PRECEDENCE_NOMINEE_MATCH_READONLY_HOLD',
  pinnedBaseMainSha:joined?roleJoin.currentMainBaseSha:null,
  currentDevelopmentHeadSha:joined?roleJoin.currentDevelopmentHeadSha:null,
  effectiveCodeownersPath:usable?first.path:null,
  effectiveGitBlobSha:usable?first.gitBlobSha:null,
  effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly:usable,
  exactTwoNominatedAccountsInEachAcceptedRuleOnly:usable,
  githubCodeownersAloneCannotEnforceTwoDistinctRoleApprovals:true,
  reviewerLoginsAndTokenExcludedFromOutput:true,
  independentlyAuthenticatedCorporateSecurityBusinessMandates:false,
  effectiveMainRulesetOrAdminNonbypassApproved:false,
  providerCaMcaWormDrOidcAndStagingAccepted:false,
  canModifyMainRequestReviewsMergeOrDeploy:false,
  anomalyCodes:Object.freeze([...anomaly].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}

async function main(){
 const args=process.argv.slice(2),token=process.env.GITHUB_READ_TOKEN??'';
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==3||
    args[0]!=='--inspect-pinned-main-codeowners-readonly'||
    !validLogin(args[1])||!validLogin(args[2])||
    args[1].toLowerCase()===args[2].toLowerCase()||
    token.length<1||token.length>4096)
  throw Error('DG_AUTHORIZED_OPERATOR_ONLY_WITH_DISTINCT_REAL_NOMINEES');
 const [securityLogin,businessLogin]=args.slice(1);
 const {collectLiveActualGovernance}=await import('./phase1dc-live-external-governance-readiness.mjs');
 const {collectLiveReviewerEvidence}=await import('./phase1co-live-exact-head-reviewer-quorum.mjs');
 const {assessRoleBoundReadOnlyReconciliation}=await import('./phase1df-role-bound-readonly-reconciliation.mjs');
 const governanceBefore=await collectLiveActualGovernance({token});
 const roleQuorumFirst=await collectLiveReviewerEvidence({token,securityLogin,businessLogin});
 const roleQuorumSecond=await collectLiveReviewerEvidence({token,securityLogin,businessLogin});
 const governanceAfter=await collectLiveActualGovernance({token});
 const roleJoin=assessRoleBoundReadOnlyReconciliation({governanceBefore,
  roleQuorumFirst,roleQuorumSecond,governanceAfter});
 const mainSha=roleJoin.currentMainBaseSha;
 if(!SHA.test(mainSha??''))throw Error('DG_MAIN_REF_NOT_STABLY_PINNED');
 const take=async()=>Object.fromEntries(await Promise.all(
  CODEOWNERS_PRECEDENCE.map(async path=>[path,
   await readPinnedMainCodeowners(path,mainSha,token)])));
 const observedFirst=await take(),observedSecond=await take();
 const outcome=assessPinnedMainCodeowners({roleJoin,securityLogin,businessLogin,
  observedFirst,observedSecond});
 // Phase 1DI: CLOSE the stale-read window AFTER pinned owner files, not
 // before. Bracket a third exact-role review with fresh full policy/main
 // readbacks; refuse races including same-count policy content swaps.
 const {assessTerminalReadOnlyMainAndReviewRecheck}=await import(
  './phase1di-terminal-main-review-recheck.mjs');
 const terminalGovernanceBefore=await collectLiveActualGovernance({token});
 const terminalNominatedReview=await collectLiveReviewerEvidence({
  token,securityLogin,businessLogin
 });
 const terminalGovernanceAfter=await collectLiveActualGovernance({token});
 const terminal=assessTerminalReadOnlyMainAndReviewRecheck({
  roleJoin,pinnedOwners:outcome,
  initialGovernanceBefore:governanceBefore,
  initialGovernanceAfter:governanceAfter,
  terminalGovernanceBefore,terminalNominatedReview,terminalGovernanceAfter
 });
 // No logins, token, raw policy content, official responses or credentials.
 console.log(JSON.stringify({codeowners:outcome,terminal},null,2));
 if(!outcome.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly||
    !terminal.wholeOperatorReadWindowTechnicallyConsistentOnly)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(()=>{
  console.error('DG_PINNED_MAIN_CODEOWNERS_AUTHORITY_HARD_HOLD');
  process.exitCode=1;
 });
