import {execFileSync} from 'node:child_process';
import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1BY: independent *local Git object ancestry* corroboration of a PR
// test-merge checkout. This is NOT GitHub ruleset, reviewer, signer or WORM
// authentication and it never grants production release permission.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const SOURCE='chore/phase0-foundation-20261106';
const SHA=/^[a-f0-9]{40}$/;
const exact=(a,b)=>typeof a==='string'&&a===b;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export function parseGitCommitParents(raw){
 if(typeof raw!=='string'||raw.length>65536)
  throw Error('BY source commit object absent/oversized');
 const header=raw.split(/\r?\n\r?\n/,1)[0];
 const lines=header.split('\n');
 const trees=lines.filter(x=>/^tree /.test(x));
 const parentLines=lines.filter(x=>/^parent /.test(x));
 if(trees.length!==1||!/^tree [a-f0-9]{40}$/.test(trees[0])||
    parentLines.some(line=>!/^parent [a-f0-9]{40}$/.test(line)))
  throw Error('BY commit header malformed');
 return Object.freeze({
  treeSha:trees[0].slice(5),
  parentShas:Object.freeze(parentLines.map(x=>x.slice(7))),
  parentCount:parentLines.length
 });
}
export function assessGithubPrTestMergeLineage({
 environment={},event,checkedOutSha,commitObject
}={}){
 const anomalyCodes=new Set();
 const push=typeof environment.GITHUB_EVENT_NAME==='string'?
   environment.GITHUB_EVENT_NAME:'unknown';
 const pr=event?.pull_request;
 const actualRepo=event?.repository?.full_name;
 const sourceSha=pr?.head?.sha;
 const baseSha=pr?.base?.sha;
 const mergeSha=pr?.merge_commit_sha;
 if(environment.GITHUB_REPOSITORY!==REPO||actualRepo!==REPO||
    environment.GITHUB_EVENT_NAME!=='pull_request'||
    environment.GITHUB_REF!=='refs/pull/1/merge'||
    environment.GITHUB_HEAD_REF!==SOURCE||
    environment.GITHUB_BASE_REF!=='main'||
    event?.number!==1||pr?.number!==1||pr?.state!=='open'||
    pr?.draft!==true||pr?.merged===true||
    pr?.user?.login!=='j9619655391-max'||
    pr?.head?.ref!==SOURCE||pr?.base?.ref!=='main'||
    pr?.head?.repo?.full_name!==REPO||pr?.base?.repo?.full_name!==REPO)
  anomalyCodes.add('BY_UNEXPECTED_PR_REPOSITORY_EVENT_OR_AUTHOR');
 if(!SHA.test(checkedOutSha??'')||!SHA.test(environment.GITHUB_SHA??'')||
    !SHA.test(sourceSha??'')||!SHA.test(baseSha??'')||
    !SHA.test(mergeSha??''))
  anomalyCodes.add('BY_INVALID_SOURCE_BASE_OR_MERGE_SHA');
 if(!exact(checkedOutSha,environment.GITHUB_SHA)||
    !exact(checkedOutSha,mergeSha))
  anomalyCodes.add('BY_CI_CHECKOUT_NOT_PR_TEST_MERGE');
 let parents=null,treeSha=null;
 try{
  const parsed=parseGitCommitParents(commitObject);
  parents=parsed.parentShas;
  treeSha=parsed.treeSha;
  if(parsed.parentCount!==2||
     parsed.parentShas[0]!==baseSha||
     parsed.parentShas[1]!==sourceSha||
     baseSha===sourceSha)
   anomalyCodes.add('BY_GIT_MERGE_PARENTS_NOT_PR_BASE_AND_HEAD');
 }catch{
  anomalyCodes.add('BY_MISSING_OR_INVALID_GIT_COMMIT_OBJECT');
 }
 return Object.freeze({
  schemaVersion:1,phase:'1BY',kind:'PR_TEST_MERGE_PARENT_LINEAGE_HOLD',
  localSourceGraphCorroborated:anomalyCodes.size===0,
  anomalyCodes:Object.freeze([...anomalyCodes].sort()),
  githubRunEvent:push,
  observedCheckoutSha:SHA.test(checkedOutSha??'')?checkedOutSha:null,
  observedSourceHeadSha:SHA.test(sourceSha??'')?sourceSha:null,
  observedBaseSha:SHA.test(baseSha??'')?baseSha:null,
  observedMergeParents:parents,
  observedTreeSha:treeSha,
  githubReviewRolesAuthenticated:false,
  branchProtectionServerSideVerified:false,
  signedCIExternalIdentityVerified:false,
  externalWormRetentionVerified:false,
  independentSecurityApprovalVerified:false,
  upstreamPicomatchFixVerified:false,
  zeroHighDependencyGatePassed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('BY lineage checker supports only --ci-hold');
 const eventPath=process.env.GITHUB_EVENT_PATH;
 if(!eventPath||typeof eventPath!=='string'||eventPath.length>1024)
  throw Error('BY GitHub event payload missing');
 const info=lstatSync(eventPath);
 if(!info.isFile()||info.isSymbolicLink()||info.size>262144)
  throw Error('BY GitHub event payload unsafe type/size');
 const event=JSON.parse(readFileSync(eventPath,'utf8'));
 // No shell or URLs, ever; the raw parent headers in the shallow Git object
 // still identify the merged source and base even without downloading parents.
 const sha=execFileSync('git',['rev-parse','HEAD'],{
  encoding:'utf8',timeout:5000,maxBuffer:4096}).trim();
 if(!SHA.test(sha))throw Error('BY git checkout SHA malformed');
 const commitObject=execFileSync('git',['cat-file','-p',sha],{
  encoding:'utf8',timeout:5000,maxBuffer:65536});
 const report=assessGithubPrTestMergeLineage({
  environment:process.env,event,checkedOutSha:sha,commitObject
 });
 writeFileSync('phase1by-pr-merge-lineage-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 // This job checks actual Git parentage, but never promotes to GO.
 if(!report.localSourceGraphCorroborated||
    report.productionReleaseAuthorized||report.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Phase 1BY Git source-parent lineage fail-closed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
