import test from 'node:test';
import assert from 'node:assert/strict';
import {assessGithubPrTestMergeLineage,parseGitCommitParents}
 from '../scripts/phase1by-pr-merge-lineage.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
const BASE='a'.repeat(40),HEAD='b'.repeat(40),MERGE='c'.repeat(40);
const TREE='d'.repeat(40);
const COMMIT=['tree '+TREE,'parent '+BASE,'parent '+HEAD,
 'author CI <ci@example.invalid> 0 +0000',
 'committer CI <ci@example.invalid> 0 +0000','','Merge HEAD into main',''].join('\n');
function fixture(){
 return {
  checkedOutSha:MERGE,commitObject:COMMIT,
  environment:{
   GITHUB_REPOSITORY:REPO,GITHUB_EVENT_NAME:'pull_request',
   GITHUB_REF:'refs/pull/1/merge',GITHUB_HEAD_REF:DEV,
   GITHUB_BASE_REF:'main',GITHUB_SHA:MERGE
  },
  event:{
   number:1,repository:{full_name:REPO},
   pull_request:{
    number:1,state:'open',draft:true,merged:false,
    merge_commit_sha:MERGE,user:{login:'j9619655391-max'},
    head:{sha:HEAD,ref:DEV,repo:{full_name:REPO}},
    base:{sha:BASE,ref:'main',repo:{full_name:REPO}}
   }
  }
 };
}
const check=change=>{
 const data=fixture();change?.(data);
 return assessGithubPrTestMergeLineage(data);
};
test('BY local Git parents exactly corroborate GH PR head/base/test-merge, never external authorization',()=>{
 const r=check();
 assert.equal(r.localSourceGraphCorroborated,true,r.anomalyCodes.join(','));
 assert.deepEqual(r.observedMergeParents,[BASE,HEAD]);
 assert.equal(r.observedCheckoutSha,MERGE);
 assert.equal(r.observedBaseSha,BASE);
 assert.equal(r.observedSourceHeadSha,HEAD);
 assert.equal(r.branchProtectionServerSideVerified,false);
 assert.equal(r.githubReviewRolesAuthenticated,false);
 assert.equal(r.signedCIExternalIdentityVerified,false);
 assert.equal(r.externalWormRetentionVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BY attacker swaps first or second parent or reorders merge parents: fail closed',()=>{
 for(const commit of [
  COMMIT.replace('parent '+BASE,'parent '+'f'.repeat(40)),
  COMMIT.replace('parent '+HEAD,'parent '+'e'.repeat(40)),
  COMMIT.replace('parent '+BASE+'\nparent '+HEAD,'parent '+HEAD+'\nparent '+BASE),
  COMMIT.replace('parent '+HEAD,'parent '+BASE),
  COMMIT.replace('parent '+HEAD,''),
  COMMIT.replace('parent '+HEAD,'parent '+HEAD+'\nparent '+HEAD)
 ]){
  const r=check(x=>x.commitObject=commit);
  assert.ok(r.anomalyCodes.includes('BY_GIT_MERGE_PARENTS_NOT_PR_BASE_AND_HEAD'),
   r.anomalyCodes.join(','));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BY changed checkout, event SHA and synthetic PR merge SHA cannot be laundered',()=>{
 for(const mutation of [
  f=>f.checkedOutSha='e'.repeat(40),
  f=>f.environment.GITHUB_SHA='e'.repeat(40),
  f=>f.event.pull_request.merge_commit_sha='e'.repeat(40),
  f=>f.event.pull_request.head.sha='e'.repeat(40),
  f=>f.event.pull_request.base.sha='e'.repeat(40)
 ]){
  const r=check(mutation);
  assert.equal(r.localSourceGraphCorroborated,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BY source repo, branch, event, PR number, author, draft or merged changes refuse',()=>{
 for(const mutation of [
  f=>f.environment.GITHUB_REPOSITORY='attacker/repo',
  f=>f.environment.GITHUB_EVENT_NAME='workflow_dispatch',
  f=>f.environment.GITHUB_REF='refs/heads/main',
  f=>f.environment.GITHUB_HEAD_REF='attacker-branch',
  f=>f.environment.GITHUB_BASE_REF='not-main',
  f=>f.event.repository.full_name='attacker/repo',
  f=>f.event.number=2,
  f=>f.event.pull_request.number=2,
  f=>f.event.pull_request.user.login='attacker',
  f=>f.event.pull_request.draft=false,
  f=>f.event.pull_request.merged=true,
  f=>f.event.pull_request.state='closed',
  f=>f.event.pull_request.head.ref='attacker',
  f=>f.event.pull_request.base.ref='other',
  f=>f.event.pull_request.head.repo.full_name='attacker/repo',
  f=>f.event.pull_request.base.repo.full_name='attacker/repo'
 ]){
  const r=check(mutation);
  assert.ok(r.anomalyCodes.includes('BY_UNEXPECTED_PR_REPOSITORY_EVENT_OR_AUTHOR'),
   r.anomalyCodes.join(','));
 }
});
test('BY malformed Git commit raw header and missing or invalid hashes cannot pass',()=>{
 for(const raw of [
  '', 'fake', 'tree '+TREE+'\n\nmessage\n',
  'tree '+'g'.repeat(40)+'\nparent '+BASE+'\nparent '+HEAD+'\n',
  'tree '+TREE+'\ntree '+TREE+'\nparent '+BASE+'\nparent '+HEAD+'\n',
  'tree '+TREE+'\nparent '+BASE+'\nparent '+'x'.repeat(40)+'\n',
  'x'.repeat(65537)
 ]){
  const r=check(f=>f.commitObject=raw);
  assert.ok(r.anomalyCodes.includes('BY_MISSING_OR_INVALID_GIT_COMMIT_OBJECT')||
   r.anomalyCodes.includes('BY_GIT_MERGE_PARENTS_NOT_PR_BASE_AND_HEAD'));
  assert.equal(r.localSourceGraphCorroborated,false);
 }
});
test('BY commit message cannot impersonate parent headers after blank separator',()=>{
 const raw='tree '+TREE+'\nparent '+BASE+'\nparent '+HEAD+
  '\nauthor A <a@example.invalid> 0 +0000\n\nparent '+'e'.repeat(40);
 const r=check(f=>f.commitObject=raw);
 assert.equal(r.localSourceGraphCorroborated,true);
 assert.equal(r.observedMergeParents.length,2);
});
test('BY invalid target SHA rejects even syntactically valid parent source',()=>{
 for(const change of [
  f=>f.environment.GITHUB_SHA='bad',
  f=>f.checkedOutSha='bad',
  f=>f.event.pull_request.head.sha='bad',
  f=>f.event.pull_request.base.sha='bad',
  f=>f.event.pull_request.merge_commit_sha='bad'
 ]){
  const r=check(change);
  assert.ok(r.anomalyCodes.includes('BY_INVALID_SOURCE_BASE_OR_MERGE_SHA'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BY parser gives exact parent order and tree without needing shallow parent objects',()=>{
 const info=parseGitCommitParents(COMMIT);
 assert.equal(info.treeSha,TREE);
 assert.equal(info.parentCount,2);
 assert.deepEqual(info.parentShas,[BASE,HEAD]);
 assert.equal(Object.isFrozen(info.parentShas),true);
 assert.throws(()=>parseGitCommitParents({}),/absent/);
 assert.throws(()=>parseGitCommitParents('tree '+TREE+'\nparent abc\n'),/malformed/);
});
test('BY even valid local Git SHA lineage cannot authorize WORM/reviewer/GitHub protection',()=>{
 const r=check();
 assert.equal(r.localSourceGraphCorroborated,true);
 assert.equal(r.githubReviewRolesAuthenticated,false);
 assert.equal(r.branchProtectionServerSideVerified,false);
 assert.equal(r.signedCIExternalIdentityVerified,false);
 assert.equal(r.externalWormRetentionVerified,false);
 assert.equal(r.independentSecurityApprovalVerified,false);
 assert.equal(r.zeroHighDependencyGatePassed,false);
 assert.equal(r.releaseDecision,'HOLD');
});
