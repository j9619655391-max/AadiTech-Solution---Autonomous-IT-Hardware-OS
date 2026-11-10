import 'dotenv/config';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {assessReleaseCandidate,type CandidateSecurityAudit} from './lib/releaseCandidate';

function main(){
 const env=process.env;
 if(env.RELEASE_CANDIDATE_CI!=='1'||env.GITHUB_ACTIONS!=='true'||
    env.GITHUB_REPOSITORY!=='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS')
  throw Error('Held release candidate inventory requires the approved repository GitHub CI runner');
 const sourceRef=env.GITHUB_EVENT_NAME==='pull_request'?env.GITHUB_HEAD_REF:
  env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF?.startsWith('refs/heads/')?
   env.GITHUB_REF.slice('refs/heads/'.length):'';
 if(sourceRef!=='chore/phase0-foundation-20261106')
  throw Error('Candidate inventory not permitted outside Draft PR development branch');
 const gitSha=execFileSync('git',['rev-parse','HEAD'],{
  encoding:'utf8',timeout:5000,stdio:['ignore','pipe','ignore']
 }).trim();
 if(gitSha!==env.GITHUB_SHA)throw Error('GitHub job SHA does not match checked-out commit');
 const baseline=JSON.parse(readFileSync('dependency-baseline-status.json','utf8'));
 const triage=JSON.parse(readFileSync('dependency-triage.json','utf8'));
 const report=assessReleaseCandidate({
  sourceSha:gitSha,sourceRef,root:process.cwd(),
  audit:{baseline,triage} as CandidateSecurityAudit,
  generatedAt:new Date().toISOString()
 });
 // This is a provenance inventory of build *hashes*. It is NOT a signed
 // release bundle, staging acceptance, an attestation or deployment approval.
 writeFileSync('release-candidate-manifest.json',JSON.stringify(report,null,2)+'\n',
  {mode:0o600,flag:'w'});
 console.log(JSON.stringify({
  developmentInventoryRecorded:true,sourceRef,
  gitCommitSha:report.gitCommitSha,
  artifactSetSha256:report.artifactSetSha256,
  fileCount:report.fileCount,
  productionReleaseAuthorized:false,
  releaseDecision:report.releaseDecision
 },null,2));
}
try{main();}
catch(e){
 console.error('Held release-candidate inventory refused:',
  e instanceof Error?e.message:'Unknown');
 process.exitCode=1;
}
