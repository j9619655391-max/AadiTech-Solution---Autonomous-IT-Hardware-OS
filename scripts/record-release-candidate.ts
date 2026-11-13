import 'dotenv/config';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {assessReleaseCandidate,validateCandidatePushContext,type CandidateSecurityAudit} from './lib/releaseCandidate';

function main(){
 const env=process.env;
 // Reject local, fork, PR-merge and other-branch invocations before reading artifacts.
 if(env.RELEASE_CANDIDATE_CI!=='1'||env.GITHUB_ACTIONS!=='true')
  throw Error('Candidate inventory is GitHub Actions opt-in only');
 const gitSha=execFileSync('git',['rev-parse','HEAD'],{
  encoding:'utf8',timeout:5000,stdio:['ignore','pipe','ignore']
 }).trim();
 const {sourceSha,sourceRef}=validateCandidatePushContext(env,gitSha);
 const baseline=JSON.parse(readFileSync('dependency-baseline-status.json','utf8'));
 const triage=JSON.parse(readFileSync('dependency-triage.json','utf8'));
 const report=assessReleaseCandidate({
  sourceSha,sourceRef,root:process.cwd(),
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
