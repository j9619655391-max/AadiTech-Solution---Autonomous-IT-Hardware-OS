import 'dotenv/config';
import {readFileSync} from 'node:fs';
import {assessStagingAcceptance,type StagingAcceptancePackage} from './lib/stagingAcceptance';
import {verifyStagingEvidenceFiles,type StagingEvidenceManifest} from './lib/stagingEvidenceIntegrity';

if(process.env.STAGING_ACCEPTANCE_REVIEW!=='YES'){
 console.error('Review is disabled without STAGING_ACCEPTANCE_REVIEW=YES');
 process.exitCode=1;
}else{
 try{
  const [acceptancePath,manifestPath,root]=process.argv.slice(2);
  if(!acceptancePath||!manifestPath||!root||process.argv.length!==5)
   throw Error('Requires private acceptance JSON, matching manifest JSON and private evidence root');
  const input=JSON.parse(readFileSync(acceptancePath,'utf8')) as StagingAcceptancePackage;
  const manifest=JSON.parse(readFileSync(manifestPath,'utf8')) as StagingEvidenceManifest;
  const review=assessStagingAcceptance(input);
  const integrity=verifyStagingEvidenceFiles(manifest,root,{
   changeTicket:input.changeTicket,stagingOrigin:input.stagingOrigin
  });
  // Never print private evidence input, file names, contents, signatures or
  // source paths. Hash verification is not signature or fact verification.
  console.log(JSON.stringify({
   submittedEvidenceComplete:review.submittedEvidenceComplete,
   integrityChecksPassed:integrity.integrityChecksPassed,
   checkedEvidenceFileCount:integrity.checkedEvidenceFileCount,
   reviewIssues:review.issues,
   integrityProblems:integrity.problems,
   rtoMinutes:review.restoreRtoMinutes,
   rpoMinutes:review.restoreRpoMinutes,
   independentlyWitnessedRestoreVerified:false,
   providerInfrastructureVerified:false,
   productionReleaseAuthorized:false
  },null,2));
  if(!review.submittedEvidenceComplete||!integrity.integrityChecksPassed)
   process.exitCode=1;
 }catch(e){
  console.error('Staging acceptance evidence review refused:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
