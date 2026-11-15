import {assessStagingAcceptance} from './lib/stagingAcceptance';
import {verifyStagingEvidenceFiles} from './lib/stagingEvidenceIntegrity';
import {readPrivateStagingReviewInputs} from './lib/privateStagingReviewInputs';

// No dotenv auto-loading: operator authorization must be explicit in the
// invoking process. The checker never sends messages or authorizes a release.
const args=process.argv.slice(2);
try{
 if(args.length===1&&args[0]==='--ci-hold'){
  process.stdout.write(JSON.stringify({
   phase:'1AT',privateEvidenceInspected:false,submittedEvidenceComplete:false,
   integrityChecksPassed:false,signerIdentityExternallyVerified:false,
   independentlyWitnessedRestoreVerified:false,providerInfrastructureVerified:false,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'
  },null,2)+'\n');
 }else{
  if(args.length!==3||process.env.STAGING_ACCEPTANCE_REVIEW!=='YES'||
     process.env.STAGING_PRIVATE_JSON_REVIEW_APPROVED!=='YES'||
     process.env.CI==='true'||process.env.GITHUB_ACTIONS==='true'||
     process.env.NODE_ENV==='production')
   throw Error('Private staging evidence review is not approved');
  const [acceptancePath,manifestPath,root]=args;
  const {acceptance,manifest}=readPrivateStagingReviewInputs(acceptancePath,manifestPath);
  const review=assessStagingAcceptance(acceptance);
  const integrity=verifyStagingEvidenceFiles(manifest,root,{
   changeTicket:acceptance.changeTicket,stagingOrigin:acceptance.stagingOrigin
  });
  // No private JSON, file paths, individual hashes, certificates or signer
  // identifiers are printed. Synthetic completeness cannot grant approval.
  process.stdout.write(JSON.stringify({
   phase:'1AT',privateEvidenceInspected:true,
   submittedEvidenceComplete:review.submittedEvidenceComplete,
   integrityChecksPassed:integrity.integrityChecksPassed,
   checkedEvidenceFileCount:integrity.checkedEvidenceFileCount,
   reviewIssues:review.issues,integrityProblems:integrity.problems,
   rtoMinutes:review.restoreRtoMinutes,rpoMinutes:review.restoreRpoMinutes,
   signerIdentityExternallyVerified:false,
   independentlyWitnessedRestoreVerified:false,
   providerInfrastructureVerified:false,productionReleaseAuthorized:false,
   releaseDecision:'HOLD'
  },null,2)+'\n');
  // A validated local evidence inventory is still not signed/reviewed live
  // acceptance. Nonzero exit ensures no shell pipeline treats it as release GO.
  process.exitCode=2;
 }
}catch{
 process.stderr.write(
  'Phase 1AT HOLD: unauthorized, invalid or unsafe staging input; private details withheld.\n'
 );
 process.exitCode=2;
}
