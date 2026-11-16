import {phase1AzAssessReadiness} from './lib/phase1AzExternalReadiness.mjs';

// No provider agreement, credentials, witness key, archive object, company
// details, private documents or DR restoration are read in this CI-only mode.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('Unsupported Phase 1AZ evidence processing mode');
 const result=phase1AzAssessReadiness();
 if(result.productionReleaseAuthorized!==false||
    result.productionReleaseBlocked!==true||result.releaseDecision!=='HOLD')
  throw Error('Phase 1AZ release gate violated');
 process.stdout.write(JSON.stringify({
  phase:'1AZ',source:'ZERO_INPUT_CI_SYNTHETIC_READINESS_ONLY',
  ...result,providerAgreementAuthenticated:false,
  witnessOrganizationsAuthenticated:false,
  immutableExternalRetentionVerified:false,
  encryptedDisasterRecoveryWitnessed:false,
  approvedStagingRestore:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1AZ HOLD: unavailable authorization; supplied input withheld.\n');
 process.exitCode=2;
}
