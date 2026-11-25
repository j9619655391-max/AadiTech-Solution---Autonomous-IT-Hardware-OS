import {assessPhase1BcWitnessCustody} from './lib/phase1BcWitnessCustody.mjs';

// No credentials, private material, external network, source-of-truth
// enrollment, provider access or user-provided evidence allowed in CI.
try{
 const argv=process.argv.slice(2);
 if(argv.length!==1||argv[0]!=='--ci-hold')
  throw Error('Phase 1BC unauthorized source-enrollment argument');
 const verdict=assessPhase1BcWitnessCustody();
 if(verdict.productionReleaseAuthorized!==false||
   verdict.productionReleaseBlocked!==true||verdict.releaseDecision!=='HOLD'||
   verdict.claimCryptographicallyConsistent!==false)
  throw Error('Phase 1BC release invariant violation');
 process.stdout.write(JSON.stringify({
  ...verdict,source:'ZERO_INPUT_CI_ONLY',
  independentPublishedHeadVerified:false,
  externalWitnessKeyCustodyAuthenticated:false,
  providerContractAndCrlOcspVerified:false,
  genuineWormDeletionDenied:false,
  encryptedDisasterRecoveryWitnessed:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BC HARD HOLD: unauthorized external witness or release input refused.\n');
 process.exitCode=2;
}
