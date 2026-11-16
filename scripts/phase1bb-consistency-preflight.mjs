import {assessPhase1BbWitnessConsistency} from './lib/phase1BbWitnessConsistency.mjs';

// No inputs or network: do not allow a self-provided witness receipt or
// unpublished proof to replace genuine, authenticated source-of-truth trust.
try{
 const argv=process.argv.slice(2);
 if(argv.length!==1||argv[0]!=='--ci-hold')
  throw Error('Unsupported Phase 1BB consistency preflight arguments');
 const verdict=assessPhase1BbWitnessConsistency();
 if(verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||verdict.releaseDecision!=='HOLD'||
    verdict.internalAppendOnlyConsistent!==false)
  throw Error('Unverified witness cannot authorize release');
 process.stdout.write(JSON.stringify({
  ...verdict,externalLogHeadSourceAuthenticated:false,
  outOfBandWitnessPinAuthentication:false,
  genuineAppendOnlyPublisherAudited:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BB HOLD: unauthorized signed-head proof or release input withheld.\n');
 process.exitCode=2;
}
