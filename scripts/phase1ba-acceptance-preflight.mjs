import {assessPhase1BaExternalAcceptance} from './lib/phase1BaAcceptanceEvidence.mjs';

// Phase 1BA intentionally refuses evidence paths, network endpoints, tokens,
// private keys, signed contracts and runtime activation in GitHub Actions.
try {
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('No external authentication has been authorized');
 const hold=assessPhase1BaExternalAcceptance();
 if(hold.productionReleaseAuthorized!==false||
    hold.productionReleaseBlocked!==true||hold.releaseDecision!=='HOLD')
  throw Error('Phase 1BA release invariant was violated');
 process.stdout.write(JSON.stringify({
  ...hold,providerAuthorizationVerified:false,
  independentWitnessAdministrationVerified:false,
  realObjectLockDeletionDenialVerified:false,
  independentlyWitnessedEncryptedRestore:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BA HOLD: unauthorized external acceptance input withheld.\n');
 process.exitCode=2;
}
