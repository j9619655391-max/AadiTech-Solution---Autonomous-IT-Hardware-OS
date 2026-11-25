import {assessPhase1BeRevocationFreeze} from './lib/phase1BeRevocationFreeze.mjs';

// No private keys, provider endpoints, network, MCA documents, WORM mutation,
// source-of-truth enrollment or live revocation in CI. Zero input only.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('Phase 1BE unauthorized inputs');
 const report=assessPhase1BeRevocationFreeze();
 if(report.productionReleaseAuthorized!==false||
    report.productionReleaseBlocked!==true||
    report.releaseDecision!=='HOLD'||
    report.witnessKeyExternallyRevoked!==false||
    report.locallyCoSignedFreezeConsistent!==false)
  throw Error('Phase 1BE source authorization violation');
 process.stdout.write(JSON.stringify({
  ...report,
  approvedProviderAgreementVerified:false,
  outOfBandWitnessOrganizationVerified:false,
  providerSignedRevocationSourceVerified:false,
  externallyPublishedEmergencyFreezeVerified:false,
  liveWormObjectLockDeletionDenied:false,
  independentEncryptedDrRestoreWitnessed:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BE HARD HOLD: unauthorized revocation evidence or release request refused.\n');
 process.exitCode=2;
}
