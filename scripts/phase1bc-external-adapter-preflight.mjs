import {assessPhase1BcOfflineAdapter} from './lib/phase1BcExternalAdapterProtocol.mjs';

// This is intentionally not an external provider adapter. Do not add
// endpoints, credentials, TLS certificates, KMS material, signed contracts,
// object mutation or real encrypted-restore operations to CI.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BC no external authorization to receive evidence');
 const verdict=assessPhase1BcOfflineAdapter();
 if(verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||
    verdict.releaseDecision!=='HOLD')
  throw Error('1BC production release invariant failed');
 process.stdout.write(JSON.stringify({
  ...verdict,authenticProviderContractVerified:false,
  independentlyControlledChallengeIssuersVerified:false,
  providerIssuedObjectLockReceiptsVerified:false,
  genuineEncryptedDRRestoreVerified:false,
  liveCaMcaRevocationVerified:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BC HARD HOLD: unauthorized external evidence input refused.\n');
 process.exitCode=2;
}
