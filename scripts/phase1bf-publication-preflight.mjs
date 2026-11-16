import {assessPhase1BfPublication} from './lib/phase1BfRevocationPublication.mjs';

// Zero-input HARD HOLD only; no CA/provider credentials, network, secret
// manager, cloud WORM/DR, live CRL/OCSP, external trust or release path.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BF rejects evidence and activation arguments');
 const verdict=assessPhase1BfPublication();
 if(verdict.productionReleaseAuthorized!==false||
   verdict.productionReleaseBlocked!==true||
   verdict.releaseDecision!=='HOLD'||
   verdict.locallySignedPublicationConsistent!==false)
  throw Error('1BF unauthorized release state');
 process.stdout.write(JSON.stringify({
  ...verdict,independentlyAuthenticatedIssuer:false,
  independentCrlOcspRetrieval:false,actualRevocationSourceVerified:false,
  realStorageRetentionEnforced:false,independentEncryptedDRRestoreWitnessed:false,
  approvedProviderOnboarding:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BF HARD HOLD: unauthorized revocation publisher or release request rejected.\n');
 process.exitCode=2;
}
