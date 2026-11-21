import {assessPhase1AyArchiveWitnesses,assessPhase1AyRecovery}
 from './lib/phase1AyWitnessArchiveRecovery.mjs';

// This CI-only report accepts no credentials, private evidence, filesystem
// paths or actual witness enrollment. It cannot authorize any deployment.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('Phase 1AY preflight requires zero-input HOLD mode');
 const witness=assessPhase1AyArchiveWitnesses();
 const recovery=assessPhase1AyRecovery();
 process.stdout.write(JSON.stringify({
  phase:'1AY',reviewBasis:'OFFLINE_ONLY_NOT_EXTERNAL_AUTHORITY',
  witness, recovery, immutableExternalArchiveVerified:false,
  independentEncryptedRestoreVerified:false,
  providerAgreementAuthenticated:false,ccaRcaiPathVerified:false,
  liveSignedCrlOcspAuthenticated:false,mcaSignatoryAuthorityVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1AY HOLD: unauthorized witness/archive/recovery input withheld.\n');
 process.exitCode=2;
}
