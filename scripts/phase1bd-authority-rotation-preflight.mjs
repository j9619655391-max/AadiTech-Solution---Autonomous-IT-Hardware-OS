import {assessPhase1BdRotation} from './lib/phase1BdAuthorityRotation.mjs';

// Phase 1BD is an OFFLINE key-handover contract. Never accept provider
// credentials, legal records, remote endpoints, WORM operations, release
// overrides or externally issued signing keys through this CI command.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BD only permits zero-input CI assessment');
 const verdict=assessPhase1BdRotation();
 if(verdict.productionReleaseAuthorized!==false||
   verdict.productionReleaseBlocked!==true||
   verdict.releaseDecision!=='HOLD'||verdict.locallySignedHandoverConsistent!==false)
  throw Error('1BD unauthorized release state');
 process.stdout.write(JSON.stringify({
  ...verdict,
  phase:'1BD',
  source:'ZERO_INPUT_CI_HOLD_ONLY',
  externalWitnessAuthorityAuthenticated:false,
  outOfBandRotatedKeyProofAuthenticated:false,
  actualWormDeletionDenialVerified:false,
  genuineEncryptedDrRestoreWitnessed:false,
  releaseApprovalVerified:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BD HOLD: unsupported external evidence or release request denied.\n');
 process.exitCode=2;
}
