import {assessPhase1BaIndependentAcceptance} from './lib/phase1BaIndependentAcceptance.mjs';

// Phase 1BA is an OFFLINE release blocker, not a live verifier or a secret
// ingestion interface. It has no external networking or storage integrations.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BA rejects all non-CI inputs');
 const assessment=assessPhase1BaIndependentAcceptance();
 if(assessment.productionReleaseAuthorized!==false||
   assessment.productionReleaseBlocked!==true||assessment.releaseDecision!=='HOLD')
  throw Error('1BA release invariant violation');
 process.stdout.write(JSON.stringify({
  ...assessment,providerAuthorizationAuthenticated:false,
  independentWitnessSourcesAuthenticated:false,
  externalImmutableWormArchiveVerified:false,
  encryptedBackupAndRestoreWitnessed:false,
  externalIndependentSignoffsApproved:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BA HOLD: unauthorized external evidence or release request withheld.\n');
 process.exitCode=2;
}
