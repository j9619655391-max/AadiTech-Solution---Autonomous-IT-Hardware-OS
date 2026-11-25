import {assessPhase1BbEvidenceIntake} from './lib/phase1BbEvidenceIntake.mjs';

// Zero-input only: no network, provider keys, certificates, contracts, legal
// dossiers, cloud APIs, private evidence files or environment activation.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BB refuses all non-HOLD inputs');
 const result=assessPhase1BbEvidenceIntake();
 if(result.productionReleaseAuthorized!==false||
    result.productionReleaseBlocked!==true||result.releaseDecision!=='HOLD')
  throw Error('1BB invariant violation');
 process.stdout.write(JSON.stringify({
  ...result,providerAgreementAuthenticated:false,
  reviewerRolesLegallyVerified:false,
  externallyIssuedChallengesVerified:false,
  immutableCloudArchiveVerified:false,
  independentlyWitnessedEncryptedRestore:false,
  externalCredentialAccessEnabled:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BB HOLD: unauthorized intake input withheld.\n');
 process.exitCode=2;
}
