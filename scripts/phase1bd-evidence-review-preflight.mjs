import {assessPhase1BdEvidenceReview} from './lib/phase1BdEvidenceReview.mjs';

// CI has no authority to read provider credentials, issue challenges, enroll
// keys, access KMS, exercise cloud deletion probes, or perform DR restores.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('1BD refuses evidence imports and unauthorized activation');
 const result=assessPhase1BdEvidenceReview();
 if(result.productionReleaseAuthorized!==false||
    result.productionReleaseBlocked!==true||result.releaseDecision!=='HOLD')
  throw Error('1BD external authority invariant violated');
 process.stdout.write(JSON.stringify({
  ...result,approvedProviderAgreementVerified:false,
  outOfBandKeyCustodyVerified:false,liveObjectLockDeleteDeniedVerified:false,
  liveEncryptedStagingRestoreWitnessed:false,ccaEmudhraMcaVerified:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BD HARD HOLD: external authority and evidence import are not approved.\n');
 process.exitCode=2;
}
