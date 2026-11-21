import {assessPhase1BgEvidenceQuorum}
 from './lib/phase1BgCrossSourceAcceptance.mjs';

// Zero-input CI only. NOT a live CA/CRL/OCSP, witness, WORM, recovery,
// secret manager, provider, legal KYC or production activation adapter.
try{
 const argv=process.argv.slice(2);
 if(argv.length!==1||argv[0]!=='--ci-hold')
  throw Error('1BG external evidence intake prohibited in CI');
 const result=assessPhase1BgEvidenceQuorum();
 if(result.locallyConsistentAuditQuorum!==false||
    result.productionReleaseAuthorized!==false||
    result.productionReleaseBlocked!==true||
    result.releaseDecision!=='HOLD')
  throw Error('1BG release invariant violation');
 process.stdout.write(JSON.stringify({...result,
  externalCrLOcspFetched:false,
  independentlyPinnedAuditAuthorities:false,
  remotelyVerifiedObjectLock:false,
  witnessedRealEncryptedRestore:false,
  providerAgreementAndMcaSignatoryAuthenticated:false
 },null,2)+'\n');
}catch{
 process.stderr.write('Phase 1BG HARD HOLD: no external trust, credentials or production release accepted.\n');
 process.exitCode=2;
}
