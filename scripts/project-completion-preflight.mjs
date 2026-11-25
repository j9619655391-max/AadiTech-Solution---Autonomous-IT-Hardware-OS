import {assessMasterCompletionLedger,loadMasterCompletionLedger}
 from './lib/masterCompletionLedger.mjs';
// This preflight measures missing approvals. It never changes a release gate.
try{
 if(process.argv.length!==3||process.argv[2]!=='--ci-hold')
  throw Error('Unauthorized completion ledger invocation');
 const result=assessMasterCompletionLedger(loadMasterCompletionLedger());
 if(!result.ledgerStructurallyValid||result.trackedModules!==30||
    result.releaseDecision!=='HOLD'||result.productionReleaseAuthorized!==false||
    result.productionReleaseBlocked!==true)
  throw Error('Invalid or unauthorized completion evidence');
 process.stdout.write(JSON.stringify(result,null,2)+'\n');
}catch{
 process.stderr.write('Project completion HARD HOLD: malformed/unauthorized release input rejected.\n');
 process.exitCode=2;
}
