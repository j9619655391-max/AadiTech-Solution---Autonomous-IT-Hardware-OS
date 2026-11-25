import {assessPhase1AvAuthorityLifecycle} from './lib/phase1AvAuthorityLifecycle.mjs';

// Phase 1AV is intentionally an offline deny-only governance evaluator.
// It has no credential, file, database, provider-network, dispatch or
// production-approval interface. The CI gate cannot read private evidence.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('Unsupported incident authority operation');
 process.stdout.write(JSON.stringify(assessPhase1AvAuthorityLifecycle(),null,2)+'\n');
}catch{
 process.stderr.write(
  'Phase 1AV HOLD: unauthorized incident operation; private inputs withheld.\n'
 );
 process.exitCode=2;
}
