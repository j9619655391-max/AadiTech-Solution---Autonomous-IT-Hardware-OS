import {assessPhase1AwCheckpointRecovery} from './lib/phase1AwSignedCheckpoint.mjs';

// Phase 1AW: CI-safe, zero-input, zero-network, zero-secret integration.
// Public keys and signed private evidence MUST NOT be loaded from CI,
// environment variables, CLI args, .env, Git or repository fixtures.
try{
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('Unsupported signature checkpoint operation');
 process.stdout.write(JSON.stringify(assessPhase1AwCheckpointRecovery(),null,2)+'\n');
}catch{
 process.stderr.write(
  'Phase 1AW HOLD: unauthorized offline checkpoint operation; input withheld.\n'
 );
 process.exitCode=2;
}
