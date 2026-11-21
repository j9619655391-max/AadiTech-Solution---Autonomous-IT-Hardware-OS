import { auditPhase1AqPublicCertificateChain } from './lib/phase1AqTrustIncident.mjs';

// Deliberately no provider networking, private file input, secret flags or
// activation API. CI preflight always records the conservative HOLD decision.
try {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--ci-hold'))
    throw Error('Unsupported mode');
  process.stdout.write(JSON.stringify(auditPhase1AqPublicCertificateChain(), null, 2) + '\n');
} catch (_) {
  process.stderr.write('Phase 1AQ HOLD: unsupported or unauthorized trust-incident operation; input withheld.\n');
  process.exitCode = 2;
}
