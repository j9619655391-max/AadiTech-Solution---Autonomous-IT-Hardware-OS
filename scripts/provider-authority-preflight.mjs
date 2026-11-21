import { readSync, openSync, closeSync, fstatSync, lstatSync, realpathSync, constants } from 'node:fs';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reviewPhase1ApDigestInventory } from './lib/providerAuthorityPreflight.mjs';

// Phase 1AR: trust neither process.cwd() nor a pre-open path check.
// This root is derived from the installed script, not the caller's directory.
const repositoryRoot = realpathSync(fileURLToPath(new URL('../', import.meta.url)));
const MAX_PACKET_BYTES = 16_384;

function isWithinRepository(path) {
  const rel = relative(repositoryRoot, path);
  return !isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + sep);
}

function inspect(argv, env) {
  if (argv.length === 0 || (argv.length === 1 && argv[0] === '--ci-hold'))
    return reviewPhase1ApDigestInventory(null);
  if (argv.length !== 2 || argv[0] !== '--offline-packet')
    throw Error('Invalid offline inspection mode');
  if (env.GITHUB_ACTIONS === 'true' || env.CI === 'true' ||
      env.NODE_ENV === 'production' || env.PHASE_1AP_OFFLINE_INSPECTION_APPROVED !== 'YES')
    throw Error('Offline inspection prohibited in CI, production or without approval');
  if (!isAbsolute(argv[1])) throw Error('Private packet path must be absolute');

  const path = resolve(argv[1]);
  // Reject symlinks in *any* path component and check against the script-root,
  // even when invoked from outside checkout. Never read from Git worktree.
  const canonical = realpathSync(path);
  if (path !== canonical || isWithinRepository(canonical))
    throw Error('Private evidence must be a direct regular file outside checkout');
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink())
    throw Error('Private packet must be a regular file');
  if (!Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_NONBLOCK))
    throw Error('Secure no-follow file open unavailable');

  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    // Detect a replaced file between lstat and open, and reject accidental
    // world/group access. Never execute provider, network or database actions.
    if (!stat.isFile() || before.ino !== stat.ino || before.dev !== stat.dev ||
        stat.size < 1 || stat.size > MAX_PACKET_BYTES || (stat.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && stat.uid !== process.getuid()))
      throw Error('Private packet fails size, identity, ownership or permissions policy');

    // Bounded file-descriptor read prevents growing-file races from consuming
    // arbitrary memory. Validate the size again before parsing.
    const buffer = Buffer.alloc(MAX_PACKET_BYTES + 1);
    let consumed = 0;
    while (consumed < buffer.length) {
      const count = readSync(fd, buffer, consumed, buffer.length - consumed, consumed);
      if (count === 0) break;
      consumed += count;
    }
    if (consumed !== stat.size || consumed > MAX_PACKET_BYTES)
      throw Error('Private packet changed during inspection');
    return reviewPhase1ApDigestInventory(JSON.parse(buffer.subarray(0, consumed).toString('utf8')));
  } finally {
    closeSync(fd);
  }
}

try {
  const report = inspect(process.argv.slice(2), process.env);
  // Never echo a packet, hashes from individual documents, private path or credentials.
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} catch (_error) {
  process.stderr.write('Phase 1AP/1AR HOLD: invalid or unauthorized private evidence packet; input and path withheld.\n');
  process.exitCode = 2;
}
