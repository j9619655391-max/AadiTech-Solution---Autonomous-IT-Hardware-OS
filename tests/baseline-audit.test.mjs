import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const auditScript = fileURLToPath(new URL('../scripts/audit-baseline.mjs', import.meta.url));
function runAudit(files) {
  const cwd = mkdtempSync(join(tmpdir(), 'aaditech-phase0-'));
  try {
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(dirname(join(cwd, path)), { recursive: true });
      writeFileSync(join(cwd, path), content);
    }
    const result = spawnSync(process.execPath, [auditScript], { cwd, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(readFileSync(join(cwd, 'phase0-audit-report.json'), 'utf8'));
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

test('baseline audit detects known prototype risk patterns without mutating project files', () => {
  const report = runAudit({
    'src/services/storageService.ts': 'localStorage.setItem("leads", "[]");',
    'database/schema.sql': 'DROP TABLE IF EXISTS customers;',
    'server.ts': 'const PORT = 3000; const example = "₹8,42,500";',
    'src/App.tsx': 'const handleApproveCard = (id) => id;'
  });
  assert.equal(report.type, 'heuristic-baseline');
  assert.equal(report.checks.length, 6);
  assert.ok(report.checks.every(check => check.detected === true));
});

test('baseline audit distinguishes missing patterns and reports human-readable severity', () => {
  const report = runAudit({ 'server.ts': 'const PORT = Number(process.env.PORT || 3000); app.post("/api/auth/login", handler);' });
  const missing = Object.fromEntries(report.checks.map(c => [c.name, c.detected]));
  assert.equal(missing['Business persistence uses browser localStorage'], false);
  assert.equal(missing['Schema includes destructive DROP TABLE statements'], false);
  assert.equal(missing['Server has no dedicated authentication route'], false);
  assert.equal(missing['Port 3000 hardcoded'], false);
  assert.ok(report.checks.every(c => ['BLOCKER','WARNING'].includes(c.severity)));
});
