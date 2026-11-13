#!/usr/bin/env node
// Static, non-destructive diagnostics only; not proof of secure runtime behavior.
import fs from 'node:fs';
const read = file => fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
const checks = [
  ['Business persistence uses browser localStorage', /localStorage\.setItem/.test(read('src/services/storageService.ts')), 'BLOCKER'],
  ['Schema includes destructive DROP TABLE statements', /DROP TABLE IF EXISTS/i.test(read('database/schema.sql')), 'BLOCKER'],
  ['Server has no dedicated authentication route', !/app\.(post|use)\(['"]\/api\/auth/.test(read('server.ts')), 'BLOCKER'],
  ['Server exposes demo financial amounts', /8,42,500|42\.8L/.test(read('server.ts')), 'BLOCKER'],
  ['Quote approval implemented in browser state', /const handleApproveCard\s*=/.test(read('src/App.tsx')), 'BLOCKER'],
  ['Port 3000 hardcoded', /const PORT\s*=\s*3000/.test(read('server.ts')), 'WARNING']
];
const output = {generatedAt:new Date().toISOString(),type:'heuristic-baseline',checks:checks.map(([name,detected,severity])=>({name,detected,severity}))};
fs.writeFileSync('phase0-audit-report.json', JSON.stringify(output,null,2)+'\n');
for (const item of output.checks) console.log((item.detected?'FOUND':'NOT FOUND')+' '+item.severity+': '+item.name);
console.log('Baseline only; no code changes or production readiness claims.');
