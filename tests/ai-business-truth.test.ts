import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('legacy AI routes never return invented business activity',()=>{
 const s=readFileSync('server.ts','utf8');
 for(const bad of ['₹8,42,500','₹42.8L','QT-2026-089','All 8 AI Agents operating normally',
   'telegramNotificationSent: true','compatibilityStatus: "PASSED"'])
  assert.equal(s.includes(bad),false,'unsafe mock in server: '+bad);
 assert.match(s,/Business command unavailable/);
 assert.match(s,/Negotiation automation blocked pending server-side pricing/);
});
