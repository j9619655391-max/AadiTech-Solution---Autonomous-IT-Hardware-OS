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

test('browser-local command and approvals cannot forge business workflow',()=>{
 const app=readFileSync('src/App.tsx','utf8');
 assert.equal(app.includes("revenueToday: '₹8.42 Lakh'"),false);
 assert.equal(app.includes('Sales Order **#SO-4409** automatically raised'),false);
 assert.equal(app.includes("status: 'TELEGRAM_APPROVED'"),false);
 assert.match(app,/This browser-local preview has NO authority/);
 const neg=readFileSync('src/components/QuotationAndNegotiation.tsx','utf8');
 assert.equal(neg.includes('onSendToTelegram(card)'),false);
 assert.match(neg,/Negotiation automation unavailable/);
});
