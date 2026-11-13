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

test('AI BOM and campaign screens never backfill unverified prices or forecasts',()=>{
 const bom=readFileSync('src/components/SalesAndBOMBuilder.tsx','utf8');
 assert.equal(bom.includes('it.unitCost || 10000'),false);
 assert.equal(bom.includes('Autonomous Auto-Approve Allowed'),false);
 assert.match(bom,/disabled=\{!currentBOM.length/);
 const market=readFileSync('src/components/MarketingAndAgentView.tsx','utf8');
 assert.equal(market.includes("projectedConversion: '18.4%'"),false);
 assert.match(market,/Dispatch disabled — approval and consent required/);
});

test('legacy browser-only quote and campaign cannot pretend external dispatch',()=>{
 const quote=readFileSync('src/components/QuotationAndNegotiation.tsx','utf8');
 assert.equal(quote.includes("window.open(`https://api.whatsapp.com"),false);
 assert.match(quote,/Browser-only quotation cannot be sent/);
 const app=readFileSync('src/App.tsx','utf8');
 assert.match(app,/RELEASE HOLD — MIXED MODE/);
 assert.match(app,/No messages were sent and no AI agent was started/);
 const bom=readFileSync('src/components/SalesAndBOMBuilder.tsx','utf8');
 assert.equal(bom.includes('Generate Official GST Quotation'),false);
});
