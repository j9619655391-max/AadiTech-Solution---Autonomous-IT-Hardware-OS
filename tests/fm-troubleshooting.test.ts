import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
import {
 WINDOWS_GUIDES,TROUBLE_CATEGORIES,searchTroubleGuides,troubleGuideById,
 validateTroubleSearch,TroubleQueryError
} from '../server/troubleshooting/guides';
import troubleshootingRouter from '../server/troubleshooting/router';

test('1FM covers all 20 requested Windows topics with unique IDs and safe steps',()=>{
 const expected=[
  'pc-slow','wifi-no-internet','windows-update-fails','disk-almost-full',
  'blue-screen','no-sound','bluetooth-not-connecting','printer-not-printing',
  'screen-flicker-black','slow-startup','suspected-malware','outlook-crashing',
  'start-menu-frozen','battery-drains-fast','vpn-no-internet','copilot-disable',
  'preinstalled-apps','windows-privacy-telemetry','driver-update-broke','win11-context-menu'
 ];
 assert.equal(WINDOWS_GUIDES.length,20);
 assert.deepEqual(WINDOWS_GUIDES.map(g=>g.id).sort(),expected.sort());
 for(const guide of WINDOWS_GUIDES){
  assert.ok(TROUBLE_CATEGORIES.includes(guide.category));
  assert.ok(guide.title.length>5&&guide.summary.length>15);
  assert.ok(guide.firstChecks.length>=2&&guide.escalateWhen.length>=2&&guide.caution.length>35);
  assert.ok(guide.keywords.length>=3);
  assert.ok(guide.firstChecks.every(s=>s.length>20));
  assert.ok(!/powershell|cmd\.exe|reg(?:edit| add)|curl .*\|/i.test(
   [guide.caution,...guide.firstChecks].join(' ')),guide.id);
 }
 assert.equal(new Set(WINDOWS_GUIDES.map(g=>g.title)).size,20);
 assert.equal(troubleGuideById('printer-not-printing')?.title,"My printer won't print");
 assert.equal(troubleGuideById('__proto__'),undefined);
 assert.equal(troubleGuideById(['pc-slow']),undefined);
});
test('1FM deterministic keyword and category search returns only matched guides',()=>{
 assert.equal(searchTroubleGuides().length,20);
 assert.deepEqual(searchTroubleGuides('blue screen').map(g=>g.id),['blue-screen']);
 assert.deepEqual(searchTroubleGuides('wifi no internet').map(g=>g.id),['wifi-no-internet']);
 assert.deepEqual(searchTroubleGuides('outlook crashes').map(g=>g.id),['outlook-crashing']);
 assert.deepEqual(searchTroubleGuides('').filter(g=>g.category==='NETWORK').map(g=>g.id).sort(),
  ['vpn-no-internet','wifi-no-internet']);
 assert.deepEqual(searchTroubleGuides(undefined,'SECURITY').map(g=>g.id),['suspected-malware']);
 assert.equal(searchTroubleGuides('printers','SECURITY').length,0);
 assert.equal(validateTroubleSearch('  WiFi  ',undefined).query,'wifi');
});
test('1FM rejects arrays, overlong and control-character search terms and unknown categories',()=>{
 for(const q of [['printer'],123,{},'a'.repeat(121),'bad\ninput','bad\u0000input'])
  assert.throws(()=>searchTroubleGuides(q),TroubleQueryError);
 for(const c of [['SECURITY'],'UNKNOWN','security',1,{},null])
  assert.throws(()=>searchTroubleGuides('',c),TroubleQueryError);
});
test('1FM HTTP router requires a valid session; no public guidance or unauthenticated mutating routes',async()=>{
 const app=express();
 app.use('/api/help/troubleshooting',troubleshootingRouter);
 const server=app.listen(0,'127.0.0.1');
 await once(server,'listening');
 try{
  const address=server.address();
  assert.ok(address&&typeof address!=='string');
  const url='http://127.0.0.1:'+address.port+'/api/help/troubleshooting';
  for(const path of ['','/pc-slow','?q=wifi']){
   const res=await fetch(url+path);
   assert.equal(res.status,401);
   assert.equal(res.headers.get('cache-control'),'no-store');
   const body=await res.json();
   assert.equal(body.error,'Authentication required');
  }
  const post=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(post.status,401);
 }finally{
  await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
 }
});
test('1FM UI and server routes never execute Windows commands or synthesize service tickets',()=>{
 const router=readFileSync('server/troubleshooting/router.ts','utf8');
 const view=readFileSync('src/components/WindowsTroubleshootingWorkspace.tsx','utf8');
 const server=readFileSync('server.ts','utf8');
 const app=readFileSync('src/App.tsx','utf8');
 const header=readFileSync('src/components/Header.tsx','utf8');
 assert.match(router,/router\.use\(requireAuthenticated\)/);
 assert.match(router,/router\.get\('\/'/);
 assert.doesNotMatch(router,/router\.(post|put|patch|delete)\(/i);
 assert.doesNotMatch(router,/child_process|execFile|spawn|PowerShell|electron\.ipc|writeFile|\bgetPool\(/);
 assert.match(view,/GUIDANCE_ONLY/);
 assert.match(view,/deviceInspected!==false/);
 assert.match(view,/actionsExecuted!==false/);
 assert.match(view,/authenticatedFetch\(url/);
 assert.doesNotMatch(view,/localStorage|exec\(|fetch\('https?:\/\//i);
 assert.match(server,/app\.use\("\/api\/help\/troubleshooting", troubleshootingRouter\)/);
 assert.match(app,/activeTab === 'troubleshooting' && <WindowsTroubleshootingWorkspace/);
 assert.match(header,/id: 'troubleshooting', label: 'Windows Troubleshooting'/);
});
