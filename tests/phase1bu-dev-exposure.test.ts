import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {request} from 'node:http';
import {readFileSync} from 'node:fs';
import express from 'express';
import {resolveDeploymentSecurity} from '../server/security/deploymentGuards';
import {resolveDevToolExposure,devToolHostGate} from '../server/security/devToolExposure';

const PORT=34277;
const env:NodeJS.ProcessEnv={NODE_ENV:'development',APP_BIND_HOST:'127.0.0.1'};
test('BU local dev/test config is strict loopback and always release HOLD',()=>{
 const conf=resolveDevToolExposure(env,PORT);
 assert.equal(conf.bindHost,'127.0.0.1');
 assert.equal(conf.port,PORT);
 assert.deepEqual(conf.allowedOrigins,[
  'http://127.0.0.1:34277','http://localhost:34277','http://[::1]:34277']);
 assert.equal(conf.vulnerableDevToolingStillInstalled,true);
 assert.equal(conf.prodAuthorityEstablished,false);
 assert.equal(conf.independentSecurityApprovalVerified,false);
 assert.equal(conf.productionReleaseAuthorized,false);
 assert.equal(conf.releaseDecision,'HOLD');
 assert.equal(resolveDeploymentSecurity(env).bindHost,'127.0.0.1');
 assert.equal(resolveDevToolExposure({...env,APP_BIND_HOST:'::1'},PORT).bindHost,'::1');
 assert.equal(resolveDevToolExposure({NODE_ENV:'test'},PORT).bindHost,'127.0.0.1');
});
test('BU nonproduction bind, override, stage/prod typos and malformed ports fail before Vite import',()=>{
 for(const bind of [
  '0.0.0.0','::','192.168.1.15','10.0.0.25','localhost',
  'localhost.local','127.0.0.2','[::1]',''
 ]){
  assert.throws(()=>resolveDevToolExposure({...env,APP_BIND_HOST:bind},PORT),/loopback/);
  assert.throws(()=>resolveDeploymentSecurity({...env,APP_BIND_HOST:bind}),/loopback/);
 }
 for(const change of [
  {APP_ALLOW_PUBLIC_BIND:'true'},{VITE_HOST:'0.0.0.0'},
  {HOST:'0.0.0.0'},{__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS:'evil.invalid'},
  {VITE_ADDITIONAL_ALLOWED_HOSTS:'*.invalid'},
  {DEV_SERVER_PUBLIC:'true'},
  {NODE_ENV:'prodution'},{NODE_ENV:'staging'},{NODE_ENV:'production'}
 ])assert.throws(()=>resolveDevToolExposure({...env,...change},PORT));
 for(const port of [-1,0,65536,NaN,1.4])assert.throws(
  ()=>resolveDevToolExposure(env,port),/port/);
});
test('BU real HTTP refuses hostile Host, Origin, DNS rebinding and proxy spoofing',async()=>{
 const app=express();
 let guard:ReturnType<typeof devToolHostGate>|null=null;
 app.use((req,res,next)=>{
  if(!guard){res.status(503).end();return;}
  return guard(req,res,next);
 });
 app.get('/api/health',(_req,res)=>res.json({status:'ok'}));
 app.get('/@vite/client',(_req,res)=>res.json({devOnly:true}));
 const server=app.listen(0,'127.0.0.1');
 await once(server,'listening');
 try{
  const addr=server.address();assert.ok(addr&&typeof addr!=='string');
  const port=addr.port;
  guard=devToolHostGate(resolveDevToolExposure(env,port));
  const probe=(urlPath:string,headers:Record<string,string>={})=>
   new Promise<{status:number,body:string,cache:string|undefined}>((resolve,reject)=>{
    const req=request({hostname:'127.0.0.1',port,path:urlPath,
      method:'GET',headers},res=>{
     const chunks:Buffer[]=[];
     res.on('data',(b:Buffer)=>chunks.push(b));
     res.on('end',()=>resolve({status:res.statusCode??0,
      body:Buffer.concat(chunks).toString('utf8'),
      cache:res.headers['cache-control']}));
     res.on('error',reject);
    });
    req.on('error',reject);req.end();
   });
  const host='127.0.0.1:'+port;
  const accepted=await probe('/api/health');
  assert.equal(accepted.status,200);
  assert.equal(accepted.cache,'no-store');
  assert.equal((await probe('/@vite/client',{Host:host})).status,200);
  assert.equal((await probe('/api/health',{Host:'localhost:'+port,
    Origin:'http://localhost:'+port})).status,200);
  for(const headers of [
   {Host:'evil.invalid:'+port},
   {Host:'127.0.0.1.evil.invalid:'+port},
   {Host:'0.0.0.0:'+port},
   {Host:'localhost.evil.invalid:'+port},
   {Host:'[::ffff:127.0.0.1]:'+port},
   {Host:host,Origin:'http://attacker.invalid'},
   {Host:host,Origin:'http://localhost:'+port},
   {Host:host,Origin:'null'},
   {Host:host,Origin:'http://127.0.0.1:'+port+'/'},
   {Host:host,'X-Forwarded-Host':'attacker.invalid'},
   {Host:host,'X-Forwarded-For':'203.0.113.8'},
   {Host:host,'X-Forwarded-Proto':'https'},
   {Host:host,'X-Original-Host':'attacker.invalid'},
   {Host:host,Forwarded:'host=attacker.invalid'}
  ]){
   const rejected=await probe('/@vite/client',headers);
   assert.equal(rejected.status,403,JSON.stringify(headers));
   assert.match(rejected.body,/Local-only developer tooling request denied/);
   assert.equal(rejected.cache,'no-store');
  }
 }finally{
  await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
 }
});
test('BU Vite dev+preview source is constrained to local-only, no HMR or wildcard CORS',()=>{
 const src=readFileSync('vite.config.ts','utf8');
 const server=src.match(/server:\s*\{([\s\S]*?)\n\s*\},\n\s*preview:/)?.[1]??'';
 const preview=src.match(/preview:\s*\{([\s\S]*?)\n\s*\},/)?.[1]??'';
 for(const block of [server,preview]){
  assert.match(block,/host:\s*'127\.0\.0\.1'/);
  assert.match(block,/allowedHosts:\s*\['localhost','127\.0\.0\.1'\]/);
  assert.match(block,/strictPort:\s*true/);
  assert.match(block,/cors:\s*false/);
 }
 assert.match(server,/hmr:\s*false/);
 assert.match(server,/fs:\s*\{strict:\s*true\}/);
 assert.doesNotMatch(src,/allowedHosts:\s*true/);
});
