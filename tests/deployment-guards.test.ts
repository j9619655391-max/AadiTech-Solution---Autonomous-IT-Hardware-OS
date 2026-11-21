import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import express from 'express';
import {parseTrustedProxyCidrs,resolveDeploymentSecurity,
 securityTransportMiddleware} from '../server/security/deploymentGuards';

const production:NodeJS.ProcessEnv={
 NODE_ENV:'production',APP_URL:'https://staging.example.invalid',
 APP_REQUIRE_HTTPS:'true',APP_TRUSTED_PROXY_CIDRS:'127.0.0.1/32',
 MFA_REQUIRE_PRIVILEGED:'true',MFA_ENCRYPTION_KEY:'a'.repeat(64),
 DB_HOST:'mysql.staging.invalid',DB_PORT:'3306',DB_USER:'staging_user',
 DB_NAME:'aaditech_staging_ci',DB_PASSWORD:'fake-test-password',DB_SSL:'true'
};
test('production startup refuses absent or unsafe reverse-proxy, TLS, MFA, database settings',()=>{
 const valid=resolveDeploymentSecurity(production);
 assert.equal(valid.production,true);
 assert.equal(valid.bindHost,'127.0.0.1');
 assert.deepEqual(valid.trustedProxyCidrs,['127.0.0.1/32']);
 for(const key of ['APP_TRUSTED_PROXY_CIDRS','APP_URL','APP_REQUIRE_HTTPS',
  'DB_SSL','MFA_REQUIRE_PRIVILEGED','MFA_ENCRYPTION_KEY','DB_PASSWORD']){
  assert.throws(()=>resolveDeploymentSecurity({...production,[key]:undefined}),/invalid/);
 }
 for(const url of ['http://example.invalid','https://example.invalid/path',
  'https://user:pass@example.invalid/','https://example.invalid/?token=1']){
  assert.throws(()=>resolveDeploymentSecurity({...production,APP_URL:url}),/APP_URL/);
 }
 assert.throws(()=>resolveDeploymentSecurity({...production,APP_BIND_HOST:'0.0.0.0'}),
  /APP_ALLOW_PUBLIC_BIND/);
 assert.equal(resolveDeploymentSecurity({...production,APP_BIND_HOST:'0.0.0.0',
  APP_ALLOW_PUBLIC_BIND:'true'}).publicBind,true);
});
test('only precise trusted proxy IPs or narrow CIDRs accepted',()=>{
 assert.deepEqual(parseTrustedProxyCidrs('127.0.0.1,10.0.4.0/24'),
  ['127.0.0.1','10.0.4.0/24']);
 for(const bad of ['loopback','0.0.0.0/0','10.0.0.0/8','::/0',
  '10.0.0.1/33','10.0.0.1/024','127.0.0.1,,10.0.0.1',
  '127.0.0.1,127.0.0.1']){
  assert.throws(()=>parseTrustedProxyCidrs(bad));
 }
});
test('untrusted forwarded headers cannot fake HTTPS or client IP',async()=>{
 const conf=resolveDeploymentSecurity(production);
 const app=express();
 app.set('trust proxy',false);
 app.use(securityTransportMiddleware(conf));
 app.get('/probe',(req,res)=>res.json({ip:req.ip,secure:req.secure}));
 const server=app.listen(0,'127.0.0.1');
 await once(server,'listening');
 try{
  const addr=server.address();assert.ok(addr&&typeof addr!=='string');
  const base='http://127.0.0.1:'+addr.port;
  const spoof=await fetch(base+'/probe',{
   headers:{'x-forwarded-for':'203.0.113.88','x-forwarded-proto':'https'}
  });
  assert.equal(spoof.status,403);
  const blocked=await fetch(base+'/probe');
  assert.equal(blocked.status,403);
  app.set('trust proxy',conf.trustedProxyCidrs);
  const accepted=await fetch(base+'/probe',{
   headers:{'x-forwarded-for':'203.0.113.88',
    'x-forwarded-proto':'https'}
  });
  assert.equal(accepted.status,200);
  assert.equal((await accepted.json()).ip,'203.0.113.88');
  assert.equal(accepted.headers.get('strict-transport-security'),'max-age=31536000');
  assert.equal(accepted.headers.get('x-content-type-options'),'nosniff');
  const mixed=await fetch(base+'/probe',{
   headers:{'x-forwarded-proto':'https,http'}
  });
  assert.equal(mixed.status,403);
 }finally{
  await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
 }
});
test('development remains opt-out, preserving isolated CI and localhost HTTP',()=>{
 const c=resolveDeploymentSecurity({NODE_ENV:'test'});
 assert.equal(c.httpsRequired,false);
 assert.deepEqual(c.trustedProxyCidrs,[]);
});
