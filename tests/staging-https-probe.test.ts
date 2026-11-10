import test from 'node:test';
import assert from 'node:assert/strict';
import {checkProbeObservations,validateStagingProbeTarget,
 performStagingProbe,type ProbeObservation} from '../scripts/lib/stagingHttpsProbe';

const headers={
 'strict-transport-security':'max-age=31536000',
 'x-content-type-options':'nosniff','cache-control':'no-store'
};
const obs=(status:number):ProbeObservation=>({status,tlsPeerAuthorized:true,headers});
test('HTTPS probe refuses all targets unless expressly approved, exact staging origin',()=>{
 const good={
  STAGING_HTTPS_PROBE:'YES',STAGING_PROBE_APPROVED:'YES',
  STAGING_HTTPS_ORIGIN:'https://staging.aaditechs.in',
  STAGING_APPROVED_HOST:'staging.aaditechs.in',
  STAGING_CHANGE_TICKET:'CHG-STAGING-001'
 };
 assert.equal(validateStagingProbeTarget(good).origin,'https://staging.aaditechs.in');
 for(const overrides of [
  {STAGING_HTTPS_PROBE:'no'}, {STAGING_PROBE_APPROVED:undefined},
  {STAGING_CHANGE_TICKET:'bad'}, {STAGING_APPROVED_HOST:'prod.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'http://staging.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://user:pass@staging.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://staging.aaditechs.in:8443'},
  {STAGING_HTTPS_ORIGIN:'https://staging.aaditechs.in/api/health'},
  {STAGING_HTTPS_ORIGIN:'https://staging.localhost'},
  {STAGING_HTTPS_ORIGIN:'https://staging.example.invalid'}
 ])assert.throws(()=>validateStagingProbeTarget({...good,...overrides}));
});
test('probe assesses cert, HSTS, no-store, no branding and overwritten spoofed proto',()=>{
 const result=checkProbeObservations(obs(200),obs(401),obs(200));
 assert.equal(result.observedChecksPassed,true);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.proxyIpOverwriteIndependentlyVerified,false);
 assert.equal(checkProbeObservations(obs(200),obs(401),obs(403)).observedChecksPassed,false);
 assert.equal(checkProbeObservations({...obs(200),tlsPeerAuthorized:false},obs(401),obs(200)).observedChecksPassed,false);
 assert.equal(checkProbeObservations(obs(200),{...obs(401),headers:{}},obs(200)).observedChecksPassed,false);
 assert.equal(checkProbeObservations({...obs(200),headers:{...headers,
  'strict-transport-security':'max-age=30000000'}},obs(401),obs(200)).observedChecksPassed,false);
});
test('staging probe can use a mocked fetcher, never live network in tests',async()=>{
 const paths:string[]=[];
 const fetcher=async(_origin:string,path:string)=>{
  paths.push(path);return obs(path==='/api/auth/me'?401:200);
 };
 const report=await performStagingProbe({
  origin:'https://staging.aaditechs.in',changeTicket:'CHG-STAGING-001'
 },fetcher);
 assert.equal(report.observedChecksPassed,true);
 assert.deepEqual(paths,['/api/health','/api/auth/me','/api/health']);
 assert.equal(report.directListenerIsolationIndependentlyVerified,false);
});
