import test from 'node:test';
import assert from 'node:assert/strict';
import {checkProbeObservations,isPublicIPv4,parseApprovedIPv4s,
 validateStagingProbeTarget,resolvePinnedStagingIPv4,
 performStagingProbe,type ProbeObservation} from '../scripts/lib/stagingHttpsProbe';

const headers={'strict-transport-security':'max-age=31536000',
 'x-content-type-options':'nosniff','cache-control':'no-store'};
const obs=(status:number):ProbeObservation=>({
 status,tlsPeerAuthorized:true,headers,
 certificateValidUntil:'2030-01-01T00:00:00.000Z'
});
const target={origin:'https://staging.aaditechs.in',changeTicket:'CHG-STAGING-001',
 approvedIPv4s:['1.1.1.1','8.8.8.8']};
test('HTTPS probe refuses unauthorized, non-staging or unapproved DNS inventory',()=>{
 const good={
  STAGING_HTTPS_PROBE:'YES',STAGING_PROBE_APPROVED:'YES',
  STAGING_HTTPS_ORIGIN:target.origin,
  STAGING_APPROVED_HOST:'staging.aaditechs.in',
  STAGING_CHANGE_TICKET:target.changeTicket,
  STAGING_APPROVED_IPV4S:'1.1.1.1,8.8.8.8'
 };
 assert.deepEqual(validateStagingProbeTarget(good),target);
 for(const overrides of [
  {STAGING_HTTPS_PROBE:'no'},{STAGING_PROBE_APPROVED:undefined},
  {STAGING_CHANGE_TICKET:'bad'},{STAGING_APPROVED_HOST:'prod.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'http://staging.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://user:pass@staging.aaditechs.in'},
  {STAGING_HTTPS_ORIGIN:'https://staging.aaditechs.in:8443'},
  {STAGING_HTTPS_ORIGIN:'https://staging.aaditechs.in/api/health'},
  {STAGING_HTTPS_ORIGIN:'https://staging.localhost'},
  {STAGING_HTTPS_ORIGIN:'https://staging.example.invalid'},
  {STAGING_APPROVED_IPV4S:undefined},
  {STAGING_APPROVED_IPV4S:'127.0.0.1'},
  {STAGING_APPROVED_IPV4S:'169.254.169.254'},
  {STAGING_APPROVED_IPV4S:'10.0.0.1'},
  {STAGING_APPROVED_IPV4S:'192.0.2.3'},
  {STAGING_APPROVED_IPV4S:'8.8.8.8,8.8.8.8'}
 ])assert.throws(()=>validateStagingProbeTarget({...good,...overrides}));
});
test('rejects loopback, private, carrier-grade NAT, IPv6 and reserved destinations',()=>{
 for(const ip of ['127.0.0.1','10.0.0.5','172.31.0.2','192.168.5.5',
  '169.254.169.254','100.64.1.1','198.18.0.1','198.51.100.2',
  '203.0.113.4','192.0.2.1','0.0.0.0','224.1.1.1','::1'])
  assert.equal(isPublicIPv4(ip),false,ip);
 assert.equal(isPublicIPv4('1.1.1.1'),true);
 assert.deepEqual(parseApprovedIPv4s('8.8.8.8,1.1.1.1'),['1.1.1.1','8.8.8.8']);
});
test('DNS pinning fails closed on drift, IPv6, private or missing resolution',async()=>{
 assert.equal(await resolvePinnedStagingIPv4(target,async()=>['8.8.8.8','1.1.1.1']),'1.1.1.1');
 for(const answers of [[],['8.8.8.8'],['8.8.8.8','8.8.4.4'],
  ['8.8.8.8','127.0.0.1'],['1.1.1.1','::1'],['1.1.1.1','1.1.1.1']])
  await assert.rejects(resolvePinnedStagingIPv4(target,async()=>answers));
});
test('probe checks TLS expiry, HSTS, cache, no branding and forged protocol overwrite',()=>{
 const result=checkProbeObservations(obs(200),obs(401),obs(200));
 assert.equal(result.observedChecksPassed,true);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.proxyIpOverwriteIndependentlyVerified,false);
 assert.equal(checkProbeObservations(obs(200),obs(401),obs(403)).observedChecksPassed,false);
 assert.equal(checkProbeObservations({...obs(200),tlsPeerAuthorized:false},obs(401),obs(200)).observedChecksPassed,false);
 assert.equal(checkProbeObservations(obs(200),{...obs(401),headers:{}},obs(200)).observedChecksPassed,false);
 assert.equal(checkProbeObservations({...obs(200),headers:{...headers,
  'strict-transport-security':'max-age=30000000'}},obs(401),obs(200)).observedChecksPassed,false);
 assert.equal(checkProbeObservations({...obs(200),
  certificateValidUntil:'2026-11-12T00:00:00.000Z'},obs(401),obs(200)).observedChecksPassed,false);
});
test('staging probe mocked fetcher pins one approved IPv4 and never calls network',async()=>{
 const paths:string[]=[],addresses:string[]=[];
 const fetcher=async(_origin:string,path:string,_headers:Record<string,string>,ip:string)=>{
  paths.push(path);addresses.push(ip);
  return obs(path==='/api/auth/me'?401:200);
 };
 const report=await performStagingProbe(target,fetcher,async()=>['8.8.8.8','1.1.1.1']);
 assert.equal(report.observedChecksPassed,true);
 assert.deepEqual(paths,['/api/health','/api/auth/me','/api/health']);
 assert.deepEqual(addresses,['1.1.1.1','1.1.1.1','1.1.1.1']);
 assert.equal(report.directListenerIsolationIndependentlyVerified,false);
});
