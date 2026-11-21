import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 REPO,ROLES,canonical,signingBytes,validPublicIpv4,validateSourceSpec,
 assessManifest,assessCandidateRemoteQuorum,fetchPinnedJson,
 collectCandidatePinnedReadOnly
} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
const NOW='2026-11-20T00:00:00.000Z';
const head='d'.repeat(40),base='e'.repeat(40);
const fp='f'.repeat(64),cv='1'.repeat(64),nonce='2'.repeat(64);
const hash=v=>createHash('sha256').update(v).digest('hex');
function fixture(){
 const privateKeys={},sources={};
 for(const [i,role] of ROLES.entries()){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'}).toString();
  privateKeys[role]=privateKey;
  sources[role]={
   host:['revocation.custody-example.com','witness-a.custody-example.net',
    'witness-b.custody-example.org'][i],
   path:role==='REVOCATION'?'/v1/revocations/current.json':
    '/v1/checkpoints/latest.json',
   tlsSpkiSha256:String(i+3).repeat(64),
   signerSpkiSha256:hash(publicKey.export({type:'spki',format:'der'})),
   publicKeyPem:pem,keyId:role.toLowerCase().replaceAll('_','-')+'-key-v1'
  };
 }
 const manifest={schemaVersion:1,repository:REPO,
  currentHeadSha:head,mainBaseSha:base,
  policyFingerprintSha256:fp,cvCandidateSha256:cv,nonce,
  previousAnchor:{
   epoch:7,checkpointDigest:'a'.repeat(64),
   revocationVersion:9,revocationDigest:'b'.repeat(64),
   observedAt:'2026-11-19T23:40:00.000Z'
  },sources};
 const rev={schemaVersion:1,repository:REPO,
  sourceHeadSha:head,policyFingerprintSha256:fp,
  cvCandidateSha256:cv,epoch:8,
  checkpointDigest:'c'.repeat(64),previousCheckpointDigest:'a'.repeat(64),
  version:10,previousVersion:9,previousRevocationDigest:'b'.repeat(64),
  revokedKeyIds:[],nonce,
  issuedAt:'2026-11-19T23:55:00.000Z',
  expiresAt:'2026-11-20T00:05:00.000Z'};
 const revDigest=hash(signingBytes('REVOCATION',rev));
 const witness={schemaVersion:1,repository:REPO,
  sourceHeadSha:head,policyFingerprintSha256:fp,cvCandidateSha256:cv,
  epoch:8,checkpointDigest:'c'.repeat(64),
  previousCheckpointDigest:'a'.repeat(64),revocationDigest:revDigest,
  nonce,archiveDigest:fp,objectVersion:'remote-version-123',
  observedAt:'2026-11-19T23:57:00.000Z',
  expiresAt:'2026-11-20T00:06:00.000Z'};
 const statements={REVOCATION:rev,WITNESS_A:structuredClone(witness),
  WITNESS_B:structuredClone(witness)};
 const observations={};
 for(const role of ROLES){
  const spec=sources[role],statement=statements[role];
  observations[role]={
   status:'read',host:spec.host,path:spec.path,
   peerSpkiSha256:spec.tlsSpkiSha256,httpStatus:200,redirectCount:0,
   data:{statement,signature:{
    keyId:spec.keyId,algorithm:'Ed25519',
    signature:sign(null,signingBytes(role,statement),privateKeys[role])
     .toString('base64')
   }}
  };
 }
 return {manifest,observations,now:NOW};
}
const assess=edit=>{const f=fixture();edit?.(f);return assessCandidateRemoteQuorum(f)};
function deny(edit,code){
 const r=assess(edit);
 assert.equal(r.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent,false,
  'should fail closed');
 assert.ok(r.anomalyCodes.includes(code),
  'expected '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('CX: three process-local signed packets validate only candidate consistency, never authority',()=>{
 const r=assess();
 assert.equal(r.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent,
  true,r.anomalyCodes.join('|'));
 assert.equal(r.locallyMatchedSignedSourceCount,3);
 assert.equal(r.currentSourceHeadSha,head);
 assert.match(r.candidateHandoffDigestSha256,/^[a-f0-9]{64}$/);
 for(const key of [
  'externallyMandatedTrustAnchorAndRoleEnrollmentVerified',
  'remoteTlsPinsIndependentlyAuthenticated',
  'independentlyApprovedRevocationAndCertificatePolicyVerified',
  'independentlyDurableOffsiteCheckpointCasVerified',
  'crossRunForkAbsenceAndAbaRollbackGloballyProven',
  'externallyVerifiedWormObjectLockAndRecovery',
  'independentMcaEmudhraCcaRcaiOrStagingAcceptance',
  'productionReleaseAuthorized'
 ])assert.equal(r[key],false,key);
 assert.equal(r.productionReleaseBlocked,true);
});
test('CX: canonical bytes are domain separated and reject unsupported types',()=>{
 assert.equal(canonical({z:2,a:[true,'hi']}),'{"a":[true,"hi"],"z":2}');
 assert.equal(signingBytes('REVOCATION',{a:1}).toString(),
  'aaditech/phase1cx/readonly-source/v1/REVOCATION/v1\n{"a":1}');
 assert.throws(()=>canonical({a:1.5}),/CX_UNSUPPORTED_CANDIDATE/);
 assert.throws(()=>signingBytes('unknown',{a:1}),/CX_INVALID_SIGNED/);
});
test('CX: IPv4 DNS public-only policy rejects internal, loopback and reserved ranges',()=>{
 for(const ip of ['0.0.0.0','10.1.2.3','127.0.0.1','169.254.169.254',
  '172.16.1.3','172.31.255.255','192.168.1.1','100.64.1.1',
  '198.18.0.1','192.0.2.10','198.51.100.2','203.0.113.1',
  '224.0.0.1','255.255.255.255','::1','2001:db8::1'])
  assert.equal(validPublicIpv4(ip),false,ip);
 assert.equal(validPublicIpv4('8.8.8.8'),true);
 assert.equal(validPublicIpv4('1.1.1.1'),true);
});
test('CX: exact source path and DNS host rejects SSRF and unsupported schemes',()=>{
 const f=fixture();
 for(const edit of [
  s=>s.host='localhost',
  s=>s.host='127.0.0.1',
  s=>s.host='169.254.169.254',
  s=>s.host='metadata.internal',
  s=>s.host='bad.example',
  s=>s.host='evil.com@127.0.0.1',
  s=>s.host='UPPERCASE.Example.com',
  s=>s.host='host..com',
  s=>s.host='foo.com:443',
  s=>s.path='http://bad.com',
  s=>s.path='/v1/revocations/../../admin',
  s=>s.path='/v1/revocations/current.json?token=secret',
  s=>s.path='/v1/checkpoints/latest.json'
 ]){
  const s=structuredClone(f.manifest.sources.REVOCATION);
  edit(s);assert.equal(validateSourceSpec(s,'REVOCATION'),false,JSON.stringify(s));
 }
});
test('CX: wrong signer SPKI or bogus key cannot establish pinned source',()=>{
 for(const update of [
  f=>f.manifest.sources.REVOCATION.signerSpkiSha256='0'.repeat(64),
  f=>f.manifest.sources.WITNESS_A.publicKeyPem='not a key',
  f=>f.manifest.sources.WITNESS_B.keyId='bad id'
 ])deny(update,'CX_OPERATOR_SOURCE_SPEC_UNSAFE_'+(
  update.toString().includes('REVOCATION')?'REVOCATION':
  update.toString().includes('WITNESS_A')?'WITNESS_A':'WITNESS_B'));
});
test('CX: duplicate endpoint host, TLS pin, signer key or key ID is not independent',()=>{
 for(const key of ['host','tlsSpkiSha256','signerSpkiSha256','keyId'])
  deny(f=>{f.manifest.sources.WITNESS_B[key]=f.manifest.sources.WITNESS_A[key]},
   'CX_SOURCE_HOST_OR_KEY_NOT_INDEPENDENT');
});
test('CX: invalid manifest fields, extra role, missing role and same all-zero nonce blocked',()=>{
 for(const update of [
  f=>{f.manifest.repository='other/repo'},
  f=>{f.manifest.nonce='0'.repeat(64)},
  f=>{f.manifest.currentHeadSha='g'.repeat(40)},
  f=>{f.manifest.extra='authorize'},
  f=>{delete f.manifest.sources.REVOCATION},
  f=>{f.manifest.sources.CI_ATTESTOR=f.manifest.sources.WITNESS_A}
 ]){
  const r=assess(update);
  assert.equal(r.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent,false);
 }
});
test('CX: no independently anchored previous epoch or revocation digest means HOLD',()=>{
 for(const edit of [
  f=>{f.manifest.previousAnchor.epoch=-1},
  f=>{f.manifest.previousAnchor.checkpointDigest='0'},
  f=>{f.manifest.previousAnchor.revocationVersion=-1},
  f=>{f.manifest.previousAnchor.revocationDigest='bad'},
  f=>{f.manifest.previousAnchor.observedAt='not-a-time'}
 ])deny(edit,'CX_PREVIOUS_MONOTONIC_ANCHOR_UNTRUSTED');
});
test('CX: revoked currently active signing key invalidates all even with other signatures',()=>{
 for(const role of ROLES){
  deny(f=>{f.observations.REVOCATION.data.statement.revokedKeyIds=[
   f.manifest.sources[role].keyId]},
   'CX_ACTIVE_SOURCE_SIGNER_KEY_REVOKED');
 }
});
test('CX: malformed, duplicate, unsorted, oversized revocation list denied',()=>{
 for(const value of [
  ['z_revoked','a_revoked'],
  ['x_revoked','x_revoked'],
  ['contains spaces'],Array.from({length:33},(_,i)=>'revoked_'+i),
  'all-keys'
 ]){
  deny(f=>{f.observations.REVOCATION.data.statement.revokedKeyIds=value},
   'CX_REVOCATION_KEYS_UNBOUNDED_DUPLICATED_OR_UNSORTED');
 }
});
test('CX: old or skipped checkpoint and revocation versions fail monotonic gate',()=>{
 for(const edit of [
  f=>{f.observations.REVOCATION.data.statement.epoch=7},
  f=>{f.observations.REVOCATION.data.statement.epoch=9},
  f=>{f.observations.REVOCATION.data.statement.checkpointDigest='a'.repeat(64)},
  f=>{f.observations.REVOCATION.data.statement.previousCheckpointDigest='0'.repeat(64)},
  f=>{f.observations.REVOCATION.data.statement.version=9},
  f=>{f.observations.REVOCATION.data.statement.version=11},
  f=>{f.observations.REVOCATION.data.statement.previousVersion=8},
  f=>{f.observations.REVOCATION.data.statement.previousRevocationDigest='0'.repeat(64)}
 ])deny(edit,'CX_REMOTE_REVOCATION_MONOTONIC_SOURCE_OR_FRESHNESS_INVALID');
});
test('CX: expired, future, stale or pre-anchor signed revocation source blocked',()=>{
 for(const edit of [
  f=>{f.now='2026-11-20T00:12:00.000Z'},
  f=>{f.observations.REVOCATION.data.statement.issuedAt='2026-11-19T23:30:00.000Z'},
  f=>{f.observations.REVOCATION.data.statement.expiresAt='2026-11-19T23:59:00.000Z'},
  f=>{f.observations.REVOCATION.data.statement.issuedAt='2026-11-20T01:00:00.000Z'}
 ])deny(edit,'CX_REMOTE_REVOCATION_MONOTONIC_SOURCE_OR_FRESHNESS_INVALID');
});
test('CX: signed source cannot substitute GitHub SHA, freeze hash, CV candidate or nonce',()=>{
 for(const prop of ['sourceHeadSha','policyFingerprintSha256',
  'cvCandidateSha256','nonce']){
  deny(f=>{f.observations.REVOCATION.data.statement[prop]='0'.repeat(
   prop==='sourceHeadSha'?40:64)},
   'CX_REMOTE_REVOCATION_MONOTONIC_SOURCE_OR_FRESHNESS_INVALID');
 }
});
test('CX: changed signature, algorithm, key ID and missing packet block acceptance',()=>{
 for(const edit of [
  f=>{f.observations.REVOCATION.data.signature.signature=
    f.observations.WITNESS_A.data.signature.signature},
  f=>{f.observations.REVOCATION.data.signature.algorithm='HS256'},
  f=>{f.observations.REVOCATION.data.signature.keyId='forged-key'},
  f=>{f.observations.REVOCATION.data.signature.signature='a'.repeat(88)},
  f=>{delete f.observations.REVOCATION.data.signature}
 ])deny(edit,'CX_DETACHED_SIGNED_SOURCE_UNVERIFIABLE_REVOCATION');
});
test('CX: witness A and B checkpoint digest, epoch, source nonce or revocation mismatch',()=>{
 for(const prop of ['checkpointDigest','epoch','sourceHeadSha','nonce',
  'revocationDigest','previousCheckpointDigest']){
  const val=prop==='epoch'?9:'0'.repeat(prop==='sourceHeadSha'?40:64);
  deny(f=>{f.observations.WITNESS_B.data.statement[prop]=val},
   'CX_SIGNED_WITNESS_HEAD_REVOCATION_OR_FRESHNESS_FORK_WITNESS_B');
 }
});
test('CX: witness archival digest, object version or freshness rejects inconsistent source',()=>{
 for(const edit of [
  f=>{f.observations.WITNESS_A.data.statement.archiveDigest='0'.repeat(64)},
  f=>{f.observations.WITNESS_A.data.statement.objectVersion='bad'},
  f=>{f.observations.WITNESS_A.data.statement.observedAt='2026-11-19T23:50:00.000Z'},
  f=>{f.observations.WITNESS_A.data.statement.expiresAt='2026-11-19T23:59:00.000Z'}
 ])deny(edit,'CX_SIGNED_WITNESS_HEAD_REVOCATION_OR_FRESHNESS_FORK_WITNESS_A');
});
test('CX: two signed witnesses cannot claim different non-authorized archive object versions',()=>{
 deny(f=>{
  f.observations.WITNESS_B.data.statement.objectVersion='remote-version-999';
 },'CX_WITNESS_A_B_FORK_OR_OBJECT_VERSION_MISMATCH');
});
test('CX: different read TLS pin or identity fails, even when signature is valid',()=>{
 for(const edit of [
  o=>{o.peerSpkiSha256='0'.repeat(64)},
  o=>{o.status='missing_token'},
  o=>{o.host='attacker.example.com'},
  o=>{o.path='/v1/revocations/attacker.json'},
  o=>{o.httpStatus=307},
  o=>{o.redirectCount=1}
 ])deny(f=>edit(f.observations.REVOCATION),
  'CX_ACTUAL_CANDIDATE_TLS_READ_IDENTITY_UNVERIFIED_REVOCATION');
});
test('CX: missing or extra source results never treated as exact successful quorum',()=>{
 for(const edit of [
  f=>{delete f.observations.WITNESS_B},
  f=>{f.observations.REVOCATION.status='access_denied'},
  f=>{f.observations.REVOCATION.data=null},
  f=>{f.observations.WITNESS_A.data.extra='GO'}
 ]){
  const r=assess(edit);
  assert.equal(r.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CX: unsafe DNS prevents any HTTPS request, including metadata and IPv6 targets',async()=>{
 const spec=fixture().manifest.sources.REVOCATION;
 for(const addr of ['127.0.0.1','169.254.169.254','::1','10.3.2.1']){
  let called=0;
  const response=await fetchPinnedJson(spec,'REVOCATION',{
   lookupImpl:async()=>[{family:addr.includes(':')?6:4,address:addr}],
   requestImpl:()=>{called++;throw Error('should never fetch')}
  });
  assert.equal(response.status,'unsafe_dns');
  assert.equal(called,0);
 }
});
test('CX: DNS failure and malformed source deny before any socket creation',async()=>{
 let called=0;
 const spec=fixture().manifest.sources.REVOCATION;
 const unavailable=await fetchPinnedJson(spec,'REVOCATION',{
  lookupImpl:async()=>{throw Error('no DNS')},
  requestImpl:()=>{called++;throw Error('must not request')}
 });
 assert.equal(unavailable.status,'dns_unavailable');
 const bad=await fetchPinnedJson({...spec,host:'localhost'},'REVOCATION',{
  lookupImpl:async()=>{throw Error('must not lookup')},
  requestImpl:()=>{called++;throw Error('must not request')}
 });
 assert.equal(bad.status,'invalid_spec');
 assert.equal(called,0);
});
test('CX: invalid input manifest does not fetch any operator-supplied endpoint',async()=>{
 const f=fixture();f.manifest.sources.WITNESS_B.host='127.0.0.1';
 let called=0;
 const r=await collectCandidatePinnedReadOnly({
  manifest:f.manifest,now:NOW,
  lookupImpl:async()=>{called++;throw Error('not authorized')},
  requestImpl:()=>{called++;throw Error('not authorized')}
 });
 assert.equal(called,0);
 assert.equal(r.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CX: no real external authority can be introduced via an extra GO field',()=>{
 deny(f=>{f.observations.REVOCATION.data.statement.releaseDecision='GO'},
  'CX_DETACHED_SIGNED_SOURCE_UNVERIFIABLE_REVOCATION');
 const valid=assess();
 assert.equal(JSON.stringify(valid).includes('BEGIN PUBLIC KEY'),false);
 assert.equal(valid.productionReleaseAuthorized,false);
});
