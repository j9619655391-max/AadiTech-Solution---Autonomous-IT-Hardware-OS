import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {REPO,ROLES as SOURCES,canonical,signingBytes} from '../../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {DOMAIN,OFFICERS,candidateBytes} from '../../scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs';

const NOW='2026-11-20T00:00:00.000Z';
const H='d'.repeat(40),BASE='e'.repeat(40),
 POLICY='f'.repeat(64),CV='1'.repeat(64),NONCE='2'.repeat(64);
const dig=x=>createHash('sha256').update(x).digest('hex');
function keyRecord(keyId){
 const pair=generateKeyPairSync('ed25519'),
  pem=pair.publicKey.export({type:'spki',format:'pem'}).toString();
 return {privateKey:pair.privateKey,keyId,publicKeyPem:pem,
  spkiSha256:dig(pair.publicKey.export({type:'spki',format:'der'}))};
}
function signed(type,role,statement,privateKey,keyId){
 return {role,keyId,algorithm:'Ed25519',
  signature:sign(null,Buffer.from(DOMAIN+type+'/'+role+'/v1\n'+
   canonical(statement)),privateKey).toString('base64')};
}
function sourceSigned(role,statement,key){
 return {statement,signature:{keyId:key.keyId,algorithm:'Ed25519',
  signature:sign(null,signingBytes(role,statement),key.privateKey)
   .toString('base64')}};
}
export function fixture(){
 const sources={},observations={},srcKeys={},priorKeys={},officerKeys={};
 for(const [i,role] of SOURCES.entries()){
  const key=keyRecord(role.toLowerCase().replaceAll('_','-')+'-key-v1');
  srcKeys[role]=key;priorKeys[role]=key;
  sources[role]={
   host:['revocation.custody-example.com','witness-a.custody-example.net',
    'witness-b.custody-example.org'][i],
   path:role==='REVOCATION'?'/v1/revocations/current.json':
    '/v1/checkpoints/latest.json',
   tlsSpkiSha256:String(i+3).repeat(64),
   signerSpkiSha256:key.spkiSha256,publicKeyPem:key.publicKeyPem,
   keyId:key.keyId
  };
 }
 const previousAnchor={
  epoch:7,checkpointDigest:'a'.repeat(64),
  revocationVersion:9,revocationDigest:'b'.repeat(64),
  observedAt:'2026-11-19T23:48:00.000Z'
 };
 const manifest={
  schemaVersion:1,repository:REPO,currentHeadSha:H,mainBaseSha:BASE,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,nonce:NONCE,
  previousAnchor:structuredClone(previousAnchor),
  sources:structuredClone(sources)
 };
 const rev={schemaVersion:1,repository:REPO,sourceHeadSha:H,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,
  epoch:8,checkpointDigest:'c'.repeat(64),
  previousCheckpointDigest:'a'.repeat(64),version:10,
  previousVersion:9,previousRevocationDigest:'b'.repeat(64),
  revokedKeyIds:[],nonce:NONCE,
  issuedAt:'2026-11-19T23:55:00.000Z',
  expiresAt:'2026-11-20T00:05:00.000Z'};
 const revDigest=dig(signingBytes('REVOCATION',rev));
 const witness={schemaVersion:1,repository:REPO,sourceHeadSha:H,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,epoch:8,
  checkpointDigest:'c'.repeat(64),
  previousCheckpointDigest:'a'.repeat(64),revocationDigest:revDigest,
  nonce:NONCE,archiveDigest:POLICY,objectVersion:'remote-version-123',
  observedAt:'2026-11-19T23:57:00.000Z',
  expiresAt:'2026-11-20T00:06:00.000Z'};
 const statements={
  REVOCATION:rev,WITNESS_A:structuredClone(witness),
  WITNESS_B:structuredClone(witness)
 };
 for(const role of SOURCES){
  const spec=sources[role],key=srcKeys[role];
  observations[role]={status:'read',host:spec.host,path:spec.path,
   peerSpkiSha256:spec.tlsSpkiSha256,httpStatus:200,redirectCount:0,
   data:sourceSigned(role,statements[role],key)};
 }
 const officers={};
 for(const role of OFFICERS){
  const key=keyRecord(role.toLowerCase().replaceAll('_','-')+'-v1');
  officerKeys[role]=key;
  officers[role]={role,organizationId:'aaditech-candidate-organization',
   githubLogin:role==='SECURITY_OFFICER'?'candidate-security':'candidate-business',
   mandateDigest:role==='SECURITY_OFFICER'?'6'.repeat(64):'7'.repeat(64),
   keyId:key.keyId,publicKeyPem:key.publicKeyPem,
   spkiSha256:key.spkiSha256,
   validFrom:'2026-11-19T22:00:00.000Z',
   validUntil:'2026-11-21T00:00:00.000Z',revoked:false};
 }
 const previous={anchor:structuredClone(previousAnchor),
  sources:structuredClone(sources),officers};
 const statement={
  schemaVersion:1,kind:'CANDIDATE_OPERATOR_PIN_HANDOFF_HOLD',
  repository:REPO,sourceHeadSha:H,mainBaseSha:BASE,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,
  nonce:NONCE,previousEpoch:7,
  previousCheckpointDigest:'a'.repeat(64),previousRevocationVersion:9,
  previousRevocationDigest:'b'.repeat(64),nextEpoch:8,
  nextCheckpointDigest:'c'.repeat(64),nextRevocationVersion:10,
  nextRevocationDigest:revDigest,
  previousSourceDigest:dig(canonical(previous.sources)),
  nextSourceDigest:dig(canonical(manifest.sources)),
  issuedAt:'2026-11-19T23:58:00.000Z',
  expiresAt:'2026-11-20T00:07:00.000Z',
  decision:'HOLD'
 };
 const officerSignatures=OFFICERS.map(role=>
  signed('handoff',role,statement,officerKeys[role].privateKey,
   officerKeys[role].keyId));
 const historicalWitnesses=['WITNESS_A','WITNESS_B'].map(role=>{
  const s={schemaVersion:1,role,repository:REPO,sourceHeadSha:H,
   epoch:7,checkpointDigest:'a'.repeat(64),revocationVersion:9,
   revocationDigest:'b'.repeat(64),challengeNonce:NONCE,
   observedAt:'2026-11-19T23:52:00.000Z'};
  return {statement:s,signature:signed('historical-anchor',role,s,
   priorKeys[role].privateKey,priorKeys[role].keyId)};
 });
 return {manifest,observations,previous,statement,officerSignatures,
  rotations:[],historicalWitnesses,
  incidents:{status:'CLEAR',forkReports:[],recoveryRequested:'NONE'},
  now:NOW,privateState:{srcKeys,priorKeys,officerKeys}};
}
export function rotate(f,role,{signer=true,host=false,tls=false}={}){
 const sp=f.manifest.sources[role],previous=f.previous.sources[role];
 if(signer){
  const newKey=keyRecord(role.toLowerCase().replaceAll('_','-')+'-key-v2');
  f.privateState.srcKeys[role]=newKey;
  sp.keyId=newKey.keyId;
  sp.publicKeyPem=newKey.publicKeyPem;
  sp.signerSpkiSha256=newKey.spkiSha256;
 }
 if(host)sp.host='rotated-'+role.toLowerCase().replaceAll('_','-')+'.custody-example.io';
 if(tls)sp.tlsSpkiSha256='9'.repeat(64);
 const obs=f.observations[role];obs.host=sp.host;
 obs.peerSpkiSha256=sp.tlsSpkiSha256;
 obs.data=sourceSigned(role,obs.data.statement,f.privateState.srcKeys[role]);
 f.statement.nextSourceDigest=dig(canonical(f.manifest.sources));
 f.officerSignatures=OFFICERS.map(r=>signed('handoff',r,f.statement,
  f.privateState.officerKeys[r].privateKey,f.privateState.officerKeys[r].keyId));
 const statement={
  schemaVersion:1,repository:REPO,role,
  handoffDigest:dig(candidateBytes('handoff',f.statement)),
  previousKeyId:previous.keyId,nextKeyId:sp.keyId,
  previousTlsPin:previous.tlsSpkiSha256,nextTlsPin:sp.tlsSpkiSha256,
  previousSignerPin:previous.signerSpkiSha256,nextSignerPin:sp.signerSpkiSha256,
  previousHost:previous.host,nextHost:sp.host,
  previousPath:previous.path,nextPath:sp.path
 };
 const prevKey=f.privateState.priorKeys[role],
  nextKey=f.privateState.srcKeys[role];
 f.rotations.push({role,
  previousSignature:signed('rotation',role,statement,prevKey.privateKey,prevKey.keyId),
  successorSignature:signed('rotation',role,statement,nextKey.privateKey,nextKey.keyId)});
}
