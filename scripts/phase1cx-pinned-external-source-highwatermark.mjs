import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify,X509Certificate} from 'node:crypto';
import {lookup as dnsLookup} from 'node:dns/promises';
import {lstatSync,readFileSync} from 'node:fs';
import https from 'node:https';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1CX: strictly read-only OPERATOR candidate remote-source intake.
// TLS and detached signatures can be checked locally, but the pins, identities,
// high-watermark and source addresses are provided by the operator: none is
// independently enrolled or legally authenticated here. Always release HOLD.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const ROLES=Object.freeze(['REVOCATION','WITNESS_A','WITNESS_B']);
export const DOMAIN='aaditech/phase1cx/readonly-source/v1/';
const HEX=/^[0-9a-f]{64}$/,SHA=/^[0-9a-f]{40}$/,
 KEY=/^[a-z][a-z0-9._-]{5,79}$/,SIG=/^[A-Za-z0-9+/]{86}==$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>own(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const safe=x=>Number.isSafeInteger(x)&&x>0;
const hash=x=>createHash('sha256').update(x).digest('hex');
const when=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
export function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')
  return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(own(x))return '{'+Object.keys(x).sort().map(k=>
  JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw Error('CX_UNSUPPORTED_CANDIDATE_CANONICAL_TYPE');
}
export function signingBytes(role,statement){
 if(!ROLES.includes(role)||!own(statement)||
    JSON.stringify(statement).length>8192)
  throw Error('CX_INVALID_SIGNED_SOURCE_ROLE_OR_SIZE');
 return Buffer.from(DOMAIN+role+'/v1\n'+canonical(statement),'utf8');
}
const FIELDS={
 manifest:['schemaVersion','repository','currentHeadSha','mainBaseSha',
  'policyFingerprintSha256','cvCandidateSha256','nonce',
  'previousAnchor','sources'],
 anchor:['epoch','checkpointDigest','revocationVersion',
  'revocationDigest','observedAt'],
 spec:['host','path','tlsSpkiSha256','signerSpkiSha256','publicKeyPem','keyId'],
 observation:['status','host','path','peerSpkiSha256','httpStatus',
  'redirectCount','data'],
 packet:['statement','signature'],
 sig:['keyId','algorithm','signature'],
 rev:['schemaVersion','repository','sourceHeadSha','policyFingerprintSha256',
  'cvCandidateSha256','epoch','checkpointDigest','previousCheckpointDigest',
  'version','previousVersion','previousRevocationDigest','revokedKeyIds',
  'nonce','issuedAt','expiresAt'],
 witness:['schemaVersion','repository','sourceHeadSha',
  'policyFingerprintSha256','cvCandidateSha256','epoch',
  'checkpointDigest','previousCheckpointDigest','revocationDigest',
  'nonce','archiveDigest','objectVersion','observedAt','expiresAt']
};
export function validPublicIpv4(ip){
 if(isIP(ip)!==4)return false;  // Explicit IPv6 hard stop in this handoff.
 const a=ip.split('.').map(Number),[p,q,r]=a;
 return p>=1&&p<=223&&
  p!==10&&p!==127&&p!==0&&
  !(p===100&&q>=64&&q<=127)&&
  !(p===169&&q===254)&&
  !(p===172&&q>=16&&q<=31)&&
  !(p===192&&(q===168||q===0||q===88||q===18||q===19||q===0))&&
  !(p===198&&(q===18||q===19||q===51&&r===100))&&
  !(p===203&&q===0&&r===113)&&
  !(p===192&&q===0&&r===2)&&
  !(p===192&&q===52&&r===193);
}
function validHost(host){
 return typeof host==='string'&&host.length<=253&&host.length>=7&&
  !isIP(host)&&/^[a-z0-9.-]+$/.test(host)&&!host.includes('..')&&
  host.split('.').every(s=>s.length>=1&&s.length<=63&&
   /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s))&&
  /\.[a-z]{2,15}$/.test(host)&&
  !/\.(?:local|localhost|internal|invalid|example|test)$/.test(host);
}
export function validateSourceSpec(spec,role){
 if(!exact(spec,FIELDS.spec)||!ROLES.includes(role)||!validHost(spec.host)||
    typeof spec.path!=='string'||spec.path.length>160||
    !new RegExp(role==='REVOCATION'?
     '^/v1/revocations/[a-z0-9_-]{1,80}\\.json$':
     '^/v1/checkpoints/[a-z0-9_-]{1,80}\\.json$').test(spec.path)||
    !HEX.test(spec.tlsSpkiSha256??'')||
    !HEX.test(spec.signerSpkiSha256??'')||
    !KEY.test(spec.keyId??'')||
    typeof spec.publicKeyPem!=='string'||spec.publicKeyPem.length>4096)
  return false;
 try{
  const pub=createPublicKey(spec.publicKeyPem);
  return pub.asymmetricKeyType==='ed25519'&&
   hash(pub.export({format:'der',type:'spki'}))===spec.signerSpkiSha256;
 }catch{return false;}
}
export function assessManifest(manifest){
 const issues=new Set();
 if(!exact(manifest,FIELDS.manifest)||manifest.schemaVersion!==1||
    manifest.repository!==REPO||!SHA.test(manifest.currentHeadSha??'')||
    !SHA.test(manifest.mainBaseSha??'')||
    !HEX.test(manifest.policyFingerprintSha256??'')||
    !HEX.test(manifest.cvCandidateSha256??'')||
    !HEX.test(manifest.nonce??'')||
    manifest.nonce==='0'.repeat(64))
  issues.add('CX_OPERATOR_MANIFEST_SOURCE_OR_SCHEMA_INVALID');
 const prev=manifest?.previousAnchor;
 if(!exact(prev,FIELDS.anchor)||!Number.isSafeInteger(prev.epoch)||
    prev.epoch<0||!HEX.test(prev.checkpointDigest??'')||
    !Number.isSafeInteger(prev.revocationVersion)||
    prev.revocationVersion<0||!HEX.test(prev.revocationDigest??'')||
    !Number.isFinite(when(prev.observedAt)))
  issues.add('CX_PREVIOUS_MONOTONIC_ANCHOR_UNTRUSTED');
 if(!exact(manifest?.sources,ROLES))
  issues.add('CX_EXACT_THREE_CANDIDATE_SOURCES_REQUIRED');
 const hosts=new Set(),tlsPins=new Set(),signerPins=new Set(),ids=new Set();
 for(const role of ROLES){
  const spec=manifest?.sources?.[role];
  if(!validateSourceSpec(spec,role))
   issues.add('CX_OPERATOR_SOURCE_SPEC_UNSAFE_'+role);
  if(spec&&typeof spec==='object'){
   for(const [set,key] of [
    [hosts,'host'],[tlsPins,'tlsSpkiSha256'],
    [signerPins,'signerSpkiSha256'],[ids,'keyId']]){
    const value=spec[key];
    if(set.has(value))issues.add('CX_SOURCE_HOST_OR_KEY_NOT_INDEPENDENT');
    if(typeof value==='string')set.add(value);
   }
  }
 }
 return Object.freeze({
  candidateSourceManifestStructurallyValid:issues.size===0,
  anomalyCodes:Object.freeze([...issues].sort()),
  realIndependentKeyEnrollmentAuthenticated:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function healthyTime(start,end,now){
 const s=when(start),e=when(end);
 return Number.isFinite(s)&&Number.isFinite(e)&&Number.isFinite(now)&&
  s>=now-900000&&s<=now+300000&&e>now&&e>s&&e-s<=900000;
}
function verifiedPacket(role,entry,spec){
 if(!exact(entry,FIELDS.packet)||!exact(entry.signature,FIELDS.sig)||
    entry.signature.keyId!==spec?.keyId||
    entry.signature.algorithm!=='Ed25519'||
    !SIG.test(entry.signature.signature??''))
  return false;
 try{
  const bytes=Buffer.from(entry.signature.signature,'base64');
  return bytes.length===64&&
   bytes.toString('base64')===entry.signature.signature&&
   verify(null,signingBytes(role,entry.statement),
    createPublicKey(spec.publicKeyPem),bytes);
 }catch{return false;}
}
export function assessCandidateRemoteQuorum({
 manifest=null,observations={},now='2026-11-20T00:00:00.000Z'
}={}){
 const errors=new Set(assessManifest(manifest).anomalyCodes);
 const today=when(now);
 if(!Number.isFinite(today))errors.add('CX_VERIFICATION_CLOCK_INVALID');
 const prev=manifest?.previousAnchor,seen=new Set(),statements={};
 for(const role of ROLES){
  const spec=manifest?.sources?.[role],obs=observations?.[role];
  if(!validateSourceSpec(spec,role)||!exact(obs,FIELDS.observation)||
     obs.status!=='read'||obs.host!==spec.host||obs.path!==spec.path||
     obs.peerSpkiSha256!==spec.tlsSpkiSha256||
     obs.httpStatus!==200||obs.redirectCount!==0)
   errors.add('CX_ACTUAL_CANDIDATE_TLS_READ_IDENTITY_UNVERIFIED_'+role);
  const packet=obs?.data;
  if(!verifiedPacket(role,packet,spec))
   errors.add('CX_DETACHED_SIGNED_SOURCE_UNVERIFIABLE_'+role);
  else seen.add(role);
  statements[role]=packet?.statement;
 }
 const rev=statements.REVOCATION;
 if(!exact(rev,FIELDS.rev)||rev.schemaVersion!==1||
    rev.repository!==REPO||rev.sourceHeadSha!==manifest?.currentHeadSha||
    rev.policyFingerprintSha256!==manifest?.policyFingerprintSha256||
    rev.cvCandidateSha256!==manifest?.cvCandidateSha256||
    !HEX.test(rev.checkpointDigest??'')||
    rev.checkpointDigest===prev?.checkpointDigest||
    rev.previousCheckpointDigest!==prev?.checkpointDigest||
    rev.epoch!==prev?.epoch+1||!Number.isSafeInteger(rev.epoch)||
    rev.epoch<1||rev.version!==prev?.revocationVersion+1||
    rev.previousVersion!==prev?.revocationVersion||
    rev.previousRevocationDigest!==prev?.revocationDigest||
    rev.nonce!==manifest?.nonce||
    !healthyTime(rev.issuedAt,rev.expiresAt,today)||
    when(rev.issuedAt)<=when(prev?.observedAt))
  errors.add('CX_REMOTE_REVOCATION_MONOTONIC_SOURCE_OR_FRESHNESS_INVALID');
 const revoked=rev?.revokedKeyIds;
 const validRevoked=Array.isArray(revoked)&&revoked.length<=32&&
  revoked.every(x=>typeof x==='string'&&KEY.test(x))&&
  new Set(revoked).size===revoked.length&&
  JSON.stringify(revoked)===JSON.stringify([...revoked].sort());
 if(!validRevoked)errors.add('CX_REVOCATION_KEYS_UNBOUNDED_DUPLICATED_OR_UNSORTED');
 if(ROLES.some(role=>(revoked??[])?.includes?.(manifest?.sources?.[role]?.keyId)))
  errors.add('CX_ACTIVE_SOURCE_SIGNER_KEY_REVOKED');
 const revDigest=exact(rev,FIELDS.rev)?hash(signingBytes('REVOCATION',rev)):null;
 const fields=['epoch','checkpointDigest','previousCheckpointDigest','nonce',
  'archiveDigest','objectVersion'];
 for(const role of ['WITNESS_A','WITNESS_B']){
  const s=statements[role];
  if(!exact(s,FIELDS.witness)||s.schemaVersion!==1||
     s.repository!==REPO||s.sourceHeadSha!==manifest?.currentHeadSha||
     s.policyFingerprintSha256!==manifest?.policyFingerprintSha256||
     s.cvCandidateSha256!==manifest?.cvCandidateSha256||
     s.epoch!==rev?.epoch||s.checkpointDigest!==rev?.checkpointDigest||
     s.previousCheckpointDigest!==prev?.checkpointDigest||
     s.revocationDigest!==revDigest||s.nonce!==manifest?.nonce||
     !HEX.test(s.archiveDigest??'')||
     s.archiveDigest!==manifest?.policyFingerprintSha256||
     !/^[a-z][a-z0-9._-]{5,79}$/.test(s.objectVersion??'')||
     !healthyTime(s.observedAt,s.expiresAt,today)||
     when(s.observedAt)<when(rev?.issuedAt))
    errors.add('CX_SIGNED_WITNESS_HEAD_REVOCATION_OR_FRESHNESS_FORK_'+role);
 }
 const a=statements.WITNESS_A,b=statements.WITNESS_B;
 if(!a||!b||fields.some(k=>a[k]!==b[k])||
    a.revocationDigest!==b.revocationDigest)
  errors.add('CX_WITNESS_A_B_FORK_OR_OBJECT_VERSION_MISMATCH');
 const technicallyConsistent=errors.size===0&&seen.size===3;
 const handoff={
  head:manifest?.currentHeadSha??null,base:manifest?.mainBaseSha??null,
  previousDigest:prev?.checkpointDigest??null,
  nextDigest:rev?.checkpointDigest??null,
  epoch:rev?.epoch??null,
  revocationDigest:revDigest,archiveObjectVersion:a?.objectVersion??null
 };
 return Object.freeze({
  phase:'1CX',schemaVersion:1,
  kind:'PINNED_HTTPS_SIGNED_REVOCATION_AND_TWO_WITNESSES_CANDIDATE_HARD_HOLD',
  repository:REPO,
  candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent:
   technicallyConsistent,
  locallyMatchedSignedSourceCount:seen.size,
  currentSourceHeadSha:technicallyConsistent?manifest.currentHeadSha:null,
  candidateHandoffDigestSha256:hash(canonical(handoff)),
  anomalyCodes:Object.freeze([...errors].sort()),
  // Not proven even after actual HTTPS reads without independent trust roots.
  externallyMandatedTrustAnchorAndRoleEnrollmentVerified:false,
  remoteTlsPinsIndependentlyAuthenticated:false,
  independentlyApprovedRevocationAndCertificatePolicyVerified:false,
  independentlyDurableOffsiteCheckpointCasVerified:false,
  crossRunForkAbsenceAndAbaRollbackGloballyProven:false,
  externallyVerifiedWormObjectLockAndRecovery:false,
  independentMcaEmudhraCcaRcaiOrStagingAcceptance:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
// A pinned HTTPS request has to satisfy TLS CA+hostname verification, SHA-256
// of the *actual peer leaf* SPKI, public-only DNS resolution, and no redirects.
// No auth headers, no POST, no proxy URL, no private/IPv6 address, no arbitrary
// route, no cookies, no token reads. Abort after 6.5s or 64 KiB.
export async function fetchPinnedJson(spec,role,{
 lookupImpl=dnsLookup,requestImpl=https.request
}={}){
 if(!validateSourceSpec(spec,role))
  return {status:'invalid_spec',host:spec?.host??null};
 let resolved;
 try{
  const rows=await lookupImpl(spec.host,{all:true,verbatim:true});
  if(!Array.isArray(rows)||rows.length===0||rows.length>16||
     rows.some(r=>r.family!==4||!validPublicIpv4(r.address)))
   return {status:'unsafe_dns',host:spec.host};
  resolved=rows[0].address;
 }catch{return {status:'dns_unavailable',host:spec.host};}
 return new Promise(done=>{
  let finished=false,pinned=false;
  const finish=x=>{if(!finished){finished=true;done(x);}};
  const deny=status=>finish({status,host:spec.host,path:spec.path});
  const req=requestImpl({
   protocol:'https:',hostname:spec.host,servername:spec.host,port:443,
   method:'GET',path:spec.path,agent:false,rejectUnauthorized:true,
   timeout:6500,
   lookup:(_host,_opts,cb)=>cb(null,resolved,4),
   headers:{
    Accept:'application/json',
    'User-Agent':'AadiTech-Phase1CX-ReadOnly-External-Candidate'
   }
  },res=>{
   if(!pinned){res.destroy();deny('tls_pin_unverified');return;}
   const len=res.headers?.['content-length'];
   if(res.statusCode!==200||
      typeof res.headers?.['content-type']!=='string'||
      !/^application\/(?:json|[a-z0-9.+-]*\+json)(?:;|$)/i.test(
       res.headers['content-type'])||
      res.headers?.['content-encoding']&&
       res.headers['content-encoding']!=='identity'||
      len!==undefined&&(!/^\d+$/.test(String(len))||Number(len)>65536)){
    res.destroy();deny('http_status_headers_or_redirect_invalid');return;
   }
   const parts=[];let count=0;
   res.on('data',chunk=>{
    count+=chunk.length;
    if(count>65536){res.destroy();deny('body_oversize');return;}
    parts.push(chunk);
   });
   res.on('end',()=>{
    if(finished)return;
    try{
     const data=JSON.parse(Buffer.concat(parts).toString('utf8'));
     if(!own(data))throw Error('not object');
     finish({status:'read',host:spec.host,path:spec.path,
      peerSpkiSha256:spec.tlsSpkiSha256,httpStatus:200,
      redirectCount:0,data});
    }catch{deny('invalid_json');}
   });
   res.on('error',()=>deny('stream_failure'));
  });
  req.on('socket',socket=>{
   socket.on('secureConnect',()=>{
    try{
     if(!socket.authorized||socket.authorizationError)throw Error('tls');
     const cert=socket.getPeerCertificate(true);
     if(!cert?.raw)throw Error('no certificate');
     const leaf=new X509Certificate(cert.raw);
     const spki=hash(leaf.publicKey.export({type:'spki',format:'der'}));
     if(spki!==spec.tlsSpkiSha256)throw Error('pin');
     pinned=true;
    }catch{req.destroy();deny('tls_pin_or_ca_invalid');}
   });
  });
  req.on('error',()=>deny('request_unavailable'));
  req.on('timeout',()=>{req.destroy();deny('request_timeout');});
  req.end();
 });
}
export async function collectCandidatePinnedReadOnly({
 manifest,lookupImpl=dnsLookup,requestImpl=https.request,
 now=new Date().toISOString()
}={}){
 const decision=assessManifest(manifest);
 if(!decision.candidateSourceManifestStructurallyValid)
  return assessCandidateRemoteQuorum({manifest,observations:{},now});
 const observations={};
 for(const role of ROLES)
  observations[role]=await fetchPinnedJson(manifest.sources[role],role,{
   lookupImpl,requestImpl});
 return assessCandidateRemoteQuorum({manifest,observations,now});
}
function localJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('CX_UNAPPROVED_OPERATOR_FILE_PATH');
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>131072)
  throw Error('CX_UNSAFE_OR_OVERSIZE_OPERATOR_MANIFEST');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    !['--offline-verify','--operator-readonly-pinned-https'].includes(args[0]))
  throw Error('CX_ONLY_EXPLICIT_OFFLINE_OR_APPROVED_HUMAN_READONLY_MODE');
 const file=localJson(args[1]);
 const result=args[0]==='--offline-verify'?
  assessCandidateRemoteQuorum({
   manifest:file.manifest,observations:file.observations,
   now:new Date().toISOString()
  }):
  await collectCandidatePinnedReadOnly({
   manifest:file,now:new Date().toISOString()
  });
 console.log(JSON.stringify(result,null,2));
 if(!result.candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CX independently unapproved trust source HOLD:',
   error instanceof Error?error.message:'Unknown');process.exitCode=1;
 });
