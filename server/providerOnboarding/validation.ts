import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {exact,ensureId,ChainInputError,ChainConflictError,sha} from '../providerBridge/validation';
import {fingerprint} from '../externalTrust/validation';
import {chainEvidence} from '../evidenceChain/validation';
import {RELEASE_BLOCKERS} from '../providerSelection/validation';
export {ChainInputError,ChainConflictError,exact,ensureId,sha};
export const CCA_CURRENT_CPS_REFERENCE='https://cca.gov.in/sites/files/pdf/Licensed-CA/eMudhra%204.2.0_signed.pdf';
export const AO_BLOCKERS=[...RELEASE_BLOCKERS,
 'No externally signed eMudhra sandbox agreement, authenticated API credentials or trusted provider enrollment',
 'No independently authenticated real MCA company record or legally delegated supplier/warehouse signer',
 'No independently authenticated CA/OCSP responder/CRL publisher or approved production certificate policy',
 'No genuine signed supplier PO/ACK, official physical GRN or stock release authority'] as const;
export function packetBody(raw:unknown){
 const v=exact(raw,['nominationId','contractDocumentSha256','providerOnboardingRef','sandboxScopeRef']);
 return {nominationId:ensureId(v.nominationId),contractDocumentSha256:fingerprint(v.contractDocumentSha256),
  providerOnboardingRef:chainEvidence(v.providerOnboardingRef),
  sandboxScopeRef:chainEvidence(v.sandboxScopeRef)};
}
function decision(raw:unknown,positive:string,keys:string[]){
 const v=exact(raw,['decision','reason','evidenceRef',...keys]);
 if(v.decision!==positive&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Production approval or actual external verification is not permitted');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed independent review reason required');
 for(const k of keys)if(typeof v[k]!=='boolean'||(v.decision===positive&&v[k]!==true))
  throw new ChainInputError('Explicit independently attested missing authority required');
 return {decision:v.decision as string,reason:v.reason.trim(),evidenceRef:chainEvidence(v.evidenceRef),
  flags:keys.map(k=>v[k] as boolean)};
}
export function packetReviewBody(raw:unknown){
 const v=exact(raw,['reviewRole','decision','reason','evidenceRef',
  'noExternalContractAcknowledged','noLiveCredentialsAcknowledged']);
 if(v.reviewRole!=='LEGAL'&&v.reviewRole!=='SECURITY')
  throw new ChainInputError('Separate LEGAL and SECURITY roles required');
 return {reviewRole:v.reviewRole as 'LEGAL'|'SECURITY',
  ...decision({decision:v.decision,reason:v.reason,evidenceRef:v.evidenceRef,
   noExternalContractAcknowledged:v.noExternalContractAcknowledged,
   noLiveCredentialsAcknowledged:v.noLiveCredentialsAcknowledged},
   'INSPECTED_HELD',['noExternalContractAcknowledged','noLiveCredentialsAcknowledged'])};
}
export function trialBody(raw:unknown){
 const v=exact(raw,['packetId','policyId']);
 return {packetId:ensureId(v.packetId),policyId:ensureId(v.policyId)};
}
export function revocationBody(raw:unknown){
 const v=exact(raw,['trialId','artifactType','artifactDerB64']);
 if(v.artifactType!=='CRL'&&v.artifactType!=='OCSP')
  throw new ChainInputError('Offline signed DER CRL or OCSP only');
 if(typeof v.artifactDerB64!=='string'||v.artifactDerB64.length>90_000||
  v.artifactDerB64.length<32||v.artifactDerB64.length%4!==0||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(v.artifactDerB64))
  throw new ChainInputError('Canonical bounded DER base64 required');
 const rawDer=Buffer.from(v.artifactDerB64,'base64');
 if(rawDer.length>65536||rawDer.length<24||rawDer.toString('base64')!==v.artifactDerB64)
  throw new ChainInputError('Canonical 64 KiB maximum DER required');
 return {trialId:ensureId(v.trialId),artifactType:v.artifactType as 'CRL'|'OCSP',
  artifactDerB64:v.artifactDerB64,digest:createHash('sha256').update(rawDer).digest('hex')};
}
export function artifactReviewBody(raw:unknown){
 return decision(raw,'CRYPTO_REVIEWED_HELD',['issuerProvenanceMissingAcknowledged']);
}
export function mcaBody(raw:unknown){
 const v=exact(raw,['packetId','dossierId','mcaMasterDataSha256',
  'signatoryMandateSha256','verificationTicket']);
 return {packetId:ensureId(v.packetId),dossierId:ensureId(v.dossierId),
  mcaMasterDataSha256:fingerprint(v.mcaMasterDataSha256),
  signatoryMandateSha256:fingerprint(v.signatoryMandateSha256),
  verificationTicket:chainEvidence(v.verificationTicket)};
}
export function mcaReviewBody(raw:unknown){
 return decision(raw,'INSPECTED_HELD',
  ['externalMcaAuthenticationMissingAcknowledged','signatoryAuthorityMissingAcknowledged']);
}
export function isolatedSandbox(env:NodeJS.ProcessEnv=process.env):boolean{
 return (env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci')||
 (env.NODE_ENV!=='production'&&env.PROVIDER_AO_OFFLINE_TRIAL_APPROVED==='YES'&&
  env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&env.DB_SSL==='true'&&
  /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''));
}
export function offlineSignedRevocationCheck(kind:'CRL'|'OCSP',artifactDerB64:string,
 rootPem:string,leafPem:string,env:NodeJS.ProcessEnv=process.env){
 if(!isolatedSandbox(env))throw new ChainConflictError('Only isolated disposable CI or approved TLS staging may check offline revocation');
 if(rootPem.length>8192||leafPem.length>8192||
  !rootPem.startsWith('-----BEGIN CERTIFICATE-----')||
  !leafPem.startsWith('-----BEGIN CERTIFICATE-----'))
  throw new ChainInputError('Public X509 PEM required');
 const artifact=Buffer.from(artifactDerB64,'base64');
 if(artifact.length>65536)throw new ChainInputError('DER artifact too large');
 const dir=mkdtempSync(join(tmpdir(),'aaditech-revocation-'));
 const run=(args:string[])=>{
  const x=spawnSync('openssl',args,{cwd:dir,encoding:'utf8',
   timeout:4000,maxBuffer:16_384,stdio:['ignore','pipe','pipe']});
  if(x.error||x.status!==0)throw new ChainConflictError('Offline OpenSSL check rejected');
  return x.stdout+'\n'+x.stderr;
 };
 try{
  writeFileSync(join(dir,'root.pem'),rootPem,{mode:0o600});
  writeFileSync(join(dir,'leaf.pem'),leafPem,{mode:0o600});
  writeFileSync(join(dir,'response.der'),artifact,{mode:0o600});
  if(kind==='CRL'){
   run(['crl','-inform','DER','-in','response.der','-out','response.pem']);
   const valid=run(['crl','-in','response.pem','-noout','-verify','-CAfile','root.pem']);
   if(!valid.includes('verify OK'))throw Error('CRL signature not verified');
   const check=run(['verify','-crl_check','-CAfile','root.pem',
    '-CRLfile','response.pem','leaf.pem']);
   if(!check.includes(': OK'))throw Error('CRL rejected leaf certificate');
  }else{
   const output=run(['ocsp','-respin','response.der','-issuer','root.pem',
    '-cert','leaf.pem','-CAfile','root.pem','-no_nonce',
    '-validity_period','300','-status_age','3600']);
   if(!output.includes('Response verify OK')||!/leaf\.pem: good\b/.test(output))
    throw Error('Responder not cryptographically verified as good');
  }
  return {artifactSha256:createHash('sha256').update(artifact).digest('hex'),
   signedArtifactMathVerified:true,offlineOnly:true,
   actualExternalPublisherAuthenticated:false,realIssuerTrusted:false,
   realWorldCertificateStatusVerified:false,productionReady:false};
 }catch{throw new ChainConflictError('Offline CRL/OCSP signature, freshness or unrevoked status did not validate');}
 finally{rmSync(dir,{recursive:true,force:true});}
}
