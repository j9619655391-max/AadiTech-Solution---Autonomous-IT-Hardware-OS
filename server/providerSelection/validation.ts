import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ChainInputError,ChainConflictError,exact,sha,ensureId} from '../providerBridge/validation';
import {chainEvidence} from '../evidenceChain/validation';
import {fingerprint} from '../externalTrust/validation';
export {ChainInputError,ChainConflictError,exact,sha,ensureId};
export const PROVIDER={
 code:'EMUDHRA_INDIA_CCA',legalName:'eMudhra Limited',
 authorityUrl:'https://cca.gov.in/CAServicesPublic.html',
 cpsUrl:'https://cca.gov.in/sites/files/pdf/Licensed-CA/eMudhra_4.1.0.pdf',
 registryUrl:'https://www.mca.gov.in/' 
} as const;
export const RELEASE_BLOCKERS=[
 'Provider contract and approved sandbox credentials NOT PROVIDED',
 'Named licensed CA presence is not authorization for this exact business use',
 'Independently authenticated provider-specific root, certificate policy and issuance NOT verified',
 'Official MCA corporate lookup and signatory power NOT independently confirmed',
 'Full RFC5280 production path and trusted CRL/OCSP distribution NOT validated',
 'No supplier-issued PO/ACK, official GRN, operational stock or finance approval'
] as const;
export function nominationBody(value:unknown){
 const v=exact(value,['providerCode','nominationTicket']);
 if(v.providerCode!==PROVIDER.code)throw new ChainInputError('Only CCA-listed named provider candidate is eligible');
 return {providerCode:PROVIDER.code,nominationTicket:chainEvidence(v.nominationTicket)};
}
export function reviewBody(raw:unknown,approved:'REVIEWED_CANDIDATE_HELD'|
 'REVIEWED_POLICY_HELD'|'REVIEWED_CLAIM_HELD',flags:readonly string[]){
 const v=exact(raw,['decision','reason','evidenceRef',...flags]);
 if(v.decision!==approved&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('External trust or production approval is prohibited');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed independent decision reason required');
 for(const k of flags)
  if(typeof v[k]!=='boolean'||(v.decision===approved&&v[k]!==true))
   throw new ChainInputError('Independent inspection and trust gap acknowledgment required');
 return {decision:v.decision as string,reason:v.reason.trim(),
  evidenceRef:chainEvidence(v.evidenceRef),
  flags:flags.map(k=>v[k] as boolean)};
}
export function policyOid(raw:unknown):string{
 if(typeof raw!=='string'||raw.length>96||!/^(?:0|1|2)(?:\.(?:0|[1-9][0-9]{0,8})){2,14}$/.test(raw))
  throw new ChainInputError('Valid provider-approved ASN.1 certificate policy OID required');
 return raw;
}
export function policyBody(raw:unknown){
 const v=exact(raw,['nominationId','certId','policyOid','cpsSha256','purpose']);
 if(v.purpose!=='SUPPLIER_ACK'&&v.purpose!=='WAREHOUSE_GRN')
  throw new ChainInputError('Unsupported supplier/warehouse certificate purpose');
 return {nominationId:ensureId(v.nominationId),certId:ensureId(v.certId),
  policyOid:policyOid(v.policyOid),cpsSha256:fingerprint(v.cpsSha256),
  purpose:v.purpose as 'SUPPLIER_ACK'|'WAREHOUSE_GRN'};
}
export function dossierBody(raw:unknown){
 const v=exact(raw,['nominationId','sandboxCaseId','registryReference',
 'companyMasterDataSha256','signatoryDelegationSha256','sourceEvidenceRef']);
 if(typeof v.registryReference!=='string'||!/^[A-Za-z0-9][A-Za-z0-9 ._/-]{4,95}$/.test(v.registryReference))
  throw new ChainInputError('Canonical existing corporate registration required');
 return {nominationId:ensureId(v.nominationId),sandboxCaseId:ensureId(v.sandboxCaseId),
  registryReference:v.registryReference,
  companyMasterDataSha256:fingerprint(v.companyMasterDataSha256),
  signatoryDelegationSha256:fingerprint(v.signatoryDelegationSha256),
  sourceEvidenceRef:chainEvidence(v.sourceEvidenceRef)};
}
export function accessBody(raw:unknown){
 const v=exact(raw,['nominationId','requestTicket']);
 return {nominationId:ensureId(v.nominationId),requestTicket:chainEvidence(v.requestTicket)};
}
// A strict, nonauthorizing OpenSSL one-hop certificate POLICY dry-run.
// No CRL or OCSP material is supplied or authenticated here. A success MUST
// NEVER be represented as provider legal identity or complete PKIX acceptance.
export function inspectLocalPolicyDryRun(rootPem:string,leafPem:string,oid:string,
 env:NodeJS.ProcessEnv=process.env){
 policyOid(oid);
 if(!(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci')&&
 !(env.NODE_ENV!=='production'&&env.POLICY_DRY_RUN_APPROVED==='YES'&&
   env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&env.DB_SSL==='true'&&
   /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')))
  throw new ChainConflictError('OpenSSL policy dry run restricted to isolated CI/approved TLS staging');
 if(rootPem.length>8192||leafPem.length>8192||
  !rootPem.startsWith('-----BEGIN CERTIFICATE-----')||
  !leafPem.startsWith('-----BEGIN CERTIFICATE-----'))
  throw new ChainInputError('Only bounded PUBLIC X509 certificates may be used');
 const dir=mkdtempSync(join(tmpdir(),'aaditech-policy-'));
 try{
  writeFileSync(join(dir,'trusted.pem'),rootPem,{mode:0o600});
  writeFileSync(join(dir,'end-entity.pem'),leafPem,{mode:0o600});
  let out='';
  try{
   out=execFileSync('openssl',['verify','-CAfile',join(dir,'trusted.pem'),
    '-policy_check','-explicit_policy','-policy',oid,
    '-purpose','any','-x509_strict',join(dir,'end-entity.pem')],
    {encoding:'utf8',timeout:4000,maxBuffer:8192,stdio:['ignore','pipe','pipe']});
  }catch{throw new ChainConflictError('Sandbox OpenSSL PKIX policy check failed');}
  if(!out.includes(': OK'))throw new ChainConflictError('OpenSSL did not confirm requested policy OID');
  return {requestedPolicyOid:oid,oneHopOpenSslPolicyTrialMatched:true,
   externallyAuthenticatedProvider:false,providerPolicyApproved:false,
   trustedCrlOcspValidated:false,productionPathAccepted:false};
 }finally{rmSync(dir,{recursive:true,force:true});}
}
