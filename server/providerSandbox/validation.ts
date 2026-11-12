import {X509Certificate,createHash} from 'node:crypto';
import {exact,ChainInputError,ChainConflictError,ensureId,sha,type Purpose} from '../providerBridge/validation';
import {organizationReference,fingerprint} from '../externalTrust/validation';
import {chainEvidence} from '../evidenceChain/validation';
export {ChainInputError,ChainConflictError,exact,sha};
export function caseBody(raw:unknown){
 const v=exact(raw,['pinId','issuerId','purpose','registryReference',
  'identityDocumentSha256','signatoryReference','signatoryDocumentSha256','evidenceRef']);
 if(v.purpose!=='SUPPLIER_ACK'&&v.purpose!=='WAREHOUSE_GRN')
  throw new ChainInputError('Only supplier ACK or warehouse GRN sandbox purpose accepted');
 if(typeof v.signatoryReference!=='string'||!/^[A-Za-z0-9][A-Za-z0-9 _./:#-]{7,159}$/.test(v.signatoryReference))
  throw new ChainInputError('Sanitized internal signatory authority reference required');
 return {pinId:ensureId(v.pinId),issuerId:ensureId(v.issuerId),
  purpose:v.purpose as Purpose,registryReference:organizationReference(v.registryReference),
  identityDocumentSha256:fingerprint(v.identityDocumentSha256),
  signatoryReference:v.signatoryReference,
  signatoryDocumentSha256:fingerprint(v.signatoryDocumentSha256),
  evidenceRef:chainEvidence(v.evidenceRef)};
}
function decisionInputs(raw:unknown,approved:string,inspectionKeys:string[]){
 const v=exact(raw,['decision','reason','evidenceRef',...inspectionKeys]);
 if(v.decision!==approved&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Cannot certify external authority from an internal review');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed independent reviewer reason required');
 for(const k of inspectionKeys)
  if(typeof v[k]!=='boolean'||(v.decision===approved&&v[k]!==true))
   throw new ChainInputError('Independent document/policy inspection attestation missing');
 return {decision:v.decision as string,reason:v.reason.trim(),evidenceRef:chainEvidence(v.evidenceRef),
  inspected:inspectionKeys.map(k=>v[k] as boolean)};
}
export function reviewCaseBody(v:unknown){
 const x=decisionInputs(v,'REVIEWED_EVIDENCE_HELD',['registryInspected','signatoryInspected']);
 return {...x,registryInspected:x.inspected[0],signatoryInspected:x.inspected[1]};
}
export function reviewCertBody(v:unknown){
 const x=decisionInputs(v,'REVIEWED_CRYPTO_HELD',['certificateInspected','policyGapsAcknowledged']);
 return {...x,certificateInspected:x.inspected[0],policyGapsAcknowledged:x.inspected[1]};
}
function pem(raw:unknown):string{
 if(typeof raw!=='string'||raw.length>8192||raw.length<250||
   !/^-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{1,64}={0,2}\n)+-----END CERTIFICATE-----\n?$/.test(raw))
  throw new ChainInputError('One canonical PEM PUBLIC X509 certificate required (max 8 KiB)');
 return raw.endsWith('\n')?raw:raw+'\n';
}
export function certificateBody(raw:unknown){
 const v=exact(raw,['caseId','rootCertificatePem','leafCertificatePem']);
 return {caseId:ensureId(v.caseId),rootCertificatePem:pem(v.rootCertificatePem),
  leafCertificatePem:pem(v.leafCertificatePem)};
}
export function inspectOneHopCertificateChain(rootPem:string,leafPem:string,
 expectedRootSpki:string,expectedLeafSpki:string,atMs=Date.now()){
 let root:X509Certificate,leaf:X509Certificate;
 try{
  root=new X509Certificate(rootPem);leaf=new X509Certificate(leafPem);
 }catch{throw new ChainConflictError('Invalid or unsupported X509 DER/PEM certificate chain');}
 const rootPublic=root.publicKey.export({format:'der',type:'spki'}) as Buffer;
 const leafPublic=leaf.publicKey.export({format:'der',type:'spki'}) as Buffer;
 const rootSha=createHash('sha256').update(rootPublic).digest('hex'),
  leafSha=createHash('sha256').update(leafPublic).digest('hex');
 if(rootSha!==expectedRootSpki||leafSha!==expectedLeafSpki||
    root.publicKey.asymmetricKeyType!=='ed25519'||
    leaf.publicKey.asymmetricKeyType!=='ed25519'||
    !root.ca||leaf.ca||root.subject!==root.issuer||
    !root.verify(root.publicKey)||!leaf.checkIssued(root)||!leaf.verify(root.publicKey)||
    root.raw.equals(leaf.raw))
  throw new ChainConflictError('Untrusted one-hop CA signature, root pin, or leaf public key mismatch');
 const start=Date.parse(leaf.validFrom),end=Date.parse(leaf.validTo),
  rootStart=Date.parse(root.validFrom),rootEnd=Date.parse(root.validTo);
 if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start||
    atMs<start||atMs>=end||atMs<rootStart||atMs>=rootEnd||
    start<rootStart||end>rootEnd)
  throw new ChainConflictError('Certificate expired, not-yet-valid or outside pinned CA validity');
 if(!/^[A-Fa-f0-9]{2,128}$/.test(leaf.serialNumber))
  throw new ChainConflictError('Unsupported X509 serial number');
 return {rootCertSha256:createHash('sha256').update(root.raw).digest('hex'),
  leafCertSha256:createHash('sha256').update(leaf.raw).digest('hex'),
  rootSpkiSha256:rootSha,leafSpkiSha256:leafSha,
  leafSerial:leaf.serialNumber,notBefore:new Date(start).toISOString(),
  notAfter:new Date(end).toISOString(),
  oneHopSignatureValid:true,
  rfc5280FullPathValidated:false,providerRealIdentityAuthenticated:false};
}
export function checkDigest(input:object){return sha(JSON.stringify(input));}
