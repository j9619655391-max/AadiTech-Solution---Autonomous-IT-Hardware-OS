import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {readPin,latestFeed} from '../providerBridge/integrity';
import {inspectIssuer} from '../externalTrust/integrity';
import {ChainConflictError,inspectOneHopCertificateChain,checkDigest} from './validation';
function deny():never{throw new ChainConflictError('External organization, certificate or fresh revocation evidence remains unverified');}
export async function readCase(conn:PoolConnection,id:string,reviewed=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,
  issuer_id AS issuerId,opened_by AS openedBy,purpose,
  registry_reference AS registryReference,
  identity_document_sha256 AS identityDocumentSha256,
  signatory_reference AS signatoryReference,
  signatory_document_sha256 AS signatoryDocumentSha256,
  evidence_ref AS evidenceRef,status,
  corporate_identity_state AS corporateState,
  signatory_authority_state AS signatoryState,
  production_release AS productionRelease
  FROM inv_sandbox_onboarding_cases WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0];
 const pin=await readPin(conn,String(r.pinId));
 const issuer=await inspectIssuer(conn,String(r.issuerId));
 if(r.openedBy!==pin.provisionedBy||r.openedBy!==issuer.registeredBy||
   r.registryReference!==issuer.organizationRegistration||
   (r.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
   (r.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE')||
   r.corporateState!=='UNVERIFIED'||r.signatoryState!=='UNVERIFIED'||
   r.productionRelease!=='HOLD')deny();
 if(reviewed){
  const [decision]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewerId,
   decision,registry_document_inspected AS registryInspected,
   signatory_document_inspected AS signatoryInspected
   FROM inv_sandbox_case_reviews WHERE case_id=?`,[id]);
  if(r.status!=='REVIEWED_EVIDENCE_HELD'||decision.length!==1||
   decision[0].decision!=='REVIEWED_EVIDENCE_HELD'||
   decision[0].reviewerId===r.openedBy||
   Number(decision[0].registryInspected)!==1||
   Number(decision[0].signatoryInspected)!==1)deny();
 }
 return {id,openedBy:String(r.openedBy),pin,issuer,purpose:String(r.purpose),
  registryReference:String(r.registryReference),
  identityDocumentSha256:String(r.identityDocumentSha256),
  signatoryReference:String(r.signatoryReference),
  signatoryDocumentSha256:String(r.signatoryDocumentSha256),
  status:String(r.status)};
}
export async function readCert(conn:PoolConnection,id:string,reviewed=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,case_id AS caseId,
  imported_by AS importedBy,ca_certificate_pem AS caPem,
  leaf_certificate_pem AS leafPem,
  ca_certificate_sha256 AS caDigest,leaf_certificate_sha256 AS leafDigest,
  leaf_spki_sha256 AS leafSpki,leaf_serial AS leafSerial,status,
  provider_issued_authenticated AS providerAuthenticated,
  rfc5280_path_validated AS pathValidated
  FROM inv_sandbox_cert_packages WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0],caseData=await readCase(conn,String(r.caseId),true);
 if(r.importedBy!==caseData.openedBy||r.providerAuthenticated!=='NO'||
  r.pathValidated!=='NO'||r.status!=='CERT_SIGNATURE_MATCHED_HELD')deny();
 const crypto=inspectOneHopCertificateChain(String(r.caPem),String(r.leafPem),
  caseData.pin.rootFingerprint,caseData.issuer.fingerprint);
 if(crypto.rootCertSha256!==r.caDigest||crypto.leafCertSha256!==r.leafDigest||
   crypto.leafSpkiSha256!==r.leafSpki||crypto.leafSerial!==r.leafSerial)deny();
 if(reviewed){
  const [review]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewerId,
   decision,certificate_inspected AS inspected,policy_gaps_acknowledged AS gaps
   FROM inv_sandbox_cert_reviews WHERE cert_id=?`,[id]);
  if(review.length!==1||review[0].decision!=='REVIEWED_CRYPTO_HELD'||
   review[0].reviewerId===r.importedBy||
   Number(review[0].inspected)!==1||Number(review[0].gaps)!==1)deny();
 }
 return {id,caseData,crypto,importedBy:String(r.importedBy)};
}
export async function sandboxReadiness(conn:PoolConnection,id:string){
 const cert=await readCert(conn,id,true);
 const feed=await latestFeed(conn,cert.caseData.pin.id);
 if(feed.fingerprints.includes(cert.crypto.leafSpkiSha256)||
    feed.fingerprints.includes(cert.caseData.issuer.fingerprint))deny();
 const snapshot={certId:id,certificateSha256:cert.crypto.leafCertSha256,
  leafKeySha256:cert.crypto.leafSpkiSha256,feedId:feed.id,sequence:feed.sequenceNumber,
  issuedRootFingerprint:cert.caseData.pin.rootFingerprint,caseId:cert.caseData.id,
  productionReady:false,stockPostingState:'DISABLED'};
 return {cert,feed,snapshot,digest:checkDigest(snapshot),
  oneHopCertificateSignatureMatched:true,fullRfc5280PathValidated:false,
  actualProviderIssuanceAuthenticated:false,corporateIdentityVerified:false,
  authorizedSignatoryVerified:false,revocationPublisherVerified:false,
  officialGrnVerified:false,stockPostingEnabled:false,
  availableToSell:null,productionReady:false};
}
