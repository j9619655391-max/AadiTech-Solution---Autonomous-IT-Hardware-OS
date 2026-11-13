import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {readCert,readCase,sandboxReadiness} from '../providerSandbox/integrity';
import {ChainConflictError,PROVIDER,inspectLocalPolicyDryRun,
 RELEASE_BLOCKERS} from './validation';
function deny():never{throw new ChainConflictError('Named provider not independently approved or evidence altered');}
export async function readNomination(conn:PoolConnection,id:string,reviewed=true){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,provider_code AS providerCode,
  legal_name AS legalName,regulatory_source_url AS sourceUrl,
  opened_by AS owner,nomination_ticket AS ticket,status,
  provider_contract AS contract,sandbox_credentials AS credentials,
  external_root_authenticated AS rootAuthenticated,production_release AS releaseState
  FROM inv_provider_named_nominations WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 if(r.providerCode!==PROVIDER.code||r.legalName!==PROVIDER.legalName||
   r.sourceUrl!==PROVIDER.authorityUrl||r.contract!=='NOT_APPROVED'||
   r.credentials!=='NOT_PROVIDED'||r.rootAuthenticated!=='NO'||
   r.releaseState!=='HOLD'||r.status!=='NOMINATED_HELD')deny();
 if(reviewed){
  const [checks]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,official_listing_inspected AS inspected,
   contract_missing_acknowledged AS missing FROM inv_provider_named_reviews
   WHERE nomination_id=? FOR UPDATE`,[id]);
  if(checks.length!==1||checks[0].reviewer===r.owner||
    checks[0].decision!=='REVIEWED_CANDIDATE_HELD'||
    Number(checks[0].inspected)!==1||Number(checks[0].missing)!==1)deny();
 }
 return {id,owner:String(r.owner),providerCode:PROVIDER.code,providerName:PROVIDER.legalName,
  sourceUrl:PROVIDER.authorityUrl,status:String(r.status),externalTrustEstablished:false};
}
export async function readPolicy(conn:PoolConnection,id:string,requireReview=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,nomination_id AS nominationId,
  cert_id AS certId,prepared_by AS actor,policy_oid AS oid,
  cps_sha256 AS cpsSha,cps_source_url AS cpsUrl,purpose,status,
  full_certification_path AS fullPath,trusted_crl_ocsp AS crlOcsp,
  provider_policy_approved AS providerApproved FROM inv_provider_policy_proposals
  WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 const nom=await readNomination(conn,String(r.nominationId));
 const cert=await readCert(conn,String(r.certId),true);
 if(r.actor!==nom.owner||r.actor!==cert.importedBy||
   r.cpsUrl!==PROVIDER.cpsUrl||r.purpose!==cert.caseData.purpose||
   r.status!=='PROFILE_HELD'||r.fullPath!=='NOT_VALIDATED'||
   r.crlOcsp!=='NOT_VALIDATED'||r.providerApproved!=='NO')deny();
 const [cRows]=await conn.query<RowDataPacket[]>(`SELECT ca_certificate_pem AS rootPem,
  leaf_certificate_pem AS leafPem FROM inv_sandbox_cert_packages
  WHERE id=? FOR UPDATE`,[r.certId]);
 if(cRows.length!==1)deny();
 // Only an approved isolated CI/staging process can run the OpenSSL policy
 // trial. This is NOT production PKIX, missing revocation sources and legal KYC.
 const trial=inspectLocalPolicyDryRun(String(cRows[0].rootPem),String(cRows[0].leafPem),String(r.oid));
 if(requireReview){
  const [checks]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,policy_oid_inspected AS inspected,
   missing_crl_ocsp_acknowledged AS missing FROM inv_provider_policy_reviews
   WHERE policy_id=? FOR UPDATE`,[id]);
  if(checks.length!==1||checks[0].reviewer===r.actor||
   checks[0].decision!=='REVIEWED_POLICY_HELD'||
   Number(checks[0].inspected)!==1||Number(checks[0].missing)!==1)deny();
 }
 return {id,nom,cert,policyOid:String(r.oid),cpsSha256:String(r.cpsSha),
  preparedBy:String(r.actor),trial,productionReady:false};
}
export async function readDossier(conn:PoolConnection,id:string,requireReview=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,nomination_id AS nominationId,
  sandbox_case_id AS caseId,prepared_by AS actor,registry_source_url AS sourceUrl,
  company_master_data_sha256 AS masterSha,
  signatory_delegation_sha256 AS delegationSha,
  registry_reference AS registryRef,source_evidence_ref AS evidence,
  status,registry_authentication AS registryAuth,
  legal_signatory_authentication AS signatoryAuth
  FROM inv_provider_registry_dossiers WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 const nom=await readNomination(conn,String(r.nominationId));
 const record=await readCase(conn,String(r.caseId),true);
 if(r.actor!==nom.owner||r.actor!==record.openedBy||
  r.sourceUrl!==PROVIDER.registryUrl||r.registryRef!==record.registryReference||
  r.registryAuth!=='UNVERIFIED'||r.signatoryAuth!=='UNVERIFIED'||
  !['EVIDENCE_PENDING_EXTERNAL','INTERNALLY_INSPECTED_HELD'].includes(r.status))deny();
 if(requireReview){
  const [checks]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,registry_source_inspected AS registryInspected,
   delegation_source_inspected AS delegationInspected FROM inv_provider_registry_reviews
   WHERE dossier_id=? FOR UPDATE`,[id]);
  if(r.status!=='INTERNALLY_INSPECTED_HELD'||checks.length!==1||
   checks[0].reviewer===r.actor||checks[0].decision!=='REVIEWED_CLAIM_HELD'||
   Number(checks[0].registryInspected)!==1||
   Number(checks[0].delegationInspected)!==1)deny();
 }
 return {id,nom,record,preparedBy:String(r.actor),registryRef:String(r.registryRef),
  masterSha256:String(r.masterSha),delegationSha256:String(r.delegationSha),
  evidence:String(r.evidence),status:String(r.status),corporateIdentityVerified:false,
  legalSignatoryVerified:false};
}
export async function readiness(conn:PoolConnection,policyId:string,dossierId:string){
 const p=await readPolicy(conn,policyId,true);
 const d=await readDossier(conn,dossierId,true);
 if(d.nom.id!==p.nom.id||d.record.id!==p.cert.caseData.id)deny();
 // Re-read the freshest pinned-root signed revocation evidence. Even a
 // previously reviewed one-hop policy trial cannot resurrect revoked keys.
 await sandboxReadiness(conn,p.cert.id);
 const [gate]=await conn.query<RowDataPacket[]>(`SELECT secret_reference_status AS secretState,
  provider_authorization AS providerAuth,live_test_access AS testAccess,
  production_release AS releaseState FROM inv_provider_sandbox_access_gates
  WHERE nomination_id=? FOR UPDATE`,[p.nom.id]);
 if(gate.length!==1||gate[0].secretState!=='NOT_CONFIGURED'||
  gate[0].providerAuth!=='NOT_VERIFIED'||gate[0].testAccess!=='DISABLED'||
  gate[0].releaseState!=='HOLD')deny();
 return {namedProvider:p.nom.providerName,providerCode:p.nom.providerCode,
  officialCaListingCandidate:true,openSslPolicyTrialMatched:true,
  providerContractApproved:false,approvedSandboxCredentialsPresent:false,
  registryIndependentlyVerified:false,signatoryLegalAuthorityVerified:false,
  certificateIssuerAuthenticityVerified:false,fullRfc5280ProductionPath:false,
  authoritativeCrlOcspValidated:false,productionReady:false,officialGrnVerified:false,
  stockPostingEnabled:false,availableToSell:null,
  blockers:[...RELEASE_BLOCKERS]};
}
