import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {readNomination,readPolicy,readDossier,readiness as previousReadiness} from '../providerSelection/integrity';
import {ChainConflictError,offlineSignedRevocationCheck,AO_BLOCKERS} from './validation';
function deny():never{throw new ChainConflictError('Provider sandbox legal/security/revocation prerequisite is not authenticated');}
export async function readPacket(c:PoolConnection,id:string,dual=false){
 const [rows]=await c.query<RowDataPacket[]>(`SELECT id,nomination_id AS nomId,
  prepared_by AS owner,contract_document_sha256 AS contractDigest,
  provider_onboarding_ref AS ref,sandbox_scope_ref AS scope,status,
  contract_authentication AS contractAuth,sandbox_secret_state AS secretState,
  provider_credential_authentication AS credentialAuth,production_release AS releaseState
  FROM inv_provider_ao_packets WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 const nom=await readNomination(c,String(r.nomId),true);
 if(nom.owner!==r.owner||r.contractAuth!=='UNVERIFIED'||r.secretState!=='NOT_CONFIGURED'||
  r.credentialAuth!=='NO'||r.releaseState!=='HOLD'||r.status==='REJECTED_INTERNAL')deny();
 const [checks]=await c.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
  review_role AS role,decision,no_external_contract_ack AS contractAck,
  no_live_credentials_ack AS credentialsAck
  FROM inv_provider_ao_packet_reviews WHERE packet_id=? FOR UPDATE`,[id]);
 const kinds=new Set(checks.map(v=>v.role)),actors=new Set(checks.map(v=>v.reviewer));
 if(checks.some(v=>v.reviewer===r.owner||
    (v.decision==='INSPECTED_HELD'&&
     (Number(v.contractAck)!==1||Number(v.credentialsAck)!==1)))||
    actors.size!==checks.length||kinds.size!==checks.length)deny();
 if(dual&&(r.status!=='DUAL_REVIEWED_HELD'||checks.length!==2||
  !kinds.has('LEGAL')||!kinds.has('SECURITY')||
  checks.some(v=>v.decision!=='INSPECTED_HELD')))deny();
 return {id,nom,owner:String(r.owner),status:String(r.status),
  contractDigest:String(r.contractDigest),reviews:checks.length};
}
export async function readTrial(c:PoolConnection,id:string){
 const [rows]=await c.query<RowDataPacket[]>(`SELECT id,packet_id AS packetId,
  policy_id AS policyId,prepared_by AS actor,requested_policy_oid AS oid,
  root_certificate_sha256 AS rootSha,leaf_certificate_sha256 AS leafSha,
  status,provider_chain_authenticated AS chainAuth,
  real_issuer_status AS issuerAuth,trusted_crl_ocsp AS trustedRevocation
  FROM inv_provider_ao_pkix_trials WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 const packet=await readPacket(c,String(r.packetId),true);
 const policy=await readPolicy(c,String(r.policyId),true);
 if(r.actor!==packet.owner||policy.preparedBy!==packet.owner||
  packet.nom.id!==policy.nom.id||r.oid!==policy.policyOid||
  r.rootSha!==policy.cert.crypto.rootCertSha256||
  r.leafSha!==policy.cert.crypto.leafCertSha256||
  r.status!=='OFFLINE_CRYPTO_HELD'||r.chainAuth!=='NO'||
  r.issuerAuth!=='UNVERIFIED'||r.trustedRevocation!=='NO')deny();
 const [pem]=await c.query<RowDataPacket[]>(`SELECT ca_certificate_pem AS root,
  leaf_certificate_pem AS leaf FROM inv_sandbox_cert_packages
  WHERE id=? FOR UPDATE`,[policy.cert.id]);
 if(pem.length!==1)deny();
 return {id,packet,policy,root:String(pem[0].root),leaf:String(pem[0].leaf)};
}
export async function readArtifact(c:PoolConnection,id:string,reviewed=false){
 const [rows]=await c.query<RowDataPacket[]>(`SELECT id,trial_id AS trialId,
  imported_by AS actor,artifact_type AS kind,
  artifact_der_b64 AS data,artifact_sha256 AS digest,
  status,issuer_authority_verified AS issuerAuth,
  external_publisher_authenticated AS publisherAuth,serial_status AS serialStatus
  FROM inv_provider_ao_revocation_trials WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0],trial=await readTrial(c,String(r.trialId));
 if(r.actor!==trial.packet.owner||r.status!=='SIGNED_OFFLINE_HELD'||
  r.issuerAuth!=='NO'||r.publisherAuth!=='NO'||r.serialStatus!=='CRYPTO_GOOD_ONLY')deny();
 const crypto=offlineSignedRevocationCheck(r.kind,String(r.data),trial.root,trial.leaf);
 if(crypto.artifactSha256!==r.digest)deny();
 if(reviewed){
  const [review]=await c.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,decision,
   issuer_provenance_missing_ack AS missing FROM inv_provider_ao_revocation_reviews
   WHERE artifact_id=? FOR UPDATE`,[id]);
  if(review.length!==1||review[0].reviewer===r.actor||
   review[0].decision!=='CRYPTO_REVIEWED_HELD'||Number(review[0].missing)!==1)deny();
 }
 return {id,kind:r.kind as 'CRL'|'OCSP',trial,crypto};
}
export async function readMca(c:PoolConnection,id:string,reviewed=false){
 const [rows]=await c.query<RowDataPacket[]>(`SELECT id,packet_id AS packetId,
  dossier_id AS dossierId,prepared_by AS actor,
  mca_master_data_sha256 AS master,signatory_mandate_sha256 AS mandate,
  verification_ticket AS ticket,status,registry_authenticated AS registryAuth,
  signatory_authorized AS signatoryAuth
  FROM inv_provider_ao_mca_evidence WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();const r=rows[0];
 const packet=await readPacket(c,String(r.packetId),true);
 const dossier=await readDossier(c,String(r.dossierId),true);
 if(packet.nom.id!==dossier.nom.id||r.actor!==packet.owner||
  r.registryAuth!=='NO'||r.signatoryAuth!=='NO'||r.status==='REJECTED_INTERNAL')deny();
 if(reviewed){
  const [decision]=await c.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,external_mca_auth_missing_ack AS registryAck,
   signatory_auth_missing_ack AS signerAck FROM inv_provider_ao_mca_reviews
   WHERE mca_id=? FOR UPDATE`,[id]);
  if(r.status!=='INTERNALLY_INSPECTED_HELD'||decision.length!==1||
   decision[0].reviewer===r.actor||decision[0].decision!=='INSPECTED_HELD'||
   Number(decision[0].registryAck)!==1||Number(decision[0].signerAck)!==1)deny();
 }
 return {id,packet,dossier,preparedBy:String(r.actor),master:String(r.master),
  mandate:String(r.mandate),status:String(r.status)};
}
export async function readiness(c:PoolConnection,trialId:string,mcaId:string){
 const trial=await readTrial(c,trialId);
 const mca=await readMca(c,mcaId,true);
 if(mca.packet.id!==trial.packet.id||mca.dossier.record.id!==trial.policy.cert.caseData.id)deny();
 await previousReadiness(c,trial.policy.id,mca.dossier.id); // freshly signed root feed; no revoked source
 const [arts]=await c.query<RowDataPacket[]>(`SELECT id,artifact_type AS kind
  FROM inv_provider_ao_revocation_trials WHERE trial_id=? ORDER BY artifact_type FOR UPDATE`,[trialId]);
 if(arts.length!==2||arts[0].kind===arts[1].kind)deny();
 for(const a of arts)await readArtifact(c,String(a.id),true);
 return {provider:trial.packet.nom.providerName,
  separateLegalAndSecurityReviews:true,
  offlineOneHopPolicySignatureMatched:true,offlineCrlSignatureMatched:true,
  offlineOcspSignatureMatched:true,
  actualProviderContractVerified:false,approvedEderivedSandboxCredentialsPresent:false,
  independentMcaCorporateIdentityVerified:false,authorizedLegalSignatoryVerified:false,
  trustedCAIdentityVerified:false,authenticatedExternalCrlOcspPublisher:false,
  fullRfc5280ProductionPath:false,productionReady:false,stockPostingEnabled:false,
  officialGrnVerified:false,availableToSell:null,blockers:[...AO_BLOCKERS]};
}
