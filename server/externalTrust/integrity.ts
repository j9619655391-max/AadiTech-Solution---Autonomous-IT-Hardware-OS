import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {candidatePublicKey,verifyDeepFrozenSnapshot} from '../proofFoundation/validation';
import {independentlyReviewedPossession} from '../keyLifecycle/integrity';
import {ChainConflictError,authorityMessage,revocationMessage,
 digest,verifySigned,validateRevocation,type Party,type Purpose} from './validation';
function deny():never{throw new ChainConflictError('Unverified, frozen, invalid or tampered external trust prerequisite');}
function dbJson(v:unknown):unknown{
 if(typeof v==='string'){try{return JSON.parse(v);}catch{deny();}}
 return v;
}
export async function inspectIssuer(conn:PoolConnection,id:string,reviewed=true){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,party_kind AS partyKind,
  party_id AS partyId,registered_by AS registeredBy,
  issuer_spki_b64 AS issuerSpkiB64,fingerprint_sha256 AS fingerprint,
  organization_registration AS organizationRegistration,
  status,external_root_state AS externalRootState
  FROM inv_external_issuer_candidates WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const row=rows[0],parsed=candidatePublicKey(row.issuerSpkiB64);
 if(parsed.fingerprint!==row.fingerprint||row.externalRootState!=='UNVERIFIED'||
  !['SUPPLIER','WAREHOUSE'].includes(row.partyKind))deny();
 const [frozen]=await conn.query<RowDataPacket[]>(`SELECT issuer_id FROM inv_external_issuer_freezes
  WHERE issuer_id=? FOR UPDATE`,[id]);
 if(frozen.length)deny();
 if(reviewed){
  if(row.status!=='REVIEWED_HELD')deny();
  const [checks]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewerId,
   decision,registry_inspected AS inspected FROM inv_external_issuer_reviews
   WHERE issuer_id=?`,[id]);
  if(checks.length!==1||checks[0].decision!=='REVIEWED_HELD'||
   checks[0].reviewerId===row.registeredBy||Number(checks[0].inspected)!==1)deny();
 }
 return {id:String(row.id),partyKind:row.partyKind as Party,partyId:String(row.partyId),
  registeredBy:String(row.registeredBy),status:String(row.status),
  organizationRegistration:String(row.organizationRegistration),
  fingerprint:String(row.fingerprint),key:parsed.publicKey};
}
export async function inspectAuthority(conn:PoolConnection,id:string,reviewed=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,issuer_id AS issuerId,
  key_id AS keyId,prepared_by AS preparedBy,purpose,
  DATE_FORMAT(valid_from,'%Y-%m-%dT%H:%i:%s.000Z') AS validFrom,
  DATE_FORMAT(valid_until,'%Y-%m-%dT%H:%i:%s.000Z') AS validUntil,
  statement_sha256 AS digest,statement_json AS payload,signature_b64 AS signature,
  status,external_authority_state AS externalAuthorityState,stock_posting AS stockPosting
  FROM inv_external_authority_attestations WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0],issuer=await inspectIssuer(conn,String(r.issuerId));
 const key=await independentlyReviewedPossession(conn,String(r.keyId));
 if(issuer.partyKind!==key.key.partyKind||issuer.partyId!==key.key.partyId||
  issuer.registeredBy!==key.key.registeredBy||
  r.preparedBy!==issuer.registeredBy||
  (r.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
  (r.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE')||
  r.externalAuthorityState!=='UNVERIFIED'||r.stockPosting!=='DISABLED')deny();
 const expected=authorityMessage({issuerId:issuer.id,issuerFingerprint:issuer.fingerprint,
  keyId:key.key.id,keyFingerprint:key.key.fingerprint,partyKind:issuer.partyKind,
  partyId:issuer.partyId,organizationRegistration:issuer.organizationRegistration,
  purpose:r.purpose as Purpose,validFrom:r.validFrom,validUntil:r.validUntil});
 if(r.digest!==digest(expected)||!verifySigned(expected,issuer.key,String(r.signature)))deny();
 verifyDeepFrozenSnapshot(r.payload,expected,String(r.digest));
 if(Date.parse(String(r.validUntil))<=Date.now()||
    Date.parse(String(r.validFrom))>Date.now()+5*60_000)deny();
 if(reviewed){
  if(r.status!=='REVIEWED_CRYPTO_HELD')deny();
  const [reviews]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewerId,
   decision,signature_inspected AS inspected FROM inv_external_authority_reviews
   WHERE attestation_id=?`,[id]);
  if(reviews.length!==1||reviews[0].reviewerId===r.preparedBy||
   reviews[0].decision!=='REVIEWED_CRYPTO_HELD'||Number(reviews[0].inspected)!==1)deny();
 }
 return {id,issuer,key:key.key,purpose:r.purpose as Purpose,status:String(r.status),
  message:expected,digest:String(r.digest)};
}
export async function inspectLatestRevocations(conn:PoolConnection,issuerId:string){
 const issuer=await inspectIssuer(conn,issuerId);
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,sequence_number AS sequenceNumber,
  DATE_FORMAT(issued_at,'%Y-%m-%dT%H:%i:%s.000Z') AS issuedAt,
  DATE_FORMAT(expires_at,'%Y-%m-%dT%H:%i:%s.000Z') AS expiresAt,
  manifest_sha256 AS digest,manifest_json AS manifest,signature_b64 AS signature,
  status,external_publisher_authenticated AS publisher
  FROM inv_external_revocation_bundles WHERE issuer_id=?
  ORDER BY sequence_number DESC LIMIT 1 FOR UPDATE`,[issuerId]);
 if(rows.length!==1)deny();
 const r=rows[0];
 if(r.status!=='SIGNED_UNTRUSTED'||r.publisher!=='NO'||
  Date.parse(String(r.expiresAt))<=Date.now()||
  Date.parse(String(r.issuedAt))>Date.now()+5*60_000)deny();
 const raw=dbJson(r.manifest) as Record<string,unknown>;
 if(!raw||typeof raw!=='object'||!Array.isArray(raw.revokedFingerprints))deny();
 const v=validateRevocation({issuerId,sequenceNumber:Number(r.sequenceNumber),
  issuedAt:r.issuedAt,expiresAt:r.expiresAt,
  revokedFingerprints:raw.revokedFingerprints,signatureB64:r.signature});
 const expected=revocationMessage({...v,issuerFingerprint:issuer.fingerprint,
  partyKind:issuer.partyKind,partyId:issuer.partyId});
 if(digest(expected)!==r.digest||!verifySigned(expected,issuer.key,String(r.signature)))deny();
 verifyDeepFrozenSnapshot(r.manifest,expected,String(r.digest));
 const [entries]=await conn.query<RowDataPacket[]>(`SELECT key_fingerprint_sha256 AS fingerprint
  FROM inv_external_revocation_entries WHERE bundle_id=?
  ORDER BY key_fingerprint_sha256`,[r.id]);
 if(entries.length!==v.revokedFingerprints.length||
  entries.some((x,i)=>x.fingerprint!==v.revokedFingerprints[i]))deny();
 return {issuer,bundleId:String(r.id),sequenceNumber:v.sequenceNumber,
  expiresAt:v.expiresAt,revokedFingerprints:v.revokedFingerprints};
}
export async function inspectReadiness(conn:PoolConnection,authorityId:string){
 const attestation=await inspectAuthority(conn,authorityId,true);
 const latest=await inspectLatestRevocations(conn,attestation.issuer.id);
 if(latest.revokedFingerprints.includes(attestation.key.fingerprint))deny();
 return {attestationId:authorityId,revocationSequence:latest.sequenceNumber,
  revocationValidUntil:latest.expiresAt,
  cryptographicallyConsistentInternalEvidence:true,
  issuerExternallyAuthenticated:false,organizationAuthorityVerified:false,
  officialGrnVerified:false,stockPostingEnabled:false,productionReady:false};
}
