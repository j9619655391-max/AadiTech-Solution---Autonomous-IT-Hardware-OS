import {isDeepStrictEqual} from 'node:util';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {inspectIssuer} from '../externalTrust/integrity';
import {candidatePublicKey} from '../proofFoundation/validation';
import {ChainConflictError,pinConfig,credentialMessage,feedMessage,
 digest,verify,validateFeed,type Pin} from './validation';
function deny():never{throw new ChainConflictError('Provider root pin, organization credential or revocation source not authenticated');}
function decode(raw:unknown):unknown{
 if(typeof raw==='string'){try{return JSON.parse(raw);}catch{deny();}}
 return raw;
}
export async function readPin(conn:PoolConnection,id:string,reviewed=true):Promise<Pin>{
 // A trusted root MUST originate outside user CRUD. No application route writes pins
 // other than an exact match to separately managed environment configuration.
 const configured=pinConfig(process.env);
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,provider_code AS providerCode,
  provider_origin AS origin,root_spki_b64 AS spkiB64,
  root_fingerprint_sha256 AS rootFingerprint,tls_spki_sha256 AS tlsFingerprint,
  provisioned_by AS provisionedBy,status,external_root_state AS externalRootState
  FROM inv_provider_pin_candidates WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0],key=candidatePublicKey(r.spkiB64);
 if(key.fingerprint!==r.rootFingerprint||r.rootFingerprint!==configured.rootFingerprint||
  r.spkiB64!==configured.spkiB64||r.tlsFingerprint!==configured.tlsFingerprint||
  r.origin!==configured.origin||r.providerCode!==configured.providerCode||
  r.externalRootState!=='UNVERIFIED')deny();
 const [freeze]=await conn.query<RowDataPacket[]>(`SELECT pin_id FROM inv_provider_pin_freezes
  WHERE pin_id=? FOR UPDATE`,[id]);
 if(freeze.length)deny();
 if(reviewed){
  const [v]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,pin_inspected AS inspected FROM inv_provider_pin_reviews WHERE pin_id=?`,[id]);
  if(r.status!=='REVIEWED_HELD'||v.length!==1||
   v[0].reviewer===r.provisionedBy||v[0].decision!=='REVIEWED_HELD'||
   Number(v[0].inspected)!==1)deny();
 }
 return {id,providerCode:configured.providerCode,origin:configured.origin,
  spkiB64:configured.spkiB64,rootFingerprint:configured.rootFingerprint,
  tlsFingerprint:configured.tlsFingerprint,publicKey:configured.publicKey,
  provisionedBy:String(r.provisionedBy),status:String(r.status)};
}
export async function signedOrg(conn:PoolConnection,id:string,requireReview=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,issuer_id AS issuerId,
  submitted_by AS submitter,purpose,
  DATE_FORMAT(valid_from,'%Y-%m-%dT%H:%i:%s.000Z') AS validFrom,
  DATE_FORMAT(valid_until,'%Y-%m-%dT%H:%i:%s.000Z') AS validUntil,
  message_sha256 AS digest,message_json AS payload,signature_b64 AS signature,
  status,corporate_identity_state AS corporateState,external_issuer_state AS externalIssuerState,
  stock_posting AS stockPosting
  FROM inv_provider_org_credentials WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0],pin=await readPin(conn,String(r.pinId));
 const issuer=await inspectIssuer(conn,String(r.issuerId));
 if(pin.provisionedBy!==r.submitter||issuer.registeredBy!==r.submitter||
  r.corporateState!=='UNVERIFIED'||r.externalIssuerState!=='UNVERIFIED'||
  r.stockPosting!=='DISABLED'||
  (r.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
  (r.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE'))deny();
 const msg=credentialMessage({pinId:pin.id,providerCode:pin.providerCode,
  providerOrigin:pin.origin,rootFingerprint:pin.rootFingerprint,
  issuerId:issuer.id,issuerFingerprint:issuer.fingerprint,
  partyKind:issuer.partyKind,partyId:issuer.partyId,
  organizationRegistration:issuer.organizationRegistration,
  purpose:r.purpose,validFrom:r.validFrom,validUntil:r.validUntil});
 if(!isDeepStrictEqual(decode(r.payload),msg)||digest(msg)!==r.digest||
  !verify(msg,pin.publicKey,String(r.signature))||
  Date.parse(String(r.validUntil))<=Date.now()||
  Date.parse(String(r.validFrom))>Date.now()+300_000)deny();
 if(requireReview){
  const [reviews]=await conn.query<RowDataPacket[]>(`SELECT reviewer_id AS reviewer,
   decision,source_inspected AS inspected FROM inv_provider_org_reviews WHERE credential_id=?`,[id]);
  if(reviews.length!==1||r.status!=='REVIEWED_CRYPTO_HELD'||
   reviews[0].reviewer===r.submitter||
   reviews[0].decision!=='REVIEWED_CRYPTO_HELD'||Number(reviews[0].inspected)!==1)deny();
 }
 return {id,pin,issuer,submitter:String(r.submitter),status:String(r.status),
  purpose:String(r.purpose),message:msg,digest:String(r.digest)};
}
export async function latestFeed(conn:PoolConnection,pinId:string){
 const pin=await readPin(conn,pinId);
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,sequence_number AS seq,
  DATE_FORMAT(published_at,'%Y-%m-%dT%H:%i:%s.000Z') AS publishedAt,
  DATE_FORMAT(valid_until,'%Y-%m-%dT%H:%i:%s.000Z') AS validUntil,
  message_sha256 AS digest,message_json AS payload,
  signature_b64 AS signature,status,external_publisher_state AS publisherState
  FROM inv_provider_revocation_feeds WHERE pin_id=?
  ORDER BY sequence_number DESC LIMIT 1 FOR UPDATE`,[pinId]);
 if(rows.length!==1)deny();
 const r=rows[0],payload=decode(r.payload) as Record<string,unknown>;
 if(!payload||!Array.isArray(payload.revokedFingerprints)||r.status!=='SIGNED_CANDIDATE'||
  r.publisherState!=='UNVERIFIED'||Date.parse(String(r.validUntil))<=Date.now()||
  Date.parse(String(r.publishedAt))>Date.now()+300_000)deny();
 const parsed=validateFeed({pinId,sequenceNumber:Number(r.seq),
  publishedAt:r.publishedAt,validUntil:r.validUntil,
  revokedFingerprints:payload.revokedFingerprints,signatureB64:r.signature});
 const msg=feedMessage({...parsed,providerCode:pin.providerCode,
  providerOrigin:pin.origin,rootFingerprint:pin.rootFingerprint});
 if(!isDeepStrictEqual(payload,msg)||digest(msg)!==r.digest||
  !verify(msg,pin.publicKey,String(r.signature)))deny();
 const [entries]=await conn.query<RowDataPacket[]>(`SELECT revoked_fingerprint_sha256 AS fingerprint
  FROM inv_provider_revocation_entries WHERE feed_id=?
  ORDER BY revoked_fingerprint_sha256`,[r.id]);
 if(entries.length!==parsed.revokedFingerprints.length||
  entries.some((row,i)=>String(row.fingerprint)!==parsed.revokedFingerprints[i]))deny();
 return {id:String(r.id),sequenceNumber:parsed.sequenceNumber,validUntil:parsed.validUntil,
  fingerprints:parsed.revokedFingerprints,pin};
}
export async function internalReadiness(conn:PoolConnection,credentialId:string){
 const credential=await signedOrg(conn,credentialId,true);
 const revocations=await latestFeed(conn,credential.pin.id);
 if(revocations.fingerprints.includes(credential.issuer.fingerprint))deny();
 return {credentialId,revocationSequence:revocations.sequenceNumber,
  revocationValidUntil:revocations.validUntil,
  cryptographicSourceConsistent:true,externalProviderAuthenticated:false,
  corporateIdentityVerified:false,credentialIssuanceExternallyAuthenticated:false,
  trustedRevocationPublisherVerified:false,officialGrnVerified:false,
  stockPostingEnabled:false,productionReady:false,availableToSell:null};
}
