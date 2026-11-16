import {createHash,createPublicKey,verify} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';

// Phase 1BB is offline, digest-only intake interoperability. A caller-supplied
// SPKI pin and nonce NEVER authenticate a witness organization, issuer, KMS,
// storage service, legally authorized signatory or independent challenge.
export const BB_PURPOSE='AADITECH_PHASE_1BB_EXTERNAL_EVIDENCE_INTAKE_HOLD_V1';
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const BODY=['schemaVersion','purpose','packetSha256','logRef','sourceRole',
 'sourceRef','authorityRef','keyId','publicKeySha256','challengeSha256',
 'subjectSha256','evidenceSha256','issuedAt','expiresAt','authorityState','releaseDecision'];
const PIN=['role','sourceRef','authorityRef','keyId','publicKeyPem','publicKeySha256'];
const DETACHED=['sourceRef','keyId','signatureBase64'];
const RECORD=['body','pin','signature'];
const BASE=['EXTERNAL_PUBLISHER_AUTHORIZATION_UNVERIFIED',
 'INDEPENDENT_WITNESS_KEY_CUSTODY_NOT_AUTHENTICATED',
 'INDEPENDENT_CHALLENGE_ISSUANCE_UNVERIFIED',
 'IMMUTABLE_OBJECT_LOCK_PROVIDER_RECEIPTS_UNVERIFIED',
 'ACTUAL_ENCRYPTED_RESTORE_AND_LEGAL_SIGNOFF_PENDING'];
const REQUIRED=['WITNESS','WITNESS','STORAGE_AUDITOR','SECURITY','OPERATIONS','OWNER'];

function exact(o,fields){
 if(!o||typeof o!=='object'||Array.isArray(o)||
    Object.getPrototypeOf(o)!==Object.prototype||
    Object.keys(o).length!==fields.length||
    Object.keys(o).some(k=>!fields.includes(k)))
  throw Error('1BB only accepts exact digest-only evidence schemas');
}
function id(v){if(typeof v!=='string'||!ID.test(v))throw Error('1BB invalid opaque identity');}
function sha(v){if(typeof v!=='string'||!SHA.test(v)||/^0{64}$/.test(v))throw Error('1BB invalid SHA-256 claim');}
function time(v){
 if(typeof v!=='string'||!UTC.test(v)||!Number.isFinite(Date.parse(v))||
   new Date(v).toISOString()!==v)throw Error('1BB noncanonical UTC');
 return Date.parse(v);
}
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export function phase1BbSignedBytes(body){
 exact(body,BODY);
 if(body.schemaVersion!==1||body.purpose!==BB_PURPOSE||
    body.authorityState!=='CANDIDATE_UNVERIFIED'||
    body.releaseDecision!=='HOLD')
  throw Error('1BB must never promote externally claimed authority');
 for(const x of ['logRef','sourceRef','authorityRef','keyId'])id(body[x]);
 for(const x of ['packetSha256','publicKeySha256','challengeSha256','subjectSha256','evidenceSha256'])
  sha(body[x]);
 if(!['WITNESS','STORAGE_AUDITOR','SECURITY','OPERATIONS','OWNER'].includes(body.sourceRole))
  throw Error('1BB unsupported source role');
 const issued=time(body.issuedAt),expires=time(body.expiresAt);
 if(expires<=issued||expires-issued>3600000)
  throw Error('1BB challenge expiry outside bounded window');
 return Buffer.from('AADITECH-PHASE-1BB-EVIDENCE-V1\0'+
   JSON.stringify(BODY.map(k=>body[k])),'utf8');
}
function verifyRecord(r){
 exact(r,RECORD);exact(r.pin,PIN);exact(r.signature,DETACHED);
 const b=r.body,p=r.pin,s=r.signature,msg=phase1BbSignedBytes(b);
 for(const x of ['sourceRef','authorityRef','keyId'])id(p[x]);
 sha(p.publicKeySha256);
 if(p.role!==b.sourceRole||p.sourceRef!==b.sourceRef||
    p.authorityRef!==b.authorityRef||p.keyId!==b.keyId||
    p.publicKeySha256!==b.publicKeySha256||s.sourceRef!==p.sourceRef||
    s.keyId!==p.keyId)
  return false;
 if(typeof p.publicKeyPem!=='string'||p.publicKeyPem.length>1024||
    !/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/.test(p.publicKeyPem))
  throw Error('1BB bounded public SPKI required');
 if(typeof s.signatureBase64!=='string'||!SIG.test(s.signatureBase64)||
    Buffer.from(s.signatureBase64,'base64').toString('base64')!==s.signatureBase64)
  throw Error('1BB canonical signature required');
 const key=createPublicKey(p.publicKeyPem);
 if(key.asymmetricKeyType!=='ed25519'||
    digest(key.export({type:'spki',format:'der'}))!==p.publicKeySha256)
  throw Error('1BB pinned Ed25519 SPKI mismatch');
 return verify(null,msg,key,Buffer.from(s.signatureBase64,'base64'));
}
export function assessPhase1BbEvidenceIntake({
 azPacket=null,records=[],now=new Date()
}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
  throw Error('1BB invalid evaluation clock');
 if(!Array.isArray(records)||records.length>6)
  throw Error('1BB bounded evidence inventory required');
 const blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({phase:'1BB',...extra,
  independentSourcesAuthenticated:false,keyCustodyAuthenticated:false,
  externalImmutabilityVerified:false,realDRWitnessed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',blockerCodes:Object.freeze([...blockers].sort())});
 if(!azPacket||records.length!==6){
  blockers.add('MISSING_SIX_DOMAIN_EVIDENCE_RECORDS');
  return deny({internalEvidenceConsistent:false,batchSha256:null,challengeDigests:[]});
 }
 const az=phase1AzAssessReadiness(azPacket,{now});
 if(!az.packetInspected||!az.internalEvidenceConsistent)
  blockers.add('UNSAFE_PREDECESSOR_READINESS_PACKET');
 const sorted=records.slice().sort((a,b)=>String(a?.body?.sourceRole).localeCompare(String(b?.body?.sourceRole))||
  String(a?.body?.sourceRef).localeCompare(String(b?.body?.sourceRef)));
 const required=REQUIRED.slice().sort();
 if(sorted.map(r=>r?.body?.sourceRole).join('|')!==required.join('|'))
  blockers.add('MISSING_OR_EXTRA_EVIDENCE_ROLE');
 const keyIds=new Set(),people=new Set(),admins=new Set(),nonces=new Set(),sourceRefs=new Set();
 const timeNow=now.getTime();
 let valid=0;
 for(const r of sorted){
  exact(r,RECORD);
  const b=r.body;
  const bytes=phase1BbSignedBytes(b);
  const issued=time(b.issuedAt),expires=time(b.expiresAt);
  if(issued>timeNow+300000||expires<=timeNow)
   blockers.add('STALE_OR_FUTURE_EVIDENCE');
  if(b.packetSha256!==az.packetSha256||
     b.logRef!==azPacket.archive.logRef)
   blockers.add('PACKET_OR_LOG_BINDING_MISMATCH');
  const identity=b.sourceRole+'|'+b.sourceRef;
  if(keyIds.has(b.keyId)||people.has(b.sourceRef)||admins.has(b.authorityRef)||
     nonces.has(b.challengeSha256)||sourceRefs.has(identity))
   blockers.add('REPLAYED_CHALLENGE_OR_SHARED_AUTHORITY');
  keyIds.add(b.keyId);people.add(b.sourceRef);admins.add(b.authorityRef);
  nonces.add(b.challengeSha256);sourceRefs.add(identity);
  let registered=null;
  let subject=null,evidence=null;
  if(b.sourceRole==='WITNESS'){
   registered=azPacket.witnesses.find(w=>w.witnessRef===b.sourceRef);
   subject=azPacket.archive.checkpointReceiptSha256;
   evidence=registered?.publisherPolicySha256;
   if(!registered||registered.administrativeAuthorityRef!==b.authorityRef||
      registered.publicKeySpkiSha256!==b.publicKeySha256)
    blockers.add('WITNESS_ENROLLMENT_PIN_NOT_MATCHED');
  }else if(b.sourceRole==='STORAGE_AUDITOR'){
   subject=azPacket.archive.archiveObjectSha256;
   evidence=azPacket.archive.legalHoldEvidenceSha256;
  }else{
   registered=azPacket.approvers.find(x=>x.role===b.sourceRole);
   subject=azPacket.recovery.restoredManifestSha256;
   evidence=registered?.reviewRecordSha256;
   if(!registered||registered.reviewerRef!==b.sourceRef||
      registered.authorityRef!==b.authorityRef)
    blockers.add('RECOVERY_REVIEWER_NOT_ENROLLED');
  }
  if(b.subjectSha256!==subject||b.evidenceSha256!==evidence)
   blockers.add('EVIDENCE_DIGEST_OR_SUBJECT_MISMATCH');
  if(verifyRecord(r))valid++;
  else blockers.add('INVALID_DETACHED_EVIDENCE_SIGNATURE');
 }
 if(valid!==6)blockers.add('EVIDENCE_SIGNATURE_QUORUM_MISSING');
 // Receipt is a deterministic commitment to exactly these bounded signed
 // claims; caller-supplied challenge issuance remains UNTRUSTED.
 const batchSha256=digest(Buffer.from('AADITECH-PHASE-1BB-BATCH-V1\0'+
  JSON.stringify([az.packetSha256,sorted.map(r=>[
   digest(phase1BbSignedBytes(r.body)),r.signature.signatureBase64
  ])]),'utf8'));
 const inconsistencies=[...blockers].filter(x=>!BASE.includes(x));
 return deny({internalEvidenceConsistent:inconsistencies.length===0,
  signedClaimsChecked:valid,requestedSigners:6,batchSha256,
  challengeDigests:Object.freeze([...nonces].sort()),
  independentChallengeIssuanceVerified:false,
  externalIssuerIdentityVerified:false});
}
