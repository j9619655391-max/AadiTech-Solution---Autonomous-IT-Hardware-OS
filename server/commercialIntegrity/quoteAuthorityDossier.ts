import {createHash} from 'node:crypto';

// Phase 1BO: CLAIMED external evidence preflight, not authentication.
// All values are applicant-supplied until a legally approved provider,
// independently retained head, authentic PKI/CRL/OCSP and verified reviewers
// are enrolled by a separate trusted workflow. Never grant GO from this.
const SHA=/^[a-f0-9]{64}$/;
const ID=/^[a-zA-Z0-9._:-]{3,96}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const UTC=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ROLES=['OWNER','SECURITY','LEGAL','OPERATIONS'] as const;
const fields=(v:unknown,keys:string[]):v is Record<string,any>=>
 !!v&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join('|')===keys.slice().sort().join('|');
const instant=(value:unknown):number|null=>{
 if(typeof value!=='string'||!UTC.test(value))return null;
 const n=Date.parse(value);return Number.isFinite(n)&&new Date(n).toISOString()===value?n:null;
};
const domainHash=(domain:string,value:string)=>createHash('sha256')
 .update(domain+'\n'+value,'utf8').digest('hex');
function canonical(v:unknown,depth=0):unknown{
 if(depth>8)throw Error('BO evidence nesting exceeds bound');
 if(v===null||typeof v==='string'||typeof v==='boolean')return v;
 if(typeof v==='number'&&Number.isFinite(v))return v;
 if(Array.isArray(v)){
  if(v.length>16)throw Error('BO excessive evidence array');
  return v.map(x=>canonical(x,depth+1));
 }
 if(v&&typeof v==='object'){
  const obj=v as Record<string,unknown>,keys=Object.keys(obj).sort();
  if(keys.length>24||keys.some(k=>['__proto__','prototype','constructor'].includes(k)))
   throw Error('BO invalid evidence object');
  const normalized:Record<string,unknown>={};
  for(const k of keys)normalized[k]=canonical(obj[k],depth+1);
  return normalized;
 }
 throw Error('BO unsupported evidence scalar');
}
export type CandidateAuthorityReview={role:typeof ROLES[number],
 actorId:string,evidenceSha256:string,decision:'INTERNAL_PRECHECK_ONLY'};
export type CandidateExternalAuthorityDossier={
 format:'aaditech-quote-external-authority-candidate-v1';
 quoteId:string;
 bnPacketSha256:string;bmReceiptSha256:string;quoteSourceSha256:string;
 candidatePinsetSha256:string;
 enrollment:{
  providerId:string;agreementSha256:string;certificatePolicySha256:string;
  chainEvidenceSha256:string;hsmCustodyClaimSha256:string;
  enrolmentState:'UNVERIFIED'
 };
 publication:{
  publisherId:string;claimedHeadSha256:string;receiptEvidenceSha256:string;
  objectLockEvidenceSha256:string;observedAt:string;retentionUntil:string;
  publicationState:'UNVERIFIED'
 };
 revocation:{
  issuerId:string;crlEvidenceSha256:string;ocspEvidenceSha256:string;
  distributionPointSha256:string;epoch:number;thisUpdate:string;
  nextUpdate:string;revokedKeyIds:string[];
  revocationState:'UNVERIFIED'
 };
 disasterRecovery:{
  encryptedArchiveEvidenceSha256:string;restoreTranscriptSha256:string;
  restoredReceiptSha256:string;restoredSourceSha256:string;
  recoveredSequence:number;rehearsedAt:string;
  operatorId:string;witnessId:string;rtoSeconds:number;rpoSeconds:number;
  recoveryState:'SIMULATED_ONLY'
 };
 reviews:CandidateAuthorityReview[];
};
export type CandidateExternalAuthorityExpected={
 quoteId:string;
 bnPacketSha256:string;bmReceiptSha256:string;quoteSourceSha256:string;
 candidatePinsetSha256:string;bmSequence:number;bnRevocationEpoch:number;
 bmGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT';
 bnGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT';
 bmLocallyConsistent:boolean;bnLocallyConsistent:boolean
};
export function candidateExternalAuthorityDossierDigest(dossier:CandidateExternalAuthorityDossier){
 return domainHash('aaditech/quote/external-authority-candidate/v1',
  JSON.stringify(canonical(dossier)));
}
export function assessCandidateExternalAuthorityDossier(args:{
 dossier:CandidateExternalAuthorityDossier;
 expected:CandidateExternalAuthorityExpected;
 now:Date
}){
 const errors=new Set<string>(),{dossier:d,expected:e,now}=args;
 if(!d||typeof d!=='object'||Array.isArray(d))throw Error('BO invalid candidate dossier object');
 const at=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(at))errors.add('BO_CLOCK_INVALID');
 if(!fields(d,['format','quoteId','bnPacketSha256','bmReceiptSha256',
   'quoteSourceSha256','candidatePinsetSha256','enrollment','publication',
   'revocation','disasterRecovery','reviews'])||
   d.format!=='aaditech-quote-external-authority-candidate-v1'||
   !UUID.test(String(d.quoteId))||
   ![d.bnPacketSha256,d.bmReceiptSha256,d.quoteSourceSha256,
     d.candidatePinsetSha256].every(x=>SHA.test(String(x))))
  errors.add('BO_DOSSIER_SHAPE_OR_BINDING_INVALID');
 if(!e||!UUID.test(String(e.quoteId))||!SHA.test(String(e.bnPacketSha256))||
   !SHA.test(String(e.bmReceiptSha256))||!SHA.test(String(e.quoteSourceSha256))||
   !SHA.test(String(e.candidatePinsetSha256))||
   !Number.isSafeInteger(e.bmSequence)||e.bmSequence<1||
   !Number.isSafeInteger(e.bnRevocationEpoch)||e.bnRevocationEpoch<1||
   e.bmGovernanceState!=='HELD_UNVERIFIED'||e.bnGovernanceState!=='HELD_UNVERIFIED'||
   e.bmLocallyConsistent!==true||e.bnLocallyConsistent!==true)
  errors.add('BO_INTERNAL_UPSTREAM_NOT_ACCEPTABLE');
 if(d.quoteId!==e?.quoteId||d.bnPacketSha256!==e?.bnPacketSha256||
   d.bmReceiptSha256!==e?.bmReceiptSha256||
   d.quoteSourceSha256!==e?.quoteSourceSha256||
   d.candidatePinsetSha256!==e?.candidatePinsetSha256)
  errors.add('BO_UPSTREAM_BM_BN_HEAD_OR_PINSET_MISMATCH');
 const enrol=d.enrollment??{};
 if(!fields(enrol,['providerId','agreementSha256','certificatePolicySha256',
    'chainEvidenceSha256','hsmCustodyClaimSha256','enrolmentState'])||
    !ID.test(String(enrol.providerId))||
    ![enrol.agreementSha256,enrol.certificatePolicySha256,
      enrol.chainEvidenceSha256,enrol.hsmCustodyClaimSha256].every(x=>
      SHA.test(String(x)))||enrol.enrolmentState!=='UNVERIFIED')
  errors.add('BO_ENROLLMENT_CLAIM_INVALID_OR_PREMATURE_TRUST');
 const pub=d.publication??{};
 if(!fields(pub,['publisherId','claimedHeadSha256','receiptEvidenceSha256',
    'objectLockEvidenceSha256','observedAt','retentionUntil',
    'publicationState'])||!ID.test(String(pub.publisherId))||
    ![pub.claimedHeadSha256,pub.receiptEvidenceSha256,
      pub.objectLockEvidenceSha256].every(x=>SHA.test(String(x)))||
    pub.publicationState!=='UNVERIFIED')
  errors.add('BO_PUBLICATION_PROVENANCE_CLAIM_INVALID');
 if(pub.claimedHeadSha256!==e?.bmReceiptSha256)
  errors.add('BO_CLAIMED_OFF_PLATFORM_HEAD_MISMATCH');
 const seen=instant(pub.observedAt),expires=instant(pub.retentionUntil);
 if(seen===null||expires===null||!Number.isFinite(at)||
    seen>at+60000||at-seen>15*60000||
    expires<=at+30*24*3600000)
  errors.add('BO_PUBLISHER_HEAD_STALE_OR_RETENTION_UNPROVEN');
 const rev=d.revocation??{};
 if(!fields(rev,['issuerId','crlEvidenceSha256','ocspEvidenceSha256',
    'distributionPointSha256','epoch','thisUpdate','nextUpdate',
    'revokedKeyIds','revocationState'])||!ID.test(String(rev.issuerId))||
    ![rev.crlEvidenceSha256,rev.ocspEvidenceSha256,
      rev.distributionPointSha256].every(x=>SHA.test(String(x)))||
    !Number.isSafeInteger(rev.epoch)||rev.epoch<1||
    !Array.isArray(rev.revokedKeyIds)||rev.revokedKeyIds.length>8||
    rev.revokedKeyIds.some(k=>typeof k!=='string'||!ID.test(k))||
    new Set(rev.revokedKeyIds).size!==rev.revokedKeyIds.length||
    [...rev.revokedKeyIds].sort().join('|')!==rev.revokedKeyIds.join('|')||
    rev.revocationState!=='UNVERIFIED')
  errors.add('BO_REVOCATION_CLAIM_INVALID_OR_PREMATURE_TRUST');
 if(rev.epoch<e?.bnRevocationEpoch)
  errors.add('BO_REVOCATION_EPOCH_ROLLBACK');
 const revFrom=instant(rev.thisUpdate),revUntil=instant(rev.nextUpdate);
 if(revFrom===null||revUntil===null||!Number.isFinite(at)||
    revFrom>at+60000||at-revFrom>3600000||revUntil<=at||
    revUntil<=revFrom)
  errors.add('BO_CLAIMED_REVOCATION_STALE_OR_FUTURE');
 const dr=d.disasterRecovery??{};
 if(!fields(dr,['encryptedArchiveEvidenceSha256','restoreTranscriptSha256',
    'restoredReceiptSha256','restoredSourceSha256','recoveredSequence',
    'rehearsedAt','operatorId','witnessId','rtoSeconds','rpoSeconds',
    'recoveryState'])||
    ![dr.encryptedArchiveEvidenceSha256,dr.restoreTranscriptSha256,
      dr.restoredReceiptSha256,dr.restoredSourceSha256].every(x=>SHA.test(String(x)))||
    !ID.test(String(dr.operatorId))||!ID.test(String(dr.witnessId))||
    dr.operatorId===dr.witnessId||
    !Number.isSafeInteger(dr.recoveredSequence)||dr.recoveredSequence<0||
    !Number.isSafeInteger(dr.rtoSeconds)||dr.rtoSeconds<0||
    dr.rtoSeconds>86400||
    !Number.isSafeInteger(dr.rpoSeconds)||dr.rpoSeconds<0||
    dr.rpoSeconds>86400||dr.recoveryState!=='SIMULATED_ONLY')
  errors.add('BO_DR_DOSSIER_INVALID_OR_PREMATURE_ATTESTATION');
 const drAt=instant(dr.rehearsedAt);
 if(drAt===null||!Number.isFinite(at)||drAt>at+60000||
    at-drAt>24*3600000)
  errors.add('BO_DR_REHEARSAL_STALE_OR_FUTURE');
 if(dr.recoveredSequence<e?.bmSequence)
  errors.add('BO_DR_ROLLBACK_DETECTED');
 else if(dr.recoveredSequence!==e?.bmSequence||
         dr.restoredReceiptSha256!==e?.bmReceiptSha256||
         dr.restoredSourceSha256!==e?.quoteSourceSha256)
  errors.add('BO_DR_RESTORED_HEAD_CONFLICT');
 const rs=d.reviews;
 if(!Array.isArray(rs)||rs.length!==4||
    new Set(rs.map(r=>r?.role)).size!==4||
    new Set(rs.map(r=>r?.actorId)).size!==4||
    ROLES.some(role=>!rs.some(r=>r?.role===role))||
    rs.some(r=>!fields(r,['role','actorId','evidenceSha256','decision'])||
      !ID.test(String(r.actorId))||!SHA.test(String(r.evidenceSha256))||
      r.decision!=='INTERNAL_PRECHECK_ONLY')||
    rs.some(r=>r?.actorId===dr.operatorId||
      r?.actorId===dr.witnessId||
      r?.actorId===enrol.providerId||
      r?.actorId===pub.publisherId||
      r?.actorId===rev.issuerId))
  errors.add('BO_REVIEW_SEPARATION_OR_AUTHORITY_CLAIM_INVALID');
 const anomalyCodes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateDossierInternallyConsistent:anomalyCodes.length===0,
  candidateDossierAnomalyCodes:anomalyCodes,
  candidateDossierSha256:anomalyCodes.length===0?
   candidateExternalAuthorityDossierDigest(d):null,
  independentProviderAgreementAuthenticated:false,
  independentKeyEnrollmentAuthenticated:false,
  trustedOutOfBandPublicationHeadVerified:false,
  independentWormRetentionVerified:false,
  independentRevocationAndCrlOcspVerified:false,
  actualEncryptedDrWitnessed:false,
  legalSignatoryIdentityVerified:false,
  independentReleaseSignoffsVerified:false,
  externalAuthorityApproved:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD' as const
 });
}
