import type {CandidateExternalAuthorityDossier,CandidateExternalAuthorityExpected}
 from '../server/commercialIntegrity/quoteAuthorityDossier';

export const boFixtureNow=new Date('2026-11-17T15:00:00.000Z');
export const boFixtureSha=(character:string)=>character.repeat(64);
export const boFixtureQuote='11111111-1111-4111-8111-111111111111';
export const boClone=<T>(v:T):T=>structuredClone(v);
export function boExpectedFixture(
 overwrite:Partial<CandidateExternalAuthorityExpected>={}):CandidateExternalAuthorityExpected{
 return {quoteId:boFixtureQuote,
  bnPacketSha256:boFixtureSha('a'),
  bmReceiptSha256:boFixtureSha('b'),
  quoteSourceSha256:boFixtureSha('c'),
  candidatePinsetSha256:boFixtureSha('d'),
  bmSequence:2,bnRevocationEpoch:4,
  bmGovernanceState:'HELD_UNVERIFIED',
  bnGovernanceState:'HELD_UNVERIFIED',
  bmLocallyConsistent:true,bnLocallyConsistent:true,...overwrite};
}
export function boDossierFixture(expected:CandidateExternalAuthorityExpected):
 CandidateExternalAuthorityDossier{
 return {
  format:'aaditech-quote-external-authority-candidate-v1',
  quoteId:expected.quoteId,
  bnPacketSha256:expected.bnPacketSha256,
  bmReceiptSha256:expected.bmReceiptSha256,
  quoteSourceSha256:expected.quoteSourceSha256,
  candidatePinsetSha256:expected.candidatePinsetSha256,
  enrollment:{
   providerId:'provider-fixture-org',
   agreementSha256:boFixtureSha('1'),
   certificatePolicySha256:boFixtureSha('2'),
   chainEvidenceSha256:boFixtureSha('3'),
   hsmCustodyClaimSha256:boFixtureSha('4'),
   enrolmentState:'UNVERIFIED'
  },
  publication:{
   publisherId:'publisher-fixture-org',
   claimedHeadSha256:expected.bmReceiptSha256,
   receiptEvidenceSha256:boFixtureSha('5'),
   objectLockEvidenceSha256:boFixtureSha('6'),
   observedAt:'2026-11-17T14:58:00.000Z',
   retentionUntil:'2027-11-17T15:00:00.000Z',
   publicationState:'UNVERIFIED'
  },
  revocation:{
   issuerId:'issuer-fixture-org',
   crlEvidenceSha256:boFixtureSha('7'),
   ocspEvidenceSha256:boFixtureSha('8'),
   distributionPointSha256:boFixtureSha('9'),
   epoch:expected.bnRevocationEpoch,
   thisUpdate:'2026-11-17T14:40:00.000Z',
   nextUpdate:'2026-11-17T15:40:00.000Z',
   revokedKeyIds:[],
   revocationState:'UNVERIFIED'
  },
  disasterRecovery:{
   encryptedArchiveEvidenceSha256:boFixtureSha('a'),
   restoreTranscriptSha256:boFixtureSha('b'),
   restoredReceiptSha256:expected.bmReceiptSha256,
   restoredSourceSha256:expected.quoteSourceSha256,
   recoveredSequence:expected.bmSequence,
   rehearsedAt:'2026-11-17T14:59:00.000Z',
   operatorId:'dr-operator-fixture',
   witnessId:'dr-witness-fixture',
   rtoSeconds:120,rpoSeconds:300,recoveryState:'SIMULATED_ONLY'
  },
  reviews:[
   {role:'OWNER',actorId:'owner-fixture',evidenceSha256:boFixtureSha('a'),
    decision:'INTERNAL_PRECHECK_ONLY'},
   {role:'SECURITY',actorId:'security-fixture',evidenceSha256:boFixtureSha('b'),
    decision:'INTERNAL_PRECHECK_ONLY'},
   {role:'LEGAL',actorId:'legal-fixture',evidenceSha256:boFixtureSha('c'),
    decision:'INTERNAL_PRECHECK_ONLY'},
   {role:'OPERATIONS',actorId:'operations-fixture',
    evidenceSha256:boFixtureSha('d'),decision:'INTERNAL_PRECHECK_ONLY'}
  ]
 };
}
