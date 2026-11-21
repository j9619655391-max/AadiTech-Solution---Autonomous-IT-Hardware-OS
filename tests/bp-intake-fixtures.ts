import {generateKeyPairSync,sign} from 'node:crypto';
import {canonicalCandidateIntakeClaim,
 candidateIntakePinsetDigest,type IntakeCandidatePacket,
 type IntakeExpected,type IntakePinnedCandidateKey,type IntakeRole,
 type IntakeClaimBody} from '../server/commercialIntegrity/quoteEvidenceIntake';

export const bpNow=new Date('2026-11-17T15:00:00.000Z');
export const bpSha=(hex:string)=>hex.repeat(64);
export const bpClone=<T>(x:T):T=>structuredClone(x);
const roles=['PUBLISHER','ISSUER','WORM','RECOVERY'] as const;
const keys=new Map<IntakeRole,{
 pin:IntakePinnedCandidateKey,privateKey:ReturnType<typeof generateKeyPairSync>['privateKey']
}>();
for(const role of roles){
 const pair=generateKeyPairSync('ed25519');
 keys.set(role,{pin:{role,keyId:'bp-'+role.toLowerCase()+'-synthetic',
  publicKeySpkiPem:pair.publicKey.export({type:'spki',format:'pem'}).toString(),
  validFrom:'2026-01-01T00:00:00.000Z',
  validUntil:'2028-01-01T00:00:00.000Z',status:'ACTIVE'},
  privateKey:pair.privateKey});
}
export const bpPins=roles.map(r=>keys.get(r)!.pin);
export const bpPinsetSha=candidateIntakePinsetDigest(bpPins);
export function bpExpectedFixture(overrides:Partial<IntakeExpected>={}):IntakeExpected{
 return {
  quoteId:'22222222-2222-4222-8222-222222222222',
  boDossierSha256:bpSha('a'),bmReceiptSha256:bpSha('b'),
  bnPacketSha256:bpSha('c'),sourceSha256:bpSha('d'),
  bmSequence:2,minimumRevocationEpoch:4,
  boExists:true,boLocallyConsistent:true,
  boGovernanceState:'HELD_UNVERIFIED',...overrides};
}
export function bpSignedClaim(body:IntakeClaimBody){
 const signKey=keys.get(body.signerRole);
 if(!signKey)throw Error('BP unknown synthetic test signer');
 return {body,signatureBase64:sign(null,
  Buffer.from('aaditech/quote/evidence-intake/claim/v1\n'+
   canonicalCandidateIntakeClaim(body)),signKey.privateKey).toString('base64')};
}
export function bpPacketFixture(
 expected:IntakeExpected=bpExpectedFixture(),
 challengeSha256=bpSha('e')):IntakeCandidatePacket{
 const claims=roles.map(role=>{
  const body:IntakeClaimBody={
   format:'aaditech-quote-evidence-intake-claim-v1',
   quoteId:expected.quoteId,challengeSha256,
   boDossierSha256:expected.boDossierSha256,
   bmReceiptSha256:expected.bmReceiptSha256,
   bnPacketSha256:expected.bnPacketSha256,
   signerRole:role,signerKeyId:keys.get(role)!.pin.keyId,
   claimedSourceId:'synthetic-'+role.toLowerCase()+'-operator',
   observedAt:'2026-11-17T14:59:00.000Z',
   publicationHeadSha256:expected.bmReceiptSha256,
   revocationEpoch:expected.minimumRevocationEpoch,
   revocationThisUpdate:'2026-11-17T14:40:00.000Z',
   revocationNextUpdate:'2026-11-17T15:40:00.000Z',
   crlSha256:bpSha('1'),ocspSha256:bpSha('2'),
   issuerChainSha256:bpSha('3'),
   retentionUntil:'2028-11-17T15:00:00.000Z',
   overwriteDenied:true,deleteDenied:true,
   restoredSequence:expected.bmSequence,
   restoredReceiptSha256:expected.bmReceiptSha256,
   restoredSourceSha256:expected.sourceSha256,
   drTranscriptSha256:bpSha('4'),
   rtoSeconds:200,rpoSeconds:300,
   evidenceState:'CANDIDATE_UNVERIFIED'
  };
  return bpSignedClaim(body);
 });
 return {format:'aaditech-quote-evidence-intake-v1',
  quoteId:expected.quoteId,challengeSha256,
  boDossierSha256:expected.boDossierSha256,claims};
}
export function bpResign(packet:IntakeCandidatePacket,role:IntakeRole,
 changes:Partial<IntakeClaimBody>){
 const clone=bpClone(packet);
 const idx=clone.claims.findIndex(c=>c.body.signerRole===role);
 if(idx<0)throw Error('BP signer missing in fixture');
 clone.claims[idx]=bpSignedClaim({...clone.claims[idx].body,...changes});
 return clone;
}
