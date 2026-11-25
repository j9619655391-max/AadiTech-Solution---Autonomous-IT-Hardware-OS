import {generateKeyPairSync,sign} from 'node:crypto';
import {
 canonicalCandidateRegistrarManifest,canonicalCandidateRemoteCapture,
 candidateRegistrarPinDigest,candidateCollectorPinsetDigest,
 candidateEndpointConfigDigest,candidateRegistrarManifestDigest,
 type CandidateRegistrarPin,type CandidateCollectorPin,
 type CandidateEndpointConfig,type CandidateEnrollmentManifest,
 type CandidateRemotePacket,type CandidateRemoteCapture,
 type CandidateRemoteExpected
} from '../server/commercialIntegrity/quoteRemoteEvidence';

export const bqNow=new Date('2026-11-17T15:00:00.000Z');
export const bqSha=(digit:string)=>digit.repeat(64);
export const bqClone=<T>(x:T):T=>structuredClone(x);
const registrar=generateKeyPairSync('ed25519');
export const bqRoot:CandidateRegistrarPin={
 keyId:'bq-registrar-candidate',status:'ACTIVE',
 publicKeySpkiPem:registrar.publicKey.export({type:'spki',format:'pem'}).toString(),
 validFrom:'2026-01-01T00:00:00.000Z',
 validUntil:'2028-01-01T00:00:00.000Z'
};
const collectorPairs={
 PRIMARY:generateKeyPairSync('ed25519'),
 SECONDARY:generateKeyPairSync('ed25519')
};
export const bqCollectors:CandidateCollectorPin[]=
 (['PRIMARY','SECONDARY'] as const).map(role=>({
  role,keyId:'bq-'+role.toLowerCase()+'-candidate',status:'ACTIVE',
  publicKeySpkiPem:collectorPairs[role].publicKey.export({
   type:'spki',format:'pem'}).toString(),
  validFrom:'2026-01-01T00:00:00.000Z',
  validUntil:'2028-01-01T00:00:00.000Z'
 }));
export const bqEndpoints:CandidateEndpointConfig[]=[
 {role:'PRIMARY',origin:'https://publisher-candidate.invalid/',
  tlsSpkiSha256:bqSha('5')},
 {role:'SECONDARY',origin:'https://observer-candidate.invalid/',
  tlsSpkiSha256:bqSha('6')}
];
export const bqRootSha=candidateRegistrarPinDigest(bqRoot),
 bqCollectorsSha=candidateCollectorPinsetDigest(bqCollectors),
 bqEndpointsSha=candidateEndpointConfigDigest(bqEndpoints);
export function bqExpectedFixture(override:Partial<CandidateRemoteExpected>={}):
 CandidateRemoteExpected{
 return {quoteId:'22222222-2222-4222-8222-222222222222',
  bpPacketSha256:bqSha('a'),bmReceiptSha256:bqSha('b'),
  sourceSha256:bqSha('c'),bmSequence:1,minRevocationEpoch:4,
  bpExists:true,bpLocallyConsistent:true,
  bpGovernanceState:'HELD_UNVERIFIED',...override};
}
export function bqSignRegistrar(manifest:CandidateEnrollmentManifest){
 return sign(null,Buffer.from('aaditech/quote/registrar-manifest/v1\n'+
  canonicalCandidateRegistrarManifest(manifest)),registrar.privateKey).toString('base64');
}
export function bqSignCollector(body:CandidateRemoteCapture){
 return sign(null,Buffer.from('aaditech/quote/remote-capture/v1\n'+
  canonicalCandidateRemoteCapture(body)),
  collectorPairs[body.role].privateKey).toString('base64');
}
export function bqPacketFixture(
 expected:CandidateRemoteExpected=bqExpectedFixture(),
 challengeSha256=bqSha('e')):CandidateRemotePacket{
 const manifest:CandidateEnrollmentManifest={
  format:'aaditech-quote-registrar-manifest-v1',quoteId:expected.quoteId,
  providerId:'candidate-provider-fixture',registrarKeyId:bqRoot.keyId,
  collectorPinsetSha256:bqCollectorsSha,endpointConfigSha256:bqEndpointsSha,
  policySha256:bqSha('7'),epoch:expected.minRevocationEpoch,
  issuedAt:'2026-11-17T14:58:00.000Z',
  expiresAt:'2026-11-17T15:15:00.000Z',
  state:'OFFLINE_CANDIDATE_ONLY'
 };
 const manifestHash=candidateRegistrarManifestDigest(manifest);
 const captures=bqCollectors.map(k=>{
  const cfg=bqEndpoints.find(e=>e.role===k.role)!;
  const body:CandidateRemoteCapture={
   format:'aaditech-quote-remote-capture-v1',
   quoteId:expected.quoteId,role:k.role,collectorKeyId:k.keyId,
   manifestSha256:manifestHash,challengeSha256,origin:cfg.origin,
   tlsSpkiSha256:cfg.tlsSpkiSha256,
   retrievedAt:'2026-11-17T14:59:00.000Z',
   transportMode:'REPLAY_CAPTURE_ONLY',httpStatus:200,redirectCount:0,
   contentType:'application/vnd.aaditech.checkpoint+json',
   remoteSequence:expected.bmSequence,
   remoteReceiptSha256:expected.bmReceiptSha256,
   remoteSourceSha256:expected.sourceSha256,
   revocationEpoch:expected.minRevocationEpoch,
   revocationThisUpdate:'2026-11-17T14:40:00.000Z',
   revocationNextUpdate:'2026-11-17T15:40:00.000Z',
   crlSha256:bqSha('1'),ocspSha256:bqSha('2'),issuerChainSha256:bqSha('3'),
   wormDeleteDenied:true,wormOverwriteDenied:true,
   wormRetentionUntil:'2028-11-17T15:00:00.000Z',
   drRestoredSequence:expected.bmSequence,
   drRestoredReceiptSha256:expected.bmReceiptSha256,
   drRestoredSourceSha256:expected.sourceSha256,
   drTranscriptSha256:bqSha('4')
  };
  return {body,signatureBase64:bqSignCollector(body)};
 });
 return {format:'aaditech-quote-remote-evidence-v1',
  quoteId:expected.quoteId,challengeSha256,bpPacketSha256:expected.bpPacketSha256,
  manifest,manifestSignatureBase64:bqSignRegistrar(manifest),captures};
}
export function bqResignCapture(packet:CandidateRemotePacket,role:'PRIMARY'|'SECONDARY',
 changed:Partial<CandidateRemoteCapture>){
 const clone=bqClone(packet),i=clone.captures.findIndex(x=>x.body.role===role);
 if(i<0)throw Error('BQ missing role');
 const body={...clone.captures[i].body,...changed};
 clone.captures[i]={body,signatureBase64:bqSignCollector(body)};
 return clone;
}
export function bqResignManifest(packet:CandidateRemotePacket,
 changed:Partial<CandidateEnrollmentManifest>){
 const clone=bqClone(packet),manifest={...clone.manifest,...changed};
 clone.manifest=manifest;clone.manifestSignatureBase64=bqSignRegistrar(manifest);
 const hash=candidateRegistrarManifestDigest(manifest);
 clone.captures=clone.captures.map(c=>{
  const body={...c.body,manifestSha256:hash};
  return {body,signatureBase64:bqSignCollector(body)};
 });
 return clone;
}
