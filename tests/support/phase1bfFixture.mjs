import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {beFixture,h} from './phase1beFixture.mjs';
import {assessPhase1BeRevocationFreeze}
 from '../../scripts/lib/phase1BeRevocationFreeze.mjs';
import {BF_PURPOSE,phase1BfPublicationSigningBytes}
 from '../../scripts/lib/phase1BfRevocationPublication.mjs';

const sha=x=>createHash('sha256').update(x).digest('hex');
function pubActor(){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 return {privateKey,pin:{role:'REVOCATION_PUBLISHER',
  sourceRef:'independent-claim-publisher-001',
  authorityRef:'candidate-publisher-admin-001',
  keyId:'candidate-publisher-key-001',
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:sha(publicKey.export({format:'der',type:'spki'}))}};
}
function wrap(actor,bytes){
 return {pin:{...actor.pin},signature:{
  sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
  signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')
 }};
}
export function bfFixture(logRef='bf-revocation-checkpoint-001'){
 const freezeEvidence=beFixture(logRef),issuer=pubActor(),f=freezeEvidence.body;
 const now=new Date('2026-11-16T18:10:00.000Z');
 const held=assessPhase1BeRevocationFreeze({
  bdEvidence:freezeEvidence.bdEvidence,body:freezeEvidence.body,
  survivingWitnessSignature:freezeEvidence.survivingWitnessSignature,
  governanceSignatures:freezeEvidence.governanceSignatures,now
 });
 const body={schemaVersion:1,purpose:BF_PURPOSE,logRef,
  freezeIncidentSha256:held.incidentSha256,
  azPacketSha256:f.azPacketSha256,bdReviewSha256:f.bdReviewSha256,
  revokedWitnessRef:f.revokedWitnessRef,
  revokedKeySpkiSha256:f.revokedKeySpkiSha256,
  survivingWitnessRef:f.survivingWitnessRef,
  survivingKeySpkiSha256:f.survivingKeySpkiSha256,
  publicationSequence:1,previousPublicationSha256:null,
  publisherRef:issuer.pin.sourceRef,publisherAuthorityRef:issuer.pin.authorityRef,
  publisherPublicKeySha256:issuer.pin.publicKeySha256,
  publisherPolicySha256:h(920),
  claimedIssuedRevocationSha256:f.revocationNoticeSha256,
  priorRevocationSnapshotSha256:f.previousRevocationSnapshotSha256,
  checkpointReceiptSha256:f.checkpointReceiptSha256,
  archiveObjectSha256:f.archiveObjectSha256,
  storageObjectVersionSha256:f.storageObjectVersionSha256,
  claimedObjectLockDenialReceiptSha256:f.claimedObjectLockDenialReceiptSha256,
  claimedEncryptedRestoreTelemetrySha256:f.claimedEncryptedRestoreTelemetrySha256,
  issuedAt:'2026-11-16T18:05:00.000Z',
  observedAt:'2026-11-16T18:06:00.000Z',
  expiresAt:'2026-11-16T18:20:00.000Z',
  revocationState:'REVOKED_CLAIMED',
  quarantineRequired:true,outboundHeld:true,releaseDecision:'HOLD'};
 const result={freezeEvidence,body,publisher:null,survivingWitness:null,
  securityReviewer:null,now};
 Object.defineProperty(result,'publisherActor',{value:issuer});
 Object.defineProperty(result,'resign',{value:function(){
  const bytes=phase1BfPublicationSigningBytes(this.body);
  this.publisher=wrap(issuer,bytes);
  this.survivingWitness=wrap(freezeEvidence.bdEvidence.actors[1],bytes);
  this.securityReviewer=wrap(freezeEvidence.bdEvidence.actors[3],bytes);
  return this;
 }});
 return result.resign();
}
export {h};
