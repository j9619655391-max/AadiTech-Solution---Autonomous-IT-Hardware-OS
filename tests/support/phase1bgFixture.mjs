import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {bfFixture,h} from './phase1bfFixture.mjs';
import {assessPhase1BfPublication} from '../../scripts/lib/phase1BfRevocationPublication.mjs';
import {BG_PURPOSE,phase1BgSigningBytes,phase1BgAuditorPinsetSha256}
 from '../../scripts/lib/phase1BgCrossSourceAcceptance.mjs';

const digest=x=>createHash('sha256').update(x).digest('hex');
const ROLES=['REVOCATION_AUDITOR','STORAGE_AUDITOR','DR_AUDITOR'];
function actor(role,i){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {privateKey,pin:{
  role,sourceRef:'bg-auditor-source-00'+i,
  authorityRef:'bg-independent-claim-admin-00'+i,
  keyId:'bg-audit-signing-key-00'+i,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:digest(publicKey.export({format:'der',type:'spki'}))
 }};
}
function signed(actor,bytes){
 return {pin:{...actor.pin},signature:{
  sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
  signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')
 }};
}
export function bgFixture(logRef='bg-cross-source-checkpoint-001'){
 const publication=bfFixture(logRef),actors=ROLES.map((r,i)=>actor(r,i+1));
 const pub=assessPhase1BfPublication(publication);
 const dossier=publication.freezeEvidence.bdEvidence;
 const storage=dossier.storageReceipt.body,dr=dossier.recoveryAttestations[0].body;
 const skeleton=actors.map(x=>({pin:{...x.pin},signature:{
  sourceRef:x.pin.sourceRef,keyId:x.pin.keyId,signatureBase64:''
 }}));
 const manifest={
  schemaVersion:1,purpose:BG_PURPOSE,logRef,
  publicationSha256:pub.publicationSha256,
  publicationSequence:publication.body.publicationSequence,
  freezeIncidentSha256:publication.body.freezeIncidentSha256,
  publisherPinSha256:publication.body.publisherPublicKeySha256,
  reviewRevision:1,previousReviewSha256:null,
  auditorPinSetSha256:phase1BgAuditorPinsetSha256(skeleton),
  crlIssuerSha256:publication.body.publisherPublicKeySha256,
  crlSnapshotSha256:publication.body.claimedIssuedRevocationSha256,
  crlNumber:1,
  crlThisUpdate:'2026-11-16T18:07:00.000Z',
  crlNextUpdate:'2026-11-16T18:17:00.000Z',
  ocspResponseSha256:h(5101),
  ocspProducedAt:'2026-11-16T18:08:00.000Z',
  ocspNextUpdate:'2026-11-16T18:17:00.000Z',
  ocspStatus:'REVOKED_CLAIMED',
  revokedKeySpkiSha256:publication.body.revokedKeySpkiSha256,
  wormVersionSha256:publication.body.storageObjectVersionSha256,
  wormRetentionPolicySha256:storage.retentionPolicySha256,
  wormDeleteDenialSha256:publication.body.claimedObjectLockDenialReceiptSha256,
  wormOverwriteDenialSha256:storage.overwriteDenialReceiptSha256,
  wormReadbackSha256:storage.readbackReceiptSha256,
  wormRetentionUntil:storage.retentionUntil,
  restoreReceiptSha256:dr.isolatedRestoreReceiptSha256,
  restoreTelemetrySha256:publication.body.claimedEncryptedRestoreTelemetrySha256,
  restoredManifestSha256:dr.restoredManifestSha256,
  rtoObservedMs:Date.parse(dr.completedAt)-Date.parse(dr.failureAt),
  rpoObservedMs:Date.parse(dr.failureAt)-Date.parse(dr.latestRecoveredAt),
  reviewedAt:'2026-11-16T18:10:00.000Z',
  expiresAt:'2026-11-16T18:15:00.000Z',
  outboundHeld:true,releaseDecision:'HOLD'
 };
 const result={publication,manifest,auditors:[],
  now:new Date('2026-11-16T18:12:00.000Z')};
 Object.defineProperties(result,{
  actors:{value:actors},
  resign:{value:function(){
   const bytes=phase1BgSigningBytes(this.manifest);
   this.auditors=actors.map(x=>signed(x,bytes));
   return this;
  }},
  repin:{value:function(){
   this.manifest.auditorPinSetSha256=phase1BgAuditorPinsetSha256(
    actors.map(x=>signed(x,Buffer.from('fixture only'))));
   return this.resign();
  }}
 });
 return result.resign();
}
export {h};
