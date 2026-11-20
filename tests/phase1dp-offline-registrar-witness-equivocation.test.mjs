import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {REPO,canonical}
 from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {DOMAIN,WITNESS_ROLES,witnessSigningBytes}
 from '../scripts/phase1do-offline-registrar-witness-enrollment.mjs';
import {assessRegistrarWitnessEquivocationCandidate}
 from '../scripts/phase1dp-offline-registrar-witness-equivocation.mjs';

const HEAD='a'.repeat(40),MAIN='b'.repeat(40),REG='c'.repeat(64);
const NONCE='d'.repeat(64),NOW='2026-11-20T14:00:00.000Z';
const hash=b=>createHash('sha256').update(b).digest('hex');
function newKey(keyId){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {keyId,privateKey,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  spkiSha256:hash(publicKey.export({format:'der',type:'spki'}))};
}
function fixture(){
 const k={ROOT:newKey('registrar-root-key'),
  LEGAL_WITNESS:newKey('legal-witness-key'),
  REGISTRY_WITNESS:newKey('registry-witness-key')};
 const manifest={schemaVersion:1,
  kind:'UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE',
  repository:REPO,organizationId:'corporate-org-1',
  sourceHeadSha:HEAD,mainBaseSha:MAIN,
  registrarSpkiSha256:k.ROOT.spkiSha256,
  registryEvidenceSha256:REG,appointmentDigestSha256:'e'.repeat(64),
  nonce:NONCE,sequence:1,previousCheckpointSha256:'0'.repeat(64),
  issuedAt:'2026-11-20T13:59:00.000Z',
  expiresAt:'2026-11-20T14:09:00.000Z',decision:'HOLD'};
 const context=Object.fromEntries([
  'organizationId','sourceHeadSha','mainBaseSha',
  'registrarSpkiSha256','registryEvidenceSha256',
  'appointmentDigestSha256','nonce'].map(key=>[key,manifest[key]]));
 const witnessPins={legalWitnessSpkiSha256:k.LEGAL_WITNESS.spkiSha256,
  registryWitnessSpkiSha256:k.REGISTRY_WITNESS.spkiSha256};
 const signed=m=>{
  const witnesses={};
  for(const role of WITNESS_ROLES){
   witnesses[role]={keyId:k[role].keyId,
    publicKeyPem:k[role].publicKeyPem,spkiSha256:k[role].spkiSha256,
    signature:sign(null,witnessSigningBytes(role,m),
     k[role].privateKey).toString('base64')};
  }
  const claimedCheckpointSha256=hash(Buffer.from(
   DOMAIN+'checkpoint/v1\n'+canonical({manifest:m,
    signatures:WITNESS_ROLES.map(role=>
     [role,witnesses[role].keyId,witnesses[role].signature])}),'utf8'));
  return {manifest:structuredClone(m),witnesses,claimedCheckpointSha256};
 };
 const a=signed(manifest);
 const x={observations:[a,structuredClone(a)],comparisonPins:context,
  witnessPins,previousCheckpoint:{sequence:0,checkpointSha256:'0'.repeat(64)},
  now:NOW};
 return {x,k,signed};
}
const assess=change=>{const f=fixture();change?.(f);
 return assessRegistrarWitnessEquivocationCandidate(f.x);};
function hold(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualLegalMcaAndProviderAuthorityVerified,false);
 assert.equal(r.externalAtomicCasOrImmutableWormContinuityVerified,false);
 assert.equal(r.suppliedObserverOriginsAuthenticated,false);
 assert.equal(r.productionChangeOrReviewerRequestPossible,false);
}
function deny(change,code){
 const a=assess(change);hold(a);
 assert.ok(a.anomalyCodes.includes(code),a.anomalyCodes.join(' | '));
 return a;
}
test('DP two matching signed candidate copies are replay, not independently published proof',()=>{
 const a=deny(null,'DP_DUPLICATE_RECEIPT_NOT_INDEPENDENT_PUBLICATION');
 assert.equal(a.verifiedDualSignedPacketsMathematicallyOnly,2);
 assert.equal(a.distinctNextCheckpointDigestsOnly,1);
 assert.equal(a.sameSequenceConflictingDualSignedHeadsObservedOnly,false);
});
test('DP conflicting dual signed same-sequence manifest forks quarantine',()=>{
 const a=deny(f=>{
  const m=structuredClone(f.x.observations[1].manifest);
  m.expiresAt='2026-11-20T14:08:00.000Z';
  f.x.observations[1]=f.signed(m);
 },'DP_DUAL_SIGNED_SAME_SEQUENCE_EQUIVOCATION');
 assert.equal(a.verifiedDualSignedPacketsMathematicallyOnly,2);
 assert.equal(a.distinctNextCheckpointDigestsOnly,2);
 assert.equal(a.sameSequenceConflictingDualSignedHeadsObservedOnly,true);
});
test('DP changed unsigned manifest cannot create false signed-fork report',()=>{
 const a=deny(f=>{f.x.observations[1].manifest.issuedAt=
  '2026-11-20T13:58:00.000Z';},
 'DP_INVALID_SIGNED_WITNESS_OBSERVATION');
 assert.equal(a.sameSequenceConflictingDualSignedHeadsObservedOnly,false);
});
test('DP Legal witness signature cannot be reused by Registry role',()=>{
 deny(f=>{f.x.observations[1].witnesses.REGISTRY_WITNESS.signature=
  f.x.observations[1].witnesses.LEGAL_WITNESS.signature;},
 'DP_INVALID_SIGNED_WITNESS_OBSERVATION');
});
test('DP corrupted Legal signature rejects whole signed observation',()=>{
 deny(f=>{f.x.observations[0].witnesses.LEGAL_WITNESS.signature=
  'A'.repeat(86)+'==';},'DP_INVALID_SIGNED_WITNESS_OBSERVATION');
});
test('DP unknown and swapped witness pinsets fail',()=>{
 deny(f=>{f.x.witnessPins.legalWitnessSpkiSha256='f'.repeat(64);},
  'DP_TWO_DISTINCT_PINNED_WITNESS_KEYS_INVALID');
 deny(f=>{const p=f.x.witnessPins;
  [p.legalWitnessSpkiSha256,p.registryWitnessSpkiSha256]=
  [p.registryWitnessSpkiSha256,p.legalWitnessSpkiSha256];},
  'DP_TWO_DISTINCT_PINNED_WITNESS_KEYS_INVALID');
 deny(f=>{f.x.witnessPins=null;},'DP_TWO_SEPARATE_WITNESS_PINS_REQUIRED');
});
test('DP same key for Legal and Registry cannot establish independent roles',()=>{
 deny(f=>{f.x.witnessPins.registryWitnessSpkiSha256=
  f.x.witnessPins.legalWitnessSpkiSha256;},
 'DP_TWO_SEPARATE_WITNESS_PINS_REQUIRED');
});
test('DP signed source and external applicant-supplied context must agree exactly',()=>{
 deny(f=>{f.x.comparisonPins.sourceHeadSha='f'.repeat(40);},
 'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
 deny(f=>{f.x.comparisonPins.appointmentDigestSha256='f'.repeat(64);},
 'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
 deny(f=>{f.x.comparisonPins.organizationId='unrelated-org';},
 'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
});
test('DP source edits freshly re-signed cannot bypass separately supplied pins',()=>{
 deny(f=>{for(let i=0;i<2;i++){
  const m=structuredClone(f.x.observations[i].manifest);
  m.mainBaseSha='f'.repeat(40);f.x.observations[i]=f.signed(m);
 }},'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
});
test('DP predecessor fork, sequence skip and zero-genesis misuse deny',()=>{
 deny(f=>{f.x.previousCheckpoint.checkpointSha256='f'.repeat(64);},
  'DP_PREVIOUS_CHECKPOINT_INVALID');
 deny(f=>{f.x.previousCheckpoint.sequence=2;},
  'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
 deny(f=>{f.x.previousCheckpoint.sequence=0;
  f.x.previousCheckpoint.checkpointSha256='f'.repeat(64);},
  'DP_PREVIOUS_CHECKPOINT_INVALID');
});
test('DP omitted or non-canonical verifier clock fails closed',()=>{
 deny(f=>{delete f.x.now;},'DP_EXPLICIT_VERIFICATION_CLOCK_REQUIRED');
 deny(f=>{f.x.now='2026-11-20T14:00:00Z';},
 'DP_EXPLICIT_VERIFICATION_CLOCK_REQUIRED');
});
test('DP signed stale, future and overly long validity windows deny',()=>{
 for(const [field,time] of [
  ['issuedAt','2026-11-20T12:00:00.000Z'],
  ['issuedAt','2026-11-20T14:09:00.000Z'],
  ['expiresAt','2026-11-20T14:30:00.000Z'],
  ['expiresAt','2026-11-20T13:50:00.000Z']]){
  deny(f=>{const m=structuredClone(f.x.observations[1].manifest);
   m[field]=time;f.x.observations[1]=f.signed(m);
  },'DP_EXPLICIT_CLOCK_WITNESS_EXPIRY_INVALID');
 }
});
test('DP forged claimed checkpoint hash cannot create consistency',()=>{
 deny(f=>{f.x.observations[1].claimedCheckpointSha256='f'.repeat(64);},
 'DP_CLAIMED_CHECKPOINT_DIGEST_MISMATCH');
});
test('DP unknown GO field, unknown witness role and nested packet extras fail',()=>{
 deny(f=>{f.x.observations[1].manifest.productionReleaseAuthorized=true;},
 'DP_SIGNED_SOURCE_SCOPE_OR_SEQUENCE_INVALID');
 deny(f=>{f.x.observations[1].witnesses.ADMIN_WITNESS={};},
 'DP_TWO_DISTINCT_PINNED_WITNESS_KEYS_INVALID');
 deny(f=>{f.x.observations[1].claimedReleaseDecision='GO';},
 'DP_OBSERVATION_SCHEMA_OR_SIZE_INVALID');
});
test('DP bounded observation count: single packet, nine or circular packet denied',()=>{
 deny(f=>{f.x.observations=f.x.observations.slice(0,1);},
 'DP_TWO_TO_EIGHT_OBSERVATIONS_REQUIRED');
 deny(f=>{f.x.observations=Array(9).fill(f.x.observations[0]);},
 'DP_TWO_TO_EIGHT_OBSERVATIONS_REQUIRED');
 deny(f=>{f.x.observations[1].loop=f.x.observations[1];},
 'DP_OBSERVATION_SCHEMA_OR_SIZE_INVALID');
});
test('DP self-signed witnesses and pinned matching copies never promote legal/MCA authority',()=>{
 const a=assess();hold(a);
 assert.equal(a.verifiedDualSignedPacketsMathematicallyOnly,2);
 assert.equal(a.rawManifestNonceKeyPemsAndWitnessSignaturesExcluded,true);
});
test('DP output never contains source nonce, witness PEM, signatures or registrar registry digest',()=>{
 const f=fixture(),out=JSON.stringify(
  assessRegistrarWitnessEquivocationCandidate(f.x));
 for(const secret of [NONCE,REG,
  f.x.observations[0].witnesses.LEGAL_WITNESS.publicKeyPem,
  f.x.observations[0].witnesses.REGISTRY_WITNESS.signature,
  f.x.observations[0].claimedCheckpointSha256])
  assert.equal(out.includes(secret),false);
});
test('DP no network, local file writes or approval/mutation API',()=>{
 const code=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dp-offline-registrar-witness-equivocation.mjs'),'utf8');
 assert.equal(/fetch\s*\(|writeFileSync|process\.env|https?:\/\//.test(code),false);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(code),false);
 assert.ok(code.includes('verify(null,witnessSigningBytes('));
 assert.equal(code.includes('productionReleaseAuthorized:true'),false);
});

function relabelUnsignedKeyId(packet,id){
 packet.witnesses.LEGAL_WITNESS.keyId=id;
 packet.claimedCheckpointSha256=hash(Buffer.from(
  DOMAIN+'checkpoint/v1\n'+canonical({manifest:packet.manifest,
   signatures:WITNESS_ROLES.map(role=>
    [role,packet.witnesses[role].keyId,packet.witnesses[role].signature])}),
  'utf8'));
}
test('DQ identical dual-signed receipts remain duplicate, no metadata-drift warning',()=>{
 const r=assess();hold(r);
 assert.equal(r.distinctCryptographicallySignedManifestDigestsOnly,1);
 assert.equal(r.checkpointHashDriftWithoutSignedManifestForkObservedOnly,false);
 assert.equal(r.unsignedWitnessKeyIdMetadataDriftObservedOnly,false);
 assert.equal(r.witnessKeyIdBoundByRoleSignature,false);
});
test('DQ forged equivocation via unsigned keyId-only relabel is correctly quarantined',()=>{
 const r=assess(f=>{
  const p=f.x.observations[1],old=p.witnesses.LEGAL_WITNESS.signature;
  relabelUnsignedKeyId(p,'legal-witness-alias');
  assert.equal(p.witnesses.LEGAL_WITNESS.signature,old);
 });
 assert.equal(r.verifiedDualSignedPacketsMathematicallyOnly,2);
 assert.equal(r.distinctNextCheckpointDigestsOnly,2);
 assert.equal(r.distinctCryptographicallySignedManifestDigestsOnly,1);
 assert.equal(r.sameSequenceConflictingDualSignedHeadsObservedOnly,false);
 assert.equal(r.checkpointHashDriftWithoutSignedManifestForkObservedOnly,true);
 assert.equal(r.unsignedWitnessKeyIdMetadataDriftObservedOnly,true);
 assert.ok(r.anomalyCodes.includes('DQ_CHECKPOINT_HASH_DRIFT_WITHOUT_SIGNED_MANIFEST_FORK'));
 assert.ok(r.anomalyCodes.includes('DQ_UNBOUND_WITNESS_KEY_ID_METADATA_DRIFT'));
 assert.ok(!r.anomalyCodes.includes('DP_DUAL_SIGNED_SAME_SEQUENCE_EQUIVOCATION'));
});
test('DQ true signed manifest fork remains detectable independently of keyId drift',()=>{
 const r=assess(f=>{
  const m={...f.x.observations[1].manifest,
   expiresAt:'2026-11-20T14:08:00.000Z'};
  f.x.observations[1]=f.signed(m);
  relabelUnsignedKeyId(f.x.observations[1],'legal-witness-alias');
 });
 assert.equal(r.distinctCryptographicallySignedManifestDigestsOnly,2);
 assert.equal(r.sameSequenceConflictingDualSignedHeadsObservedOnly,true);
 assert.equal(r.unsignedWitnessKeyIdMetadataDriftObservedOnly,true);
 assert.ok(r.anomalyCodes.includes('DP_DUAL_SIGNED_SAME_SEQUENCE_EQUIVOCATION'));
 assert.ok(r.anomalyCodes.includes('DQ_UNBOUND_WITNESS_KEY_ID_METADATA_DRIFT'));
});
test('DQ invalid relabeled signature is not eligible for signed fork claims',()=>{
 const r=assess(f=>{
  const m={...f.x.observations[1].manifest,
   expiresAt:'2026-11-20T14:08:00.000Z'};
  const p=f.signed(m);
  relabelUnsignedKeyId(p,'legal-witness-alias');
  p.witnesses.LEGAL_WITNESS.signature='A'.repeat(86)+'==';
  f.x.observations[1]=p;
 });
 assert.equal(r.verifiedDualSignedPacketsMathematicallyOnly,1);
 assert.equal(r.sameSequenceConflictingDualSignedHeadsObservedOnly,false);
 assert.equal(r.unsignedWitnessKeyIdMetadataDriftObservedOnly,false);
 assert.ok(r.anomalyCodes.includes('DP_INVALID_SIGNED_WITNESS_OBSERVATION'));
 assert.ok(r.anomalyCodes.includes('DP_INCOMPLETE_VALID_OBSERVATION_QUORUM'));
});
test('DQ triple observation separates keyId-label ambiguity from signed-payload divergence',()=>{
 const r=assess(f=>{
  const copy=structuredClone(f.x.observations[0]);
  relabelUnsignedKeyId(copy,'legal-witness-alias');
  f.x.observations=[f.x.observations[0],copy,
   f.signed({...f.x.observations[0].manifest,
    issuedAt:'2026-11-20T13:58:00.000Z'})];
 });
 assert.equal(r.verifiedDualSignedPacketsMathematicallyOnly,3);
 assert.equal(r.distinctNextCheckpointDigestsOnly,3);
 assert.equal(r.distinctCryptographicallySignedManifestDigestsOnly,2);
 assert.equal(r.sameSequenceConflictingDualSignedHeadsObservedOnly,true);
 assert.equal(r.unsignedWitnessKeyIdMetadataDriftObservedOnly,true);
});
test('DQ redacted anomaly output and immutable HARD HOLD survive unsigned key relabel',()=>{
 const f=fixture();relabelUnsignedKeyId(f.x.observations[1],
  'legal-witness-alias');
 const r=assessRegistrarWitnessEquivocationCandidate(f.x),json=JSON.stringify(r);
 hold(r);
 for(const secret of [NONCE,REG,
  f.x.observations[0].witnesses.LEGAL_WITNESS.signature,
  f.x.observations[0].witnesses.LEGAL_WITNESS.publicKeyPem,
  f.x.observations[1].claimedCheckpointSha256])
  assert.equal(json.includes(secret),false);
});
