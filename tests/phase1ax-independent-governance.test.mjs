import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 ROLLOVER_PURPOSE,phase1AxRolloverSigningBytes,
 assessPhase1AxKeyRollover,assessPhase1AxCheckpointWitnesses,
 assessPhase1AxRecoveryRehearsal
} from '../scripts/lib/phase1AxIndependentGovernance.mjs';
import {CHECKPOINT_PURPOSE,phase1AwCheckpointReceiptSha256} from '../scripts/lib/phase1AwSignedCheckpoint.mjs';
import {PROVIDER_CODE,REQUESTED_SCOPE} from '../scripts/lib/providerAuthorityPreflight.mjs';
const stamp='2026-11-16T14:00:00.000Z',now=new Date(stamp);
const h=n=>n.toString(16).padStart(64,'0');
function actor(n,authorityRef){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const spki=publicKey.export({format:'der',type:'spki'});
 return {privateKey,pin:{reviewerRef:'reviewer-00'+n,keyId:'reviewer-key-00'+n,
  authorityRef,publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
  publicKeySha256:createHash('sha256').update(spki).digest('hex')}};
}
const detached=(message,actor)=>({reviewerRef:actor.pin.reviewerRef,keyId:actor.pin.keyId,signatureBase64:sign(null,message,actor.privateKey).toString('base64')});
function rollover(){
 const old=actor(1,'authority-old-001'),reviewer=actor(2,'authority-new-002');
 const proposal={schemaVersion:1,purpose:ROLLOVER_PURPOSE,organizationRef:'organization-001',
  generation:2,predecessorDigest:h(111),oldKeyId:old.pin.keyId,
  newKeyId:'replacement-key-003',newPublicKeySha256:h(222),
  proposedAt:'2026-11-16T13:00:00.000Z',activateAt:'2026-11-16T13:30:00.000Z',
  expiresAt:'2026-11-17T13:00:00.000Z',releaseDecision:'HOLD'};
 const bytes=phase1AxRolloverSigningBytes(proposal);
 return {proposal,predecessor:{organizationRef:proposal.organizationRef,generation:1,
  digest:h(111),keyId:old.pin.keyId,status:'ACTIVE'},
  replacement:{keyId:proposal.newKeyId,publicKeySha256:proposal.newPublicKeySha256},
  oldSigner:old.pin,independentApprover:reviewer.pin,
  oldSignature:detached(bytes,old),approvalSignature:detached(bytes,reviewer),now};
}
test('valid fixture rotation is cryptographically consistent but never external authority',()=>{
 const r=assessPhase1AxKeyRollover(rollover());
 assert.equal(r.cryptographicRolloverValid,true);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.deepEqual(r.blockerCodes,['EXTERNAL_REVIEWER_AUTHORITY_UNVERIFIED']);
});
test('rotation denies self approval, signer compromise, replay, key swap and wrong generation',()=>{
 const f=rollover();
 for(const modified of [
  {...f,independentApprover:f.oldSigner},
  {...f,compromised:true},
  {...f,predecessor:{...f.predecessor,generation:2}},
  {...f,replacement:{...f.replacement,publicKeySha256:h(333)}},
  {...f,oldSignature:f.approvalSignature},
  {...f,now:new Date('2026-11-20T00:00:00.000Z')}
 ]){
  const r=assessPhase1AxKeyRollover(modified);
  assert.equal(r.cryptographicRolloverValid,false);
  assert.equal(r.quarantined,true);
  assert.equal(r.productionReleaseAuthorized,false);
 }
 assert.throws(()=>phase1AxRolloverSigningBytes({...f.proposal,releaseDecision:'GO'}));
 assert.throws(()=>phase1AxRolloverSigningBytes({...f.proposal,productionReleaseAuthorized:true}));
});
function checkpoint(seq=1,tail=h(91)){
 return {schemaVersion:1,purpose:CHECKPOINT_PURPOSE,providerCode:PROVIDER_CODE,
  requestedScope:REQUESTED_SCOPE,sequence:seq,
  issuedAt:'2026-11-16T13:00:00.000Z',expiresAt:'2026-11-16T15:00:00.000Z',
  priorCheckpointSha256:seq===1?null:h(7),journalEventCount:1,
  journalTailSha256:tail,policySnapshotSha256:h(3),recoveryClaimSha256:null,
  releaseDecision:'HOLD',signatures:[
   {role:'LEGAL',reviewerRef:'legal-reviewer-001',keyId:'legal-key-001',signatureBase64:Buffer.alloc(64,1).toString('base64')},
   {role:'SECURITY',reviewerRef:'security-reviewer-001',keyId:'security-key-001',signatureBase64:Buffer.alloc(64,2).toString('base64')}
  ]};
}
function observation(cp,witness){
 const receipt=phase1AwCheckpointReceiptSha256(cp);
 return {checkpoint:cp,witnessPinId:witness.pin.keyId,observedAt:stamp,
  witnessSignature:detached(Buffer.from('AADITECH-PHASE-1AX-WITNESS-V1\0'+receipt),witness)};
}
test('independent witness observations enforce threshold and stay release-held',()=>{
 const a=actor(3,'witness-org-003'),b=actor(4,'witness-org-004'),cp=checkpoint();
 const r=assessPhase1AxCheckpointWitnesses({observations:[observation(cp,a),observation(cp,b)],
  trustedPins:[a.pin,b.pin],now});
 assert.equal(r.validWitnessObservations,2);
 assert.equal(r.equivocationDetected,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('fork, duplicate administrative authority, forged witness and outage quarantine',()=>{
 const a=actor(5,'witness-org-005'),b=actor(6,'witness-org-006');
 const one=checkpoint(),two=checkpoint(1,h(888));
 const fork=assessPhase1AxCheckpointWitnesses({observations:[observation(one,a),observation(two,b)],
  trustedPins:[a.pin,b.pin],now});
 assert.equal(fork.equivocationDetected,true);assert.equal(fork.quarantined,true);
 const collision=assessPhase1AxCheckpointWitnesses({observations:[observation(one,a),observation(one,b)],
  trustedPins:[a.pin,{...b.pin,authorityRef:a.pin.authorityRef}],now});
 assert.ok(collision.blockerCodes.includes('WITNESS_AUTHORITY_COLLISION'));
 const outage=assessPhase1AxCheckpointWitnesses({observations:[observation(one,a)],
  trustedPins:[a.pin,b.pin],now});
 assert.ok(outage.blockerCodes.includes('WITNESS_QUORUM_UNAVAILABLE'));
 const forged=observation(one,a);forged.witnessSignature.signatureBase64=Buffer.alloc(64,7).toString('base64');
 const invalid=assessPhase1AxCheckpointWitnesses({observations:[forged],trustedPins:[a.pin,b.pin],now});
 assert.ok(invalid.blockerCodes.includes('INVALID_WITNESS_SIGNATURE'));
});
test('recovery rehearsal rejects corrupt restore, self review, missing revocation and absent RTO/RPO',()=>{
 const basis={baselineDigest:h(1),restoredDigest:h(1),revocationChecked:true,
  securityReviewerRef:'security-operator-001',operationsReviewerRef:'operations-operator-002',
  measuredRtoMs:1200,measuredRpoMs:0};
 const fine=assessPhase1AxRecoveryRehearsal(basis);
 assert.equal(fine.syntheticRecoveryInputsChecked,true);
 assert.equal(fine.realRestoreWitnessed,false);
 for(const modified of [
  {...basis,restoredDigest:h(2)},
  {...basis,operationsReviewerRef:basis.securityReviewerRef},
  {...basis,revocationChecked:false},
  {...basis,measuredRtoMs:null}
 ]){
  const result=assessPhase1AxRecoveryRehearsal(modified);
  assert.equal(result.quarantined,true);
  assert.equal(result.productionReleaseAuthorized,false);
 }
});
