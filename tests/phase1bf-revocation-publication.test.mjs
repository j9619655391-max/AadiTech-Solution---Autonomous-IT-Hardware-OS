import test from 'node:test';
import assert from 'node:assert/strict';
import {bfFixture,h} from './support/phase1bfFixture.mjs';
import {assessPhase1BfPublication,phase1BfPublicationSigningBytes}
 from '../scripts/lib/phase1BfRevocationPublication.mjs';
const assess=x=>assessPhase1BfPublication(x);

test('zero-input revocation publication always hard-HOLDs and never creates authority',()=>{
 const r=assess();
 assert.equal(r.locallySignedPublicationConsistent,false);
 assert.equal(r.publicationSha256,null);
 assert.equal(r.independentlyAuthenticatedRevocationPublisher,false);
 assert.equal(r.actualExternalWitnessRevocationVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.ok(r.blockerCodes.includes('INCOMPLETE_REVOCATION_PUBLICATION'));
});
test('three locally distinct Ed25519 signers cannot authorize external revocation',()=>{
 const f=bfFixture(),r=assess(f);
 assert.equal(r.locallySignedPublicationConsistent,true,r.blockerCodes.join(','));
 assert.match(r.publicationSha256,/^[0-9a-f]{64}$/);
 assert.match(r.freezeIncidentSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.publicationSequence,1);
 assert.equal(r.independentlyAuthenticatedRevocationPublisher,false);
 assert.equal(r.actualExternalWitnessRevocationVerified,false);
 assert.equal(r.realProviderWormRetentionVerified,false);
 assert.equal(r.realEncryptedDrAcceptanceVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('forged, missing or invalid publisher, survivor, security signatures fail closed',()=>{
 for(const role of ['publisher','survivingWitness','securityReviewer']){
  const f=bfFixture();
  f[role].signature.signatureBase64=Buffer.alloc(64,7).toString('base64');
  const result=assess(f);
  assert.equal(result.locallySignedPublicationConsistent,false,role);
  assert.ok(result.blockerCodes.includes('INVALID_PUBLICATION_COSIGNATURE'),role);
 }
 const missing=bfFixture();
 missing.publisher=null;
 assert.ok(assess(missing).blockerCodes.includes('INCOMPLETE_REVOCATION_PUBLICATION'));
});
test('publisher cannot share witness or governance administrator or substitute their pins',()=>{
 const f=bfFixture();
 f.publisher.pin.authorityRef=f.survivingWitness.pin.authorityRef;
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('PUBLISHER_COMMON_CONTROL_OR_KEY_REUSE'));
 assert.ok(r.blockerCodes.includes('REPLACED_PUBLISHER_WITNESS_OR_SECURITY_PIN'));
 const g=bfFixture();
 g.securityReviewer.pin.publicKeySha256=g.survivingWitness.pin.publicKeySha256;
 assert.equal(assess(g).locallySignedPublicationConsistent,false);
 assert.ok(assess(g).blockerCodes.includes('PUBLISHER_COMMON_CONTROL_OR_KEY_REUSE'));
});
test('changing submitted publisher, legal policy or WORM receipt changes digest but remains untrusted',()=>{
 const f=bfFixture(),initial=assess(f);
 f.body.publisherPolicySha256=h(930);
 f.resign();
 const changed=assess(f);
 assert.equal(changed.locallySignedPublicationConsistent,true,changed.blockerCodes.join(','));
 assert.notEqual(initial.publicationSha256,changed.publicationSha256);
 assert.equal(changed.realProviderWormRetentionVerified,false);
 const x=bfFixture();
 x.body.claimedObjectLockDenialReceiptSha256=h(940);
 x.resign();
 assert.ok(assess(x).blockerCodes.includes('PUBLICATION_FREEZE_ARCHIVE_AND_DR_BINDING_MISMATCH'));
});
test('claimed CRL/OCSP or provider digest substitution cannot bypass frozen source-of-truth binding',()=>{
 for(const field of ['freezeIncidentSha256','azPacketSha256','bdReviewSha256',
  'revokedKeySpkiSha256','survivingWitnessRef','checkpointReceiptSha256',
  'storageObjectVersionSha256','priorRevocationSnapshotSha256',
  'claimedIssuedRevocationSha256','claimedEncryptedRestoreTelemetrySha256']){
  const f=bfFixture();
  f.body[field]=field==='survivingWitnessRef'?'new-surviving-ref-001':h(956);
  f.resign();
  const r=assess(f);
  assert.equal(r.locallySignedPublicationConsistent,false,field);
  assert.ok(r.blockerCodes.includes('PUBLICATION_FREEZE_ARCHIVE_AND_DR_BINDING_MISMATCH'),field);
 }
});
test('replay, rollback and chain gap evidence cannot be encoded as first publication',()=>{
 const f=bfFixture();
 for(const v of [
  {...f.body,publicationSequence:0},
  {...f.body,publicationSequence:2,previousPublicationSha256:null},
  {...f.body,publicationSequence:1,previousPublicationSha256:h(1)},
  {...f.body,publicationSequence:2,previousPublicationSha256:'0'.repeat(64)},
  {...f.body,publicationSequence:1000001,previousPublicationSha256:h(1)}
 ])assert.throws(()=>phase1BfPublicationSigningBytes(v));
 const second=bfFixture();
 second.body.publicationSequence=2;second.body.previousPublicationSha256=h(12);
 second.resign();
 assert.equal(assess(second).locallySignedPublicationConsistent,true);
 assert.equal(assess(second).productionReleaseAuthorized,false);
});
test('invalid GO, late publication, reused compromised SPKI and raw credential fields fail',()=>{
 const f=bfFixture();
 for(const v of [
  {...f.body,releaseDecision:'GO'},
  {...f.body,revocationState:'REVOCATION_VERIFIED'},
  {...f.body,quarantineRequired:false},
  {...f.body,outboundHeld:false},
  {...f.body,privateKey:'DO_NOT_ACCEPT'},
  {...f.body,publisherPublicKeySha256:f.body.revokedKeySpkiSha256},
  {...f.body,observedAt:'2026-11-16T18:12:00.000Z'},
  {...f.body,expiresAt:'2026-11-16T18:04:00.000Z'}
 ])assert.throws(()=>phase1BfPublicationSigningBytes(v));
 assert.throws(()=>assess({...f,secretToken:'DO_NOT_ACCEPT'}));
});
test('publication which predates freeze activation or is expired at assessment never passes',()=>{
 const f=bfFixture();
 f.body.issuedAt='2026-11-16T17:30:00.000Z';
 f.body.observedAt='2026-11-16T17:31:00.000Z';
 f.body.expiresAt='2026-11-16T18:20:00.000Z';
 f.resign();
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('PUBLICATION_EXPIRED_FUTURE_OR_PREDATES_FREEZE'));
 const future=bfFixture();
 assert.ok(assess({...future,now:new Date('2026-11-16T19:00:00.000Z')})
  .blockerCodes.includes('PUBLICATION_EXPIRED_FUTURE_OR_PREDATES_FREEZE'));
});
test('a changed upstream freeze despite a previously signed publisher publication is rejected',()=>{
 const f=bfFixture();
 f.freezeEvidence.body.revocationNoticeSha256=h(973);
 const r=assess(f);
 assert.equal(r.locallySignedPublicationConsistent,false);
 assert.ok(r.blockerCodes.includes('UPSTREAM_1BE_FREEZE_SIGNATURE_OR_EVIDENCE_INVALID'));
});
test('zero-input CLI never accepts evidence paths, private keys or release controls',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const path=fileURLToPath(new URL('../scripts/phase1bf-publication-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[path,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const ok=run(['--ci-hold']);
 assert.equal(ok.status,0,ok.stderr);
 const verdict=JSON.parse(ok.stdout);
 assert.equal(verdict.productionReleaseAuthorized,false);
 assert.equal(verdict.actualExternalWitnessRevocationVerified,false);
 for(const args of [[],['--go'],['--enroll-key'],
  ['--provider-secret','NEVER_LOG_SENSITIVE'],
  ['--input','/tmp/secret-provider-certificate']]){
  const denied=run(args);
  assert.equal(denied.status,2);
  assert.equal(denied.stdout,'');
  assert.match(denied.stderr,/HOLD/);
  assert.ok(!denied.stderr.includes('NEVER_LOG_SENSITIVE'));
  assert.ok(!denied.stderr.includes('/tmp/secret-provider-certificate'));
 }
});
