import test from 'node:test';
import assert from 'node:assert/strict';
import {bgFixture,h} from './support/phase1bgFixture.mjs';
import {assessPhase1BgEvidenceQuorum,phase1BgSigningBytes,
 phase1BgAuditorPinsetSha256}
 from '../scripts/lib/phase1BgCrossSourceAcceptance.mjs';
const assess=x=>assessPhase1BgEvidenceQuorum(x);
test('zero inputs never claim authenticated revocation or production authority',()=>{
 const x=assess();
 assert.equal(x.locallyConsistentAuditQuorum,false);
 assert.equal(x.reviewSha256,null);
 assert.equal(x.externallyAuthenticatedIssuer,false);
 assert.equal(x.liveCrlOcspRevocationVerified,false);
 assert.equal(x.realCloudWormComplianceVerified,false);
 assert.equal(x.realEncryptedDrVerified,false);
 assert.equal(x.productionReleaseAuthorized,false);
 assert.equal(x.productionReleaseBlocked,true);
 assert.equal(x.releaseDecision,'HOLD');
});
test('three disjoint synthetic auditors consistently bind the exact claimed upstream evidence',()=>{
 const f=bgFixture(),r=assess(f);
 assert.equal(r.locallyConsistentAuditQuorum,true,r.blockerCodes.join(','));
 assert.match(r.reviewSha256,/^[0-9a-f]{64}$/);
 assert.match(r.previousPublicationSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.reviewRevision,1);
 assert.equal(r.crlNumber,1);
 assert.equal(r.independentlyAuthenticatedAuditKeys,false);
 assert.equal(r.liveCrlOcspRevocationVerified,false);
 assert.equal(r.realCloudWormComplianceVerified,false);
 assert.equal(r.realEncryptedDrVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('changing the order of independent signers never changes the digest commitment',()=>{
 const f=bgFixture(),original=assess(f);
 f.auditors.reverse();
 const reordered=assess(f);
 assert.equal(reordered.locallyConsistentAuditQuorum,true,reordered.blockerCodes.join(','));
 assert.equal(reordered.reviewSha256,original.reviewSha256);
 assert.equal(reordered.auditorPinSetSha256,original.auditorPinSetSha256);
});
test('a locally signed claimed new CRL number and OCSP digest change commitment, not trust',()=>{
 const f=bgFixture(),first=assess(f);
 f.manifest.crlNumber=2;
 f.manifest.ocspResponseSha256=h(5999);
 f.resign();
 const r=assess(f);
 assert.equal(r.locallyConsistentAuditQuorum,true,r.blockerCodes.join(','));
 assert.notEqual(r.reviewSha256,first.reviewSha256);
 assert.equal(r.liveCrlOcspRevocationVerified,false);
});
test('changed published BF revocation, frozen digest or claimed provider/storage/DR scope fails',()=>{
 const fields=['publicationSha256','freezeIncidentSha256','publisherPinSha256',
  'crlIssuerSha256','crlSnapshotSha256','revokedKeySpkiSha256',
  'wormVersionSha256','wormRetentionPolicySha256','wormDeleteDenialSha256',
  'wormOverwriteDenialSha256','wormReadbackSha256','restoreReceiptSha256',
  'restoreTelemetrySha256','restoredManifestSha256'];
 for(const field of fields){
  const f=bgFixture();f.manifest[field]=h(5757);f.resign();
  const r=assess(f);
  assert.equal(r.locallyConsistentAuditQuorum,false,field);
  assert.ok(r.blockerCodes.includes('CROSS_SOURCE_PUBLICATION_STORAGE_DR_SCOPE_MISMATCH'),field);
 }
});
test('attacker cannot reclassify CRL/OCSP from stale snapshot or use expired responses',()=>{
 const f=bgFixture();
 f.manifest.crlSnapshotSha256=f.publication.body.priorRevocationSnapshotSha256;
 f.resign();
 assert.ok(assess(f).blockerCodes.includes('STALE_OR_REUSED_CRL_OCSP_DIGEST'));
 const g=bgFixture();
 g.manifest.ocspResponseSha256=g.manifest.crlSnapshotSha256;
 g.resign();
 assert.ok(assess(g).blockerCodes.includes('STALE_OR_REUSED_CRL_OCSP_DIGEST'));
 for(const change of [
  {crlNextUpdate:'2026-11-16T18:06:00.000Z'},
  {ocspNextUpdate:'2026-11-16T18:09:00.000Z'},
  {expiresAt:'2026-11-16T18:20:00.000Z'},
  {wormRetentionUntil:'2026-11-16T18:14:00.000Z'}
 ]){
  const t=bgFixture();
  assert.throws(()=>phase1BgSigningBytes({...t.manifest,...change}));
 }
});
test('forged revocation, storage or DR auditor signature fails without role promotion',()=>{
 for(let i=0;i<3;i++){
  const f=bgFixture();
  f.auditors[i].signature.signatureBase64=Buffer.alloc(64,9).toString('base64');
  const r=assess(f);
  assert.equal(r.locallyConsistentAuditQuorum,false);
  assert.ok(r.blockerCodes.includes('INVALID_INDEPENDENT_CANDIDATE_SIGNATURE'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('common control, duplicated admin, pinset substitution and missing independent role deny',()=>{
 const f=bgFixture();
 f.auditors[1].pin.authorityRef=f.auditors[0].pin.authorityRef;
 assert.ok(assess(f).blockerCodes.includes('COMMON_CONTROL_OR_KEY_REUSE_ACROSS_AUDITORS'));
 const g=bgFixture();
 g.auditors[2].pin.authorityRef=g.publication.publisher.pin.authorityRef;
 assert.ok(assess(g).blockerCodes.includes('COMMON_CONTROL_OR_KEY_REUSE_ACROSS_AUDITORS'));
 const k=bgFixture();
 k.manifest.auditorPinSetSha256=h(8787);
 k.resign();
 assert.ok(assess(k).blockerCodes.includes('AUDITOR_PINSET_MISMATCH'));
 const dup=bgFixture();
 dup.auditors[2].pin.role='STORAGE_AUDITOR';
 assert.throws(()=>assess(dup),/duplicate auditor role/);
});
test('synthetic RTO/RPO values must match upstream timestamps, not assertions',()=>{
 const f=bgFixture();
 f.manifest.rtoObservedMs++;
 f.resign();
 assert.ok(assess(f).blockerCodes.includes('CROSS_SOURCE_PUBLICATION_STORAGE_DR_SCOPE_MISMATCH'));
 const g=bgFixture();
 g.manifest.rpoObservedMs++;
 g.resign();
 assert.ok(assess(g).blockerCodes.includes('CROSS_SOURCE_PUBLICATION_STORAGE_DR_SCOPE_MISMATCH'));
 const h2=bgFixture();
 h2.publication.freezeEvidence.bdEvidence.recoveryAttestations[0].body.isolatedStaging=false;
 assert.ok(assess(h2).blockerCodes.includes('INVALID_UPSTREAM_PUBLICATION_SIGNATURE_OR_FREEZE'));
});
test('revoked issuer, expired observations, extra key material and GO cannot pass',()=>{
 const f=bgFixture();
 for(const change of [
  {releaseDecision:'GO'},
  {ocspStatus:'GOOD'},
  {outboundHeld:false},
  {privateKey:'DO_NOT_ACCEPT'},
  {reviewRevision:2,previousReviewSha256:null},
  {crlNumber:0}
 ])assert.throws(()=>phase1BgSigningBytes({...f.manifest,...change}));
 assert.throws(()=>assess({...f,token:'DO_NOT_STORE'}));
 const expired=bgFixture();
 assert.ok(assess({...expired,now:new Date('2026-11-16T18:16:00.000Z')})
  .blockerCodes.includes('STALE_FUTURE_OR_EXPIRED_SOURCE_REVIEW'));
});
test('publication substitution invalidates fully co-signed downstream candidate review',()=>{
 const f=bgFixture();
 f.publication.publisher.signature.signatureBase64=
  Buffer.alloc(64,17).toString('base64');
 assert.ok(assess(f).blockerCodes.includes('INVALID_UPSTREAM_PUBLICATION_SIGNATURE_OR_FREEZE'));
});
test('zero-input CI gate refuses provider credentials, evidence files and release switches',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const file=fileURLToPath(new URL('../scripts/phase1bg-cross-source-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[file,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const valid=run(['--ci-hold']);
 assert.equal(valid.status,0,valid.stderr);
 const output=JSON.parse(valid.stdout);
 assert.equal(output.productionReleaseAuthorized,false);
 assert.equal(output.liveCrlOcspRevocationVerified,false);
 for(const args of [[],['--activate'],['--verify-online'],
  ['--ci-hold','--secret','SECRET_DO_NOT_ECHO'],
  ['--provider-evidence','/tmp/private-documents']]){
  const r=run(args);
  assert.equal(r.status,2);
  assert.equal(r.stdout,'');
  assert.match(r.stderr,/HOLD/);
  assert.ok(!r.stderr.includes('SECRET_DO_NOT_ECHO'));
  assert.ok(!r.stderr.includes('/tmp/private-documents'));
 }
});
