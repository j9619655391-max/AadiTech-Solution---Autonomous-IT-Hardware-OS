import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync,linkSync,mkdtempSync,mkdirSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  EVIDENCE_FIELDS,CCA_CPS_PUBLIC_REFERENCE,CCA_DISCLOSURE_URL,CCA_TRUST_DOMAIN,
  localIncidentInventorySha256,assessPhase1AuPolicyDrift
} from '../scripts/lib/phase1AuPolicyDrift.mjs';
import {
  AUTHORITY_DIGEST_FIELDS,INDEPENDENT_REVIEW_DIGEST_FIELDS,
  PROVIDER_CODE,REQUESTED_SCOPE
} from '../scripts/lib/providerAuthorityPreflight.mjs';

const cli=fileURLToPath(new URL('../scripts/phase1au-policy-drift-preflight.mjs',import.meta.url));
const checkout=fileURLToPath(new URL('../',import.meta.url));
const HOUR=3_600_000;
function at(ms){return new Date(ms).toISOString();}
function snapshot(sequence,nowMs){
  let n=1;
  const digest=()=>(n++).toString(16).padStart(64,'0');
  const artifactDigests=Object.fromEntries(AUTHORITY_DIGEST_FIELDS.map(x=>[x,digest()]));
  const reviewDigests=Object.fromEntries(INDEPENDENT_REVIEW_DIGEST_FIELDS.map(x=>[x,digest()]));
  const recordedAt=nowMs-30*60_000;
  const windows=Object.fromEntries(EVIDENCE_FIELDS.map(kind=>{
    const captured=recordedAt-10*60_000;
    const duration=kind==='authenticatedOcspSnapshotSha256'?50*60_000:
      kind==='authenticatedCrlSnapshotSha256'?12*HOUR:48*HOUR;
    return [kind,{
      capturedAt:at(captured),refreshBy:at(captured+duration),
      revokedAt:null,revocationState:'CLAIMED_NOT_REVOKED'
    }];
  }));
  return {
    schemaVersion:1,providerCode:PROVIDER_CODE,requestedScope:REQUESTED_SCOPE,
    sequence,recordedAt:at(recordedAt),
    policy:{
      ccaCpsVersion:CCA_CPS_PUBLIC_REFERENCE,ccaDisclosureUrl:CCA_DISCLOSURE_URL,
      trustDomain:CCA_TRUST_DOMAIN,incidentDenylistSha256:localIncidentInventorySha256()
    },
    artifactDigests,reviewDigests,windows
  };
}
function pair(now=Date.now()){
 const baseline=snapshot(1,now-20*60_000);
 const current=snapshot(2,now);
 return {baseline,current,now:new Date(now)};
}
const run=(args,envOverrides={},cwd=checkout)=>spawnSync(process.execPath,[cli,...args],{
  env:{
    ...process.env,CI:'false',GITHUB_ACTIONS:'false',NODE_ENV:'test',
    PHASE_1AU_OFFLINE_REVIEW_APPROVED:'YES',...envOverrides
  },cwd,encoding:'utf8',timeout:8000,maxBuffer:32_768
});

test('Phase 1AU zero-input snapshot and all synthetic well-formed claims remain untrusted and held',()=>{
 const hold=assessPhase1AuPolicyDrift();
 assert.equal(hold.releaseDecision,'HOLD');
 assert.equal(hold.policyDriftDetected,null);
 assert.equal(hold.currentInventoryInspected,false);
 const {baseline,current,now}=pair(Date.parse('2026-11-16T12:00:00Z'));
 const r=assessPhase1AuPolicyDrift(baseline,current,now);
 assert.equal(r.currentInventoryInspected,true);
 assert.equal(r.baselineInventoryInspected,true);
 assert.equal(r.policyDriftDetected,false);
 assert.equal(r.changedClaimCount,0);
 assert.equal(r.dueSoonEvidenceCount,1); // OCSP claim requires recheck shortly
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.authorizedCredentialsBound,false);
 assert.equal(r.externalProviderIdentityVerified,false);
 assert.equal(r.independentlyAuthenticatedRcaiCaChain,false);
 assert.equal(r.authenticatedLiveCrlOcsp,false);
 assert.equal(r.legallyVerifiedMcaAndSignatory,false);
 assert.equal(r.officialGrnVerified,false);
 assert.equal(r.stockPostingEnabled,false);
 assert.ok(r.blockers.includes('NO_AUTHENTICATED_EXTERNAL_PROVIDER_OR_LEGAL_APPROVAL'));
});
test('claims of changed CPS, denylist inventory or certificate hash require independent review',()=>{
 const {baseline,current,now}=pair(Date.parse('2026-11-16T12:00:00Z'));
 current.policy.ccaCpsVersion='4.2.0';
 current.policy.incidentDenylistSha256='f'.repeat(64);
 current.artifactDigests.rcaiRootCertificateSha256='e'.repeat(64);
 const r=assessPhase1AuPolicyDrift(baseline,current,now);
 assert.equal(r.policyDriftDetected,true);
 assert.equal(r.incidenceInventoryChanged,true);
 assert.equal(r.currentCpsReferenceMismatch,true);
 assert.equal(r.changedClaimCount,1);
 for(const reason of ['POLICY_REFERENCE_DRIFT','PUBLIC_CPS_REFERENCE_MISMATCH',
   'PUBLIC_INCIDENT_INVENTORY_CHANGED','SHA_CLAIM_CHANGED_REVIEW_REQUIRED'])
  assert.ok(r.blockers.includes(reason));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('stale OCSP, revoked CRL, unchecked revocation and status rollback never grant trust',()=>{
 const {baseline,current,now}=pair(Date.parse('2026-11-16T12:00:00Z'));
 const ocsp=current.windows.authenticatedOcspSnapshotSha256;
 ocsp.refreshBy=at(now.getTime()-60_000);
 const crl=current.windows.authenticatedCrlSnapshotSha256;
 crl.revocationState='REVOKED';crl.revokedAt=current.recordedAt;
 const registry=current.windows.mcaCorporateRegistrySha256;
 registry.revocationState='UNKNOWN';
 const r=assessPhase1AuPolicyDrift(baseline,current,now);
 assert.equal(r.expiredEvidenceCount,1);
 assert.equal(r.revokedEvidenceCount,1);
 assert.equal(r.unknownRevocationCount,1);
 assert.equal(r.productionReleaseAuthorized,false);
 baseline.windows.authenticatedCrlSnapshotSha256.revocationState='REVOKED';
 baseline.windows.authenticatedCrlSnapshotSha256.revokedAt=baseline.recordedAt;
 crl.revocationState='CLAIMED_NOT_REVOKED';crl.revokedAt=null;
 const rollback=assessPhase1AuPolicyDrift(baseline,current,now);
 assert.equal(rollback.evidenceReviewRollbackDetected,true);
 assert.ok(rollback.blockers.includes('REVOCATION_OR_REVIEW_ROLLBACK'));
});
test('sequence rollback and missing baseline remain hard holds',()=>{
 const {baseline,current,now}=pair(Date.parse('2026-11-16T12:00:00Z'));
 const alone=assessPhase1AuPolicyDrift(null,current,now);
 assert.equal(alone.releaseDecision,'HOLD');
 assert.ok(alone.blockers.includes('NO_INDEPENDENT_BASELINE'));
 current.sequence=baseline.sequence;
 const r=assessPhase1AuPolicyDrift(baseline,current,now);
 assert.equal(r.evidenceReviewRollbackDetected,true);
 assert.ok(r.blockers.includes('EVIDENCE_SEQUENCE_ROLLBACK'));
 assert.equal(assessPhase1AuPolicyDrift(baseline,null,now).currentInventoryInspected,false);
});
test('invalid evidence windows, unknown fields, credential injections and forged positive status fail closed',()=>{
 const now=Date.parse('2026-11-16T12:00:00Z');
 const mutate=[
   s=>{s.productionReleaseAuthorized=true;},
   s=>{s.policy.officialCaApproved=true;},
   s=>{s.providerCode='EMUDHRA_PRODUCTION';},
   s=>{s.requestedScope='STOCK_POSTING';},
   s=>{s.policy.trustDomain='GLOBAL_WEBPKI_TLS';},
   s=>{s.artifactDigests.providerApiKey='secret';},
   s=>{s.windows.securityReviewSha256.status='VERIFIED';},
   s=>{s.windows.authenticatedOcspSnapshotSha256.revocationState='VERIFIED';},
   s=>{s.windows.authenticatedOcspSnapshotSha256.refreshBy=at(now+2*HOUR);},
   s=>{s.windows.authenticatedCrlSnapshotSha256.revocationState='REVOKED';},
   s=>{s.windows.authenticatedCrlSnapshotSha256.revokedAt=at(now+HOUR);},
   s=>{s.recordedAt=at(now+10*60_000);},
   s=>{delete s.windows.mcaCorporateRegistrySha256;},
   s=>{s.policy.ccaCpsVersion='../../private';},
   s=>{s.reviewDigests.legalReviewSha256=s.artifactDigests.signedAgreementSha256;}
 ];
 for(const change of mutate){
   const sample=snapshot(2,now);change(sample);
   assert.throws(()=>assessPhase1AuPolicyDrift(null,sample,new Date(now)));
 }
});
test('private offline pair reports only aggregate drift and exits HOLD; denies CI/production and path attacks',()=>{
 const dir=mkdtempSync(join(tmpdir(),'phase1au-policy-drift-'));
 const packetDir=join(dir,'private');mkdirSync(packetDir,{mode:0o700});
 const oldPath=join(packetDir,'previous.json'),newPath=join(packetDir,'current.json');
 const {baseline,current}=pair();
 const put=(p,v)=>writeFileSync(p,JSON.stringify(v),{mode:0o600});
 try{
  put(oldPath,baseline);put(newPath,current);
  const ok=run(['--offline-pair',oldPath,newPath],{},dir);
  assert.equal(ok.status,2,ok.stderr);
  assert.equal(ok.stderr,'');
  const report=JSON.parse(ok.stdout);
  assert.equal(report.releaseDecision,'HOLD');
  assert.equal(report.currentInventoryInspected,true);
  assert.equal(report.productionReleaseAuthorized,false);
  assert.ok(!ok.stdout.includes(oldPath));
  assert.ok(!ok.stdout.includes(current.artifactDigests.signedAgreementSha256));
  for(const overrides of [
    {CI:'true'},{GITHUB_ACTIONS:'true'},{NODE_ENV:'production'},
    {PHASE_1AU_OFFLINE_REVIEW_APPROVED:'NO'}
  ]){
    const denied=run(['--offline-pair',oldPath,newPath],overrides,dir);
    assert.equal(denied.status,2);
    assert.equal(denied.stdout,'');
  }
  const alias=join(packetDir,'alias.json');
  symlinkSync(newPath,alias);
  assert.equal(run(['--offline-pair',oldPath,alias]).status,2);
  chmodSync(newPath,0o644);
  assert.equal(run(['--offline-pair',oldPath,newPath]).status,2);
  chmodSync(newPath,0o600);
  const hard=join(packetDir,'hard.json');linkSync(newPath,hard);
  assert.equal(run(['--offline-pair',oldPath,newPath]).status,2);
  for(const args of [
    ['--promote'],['--offline-pair',oldPath],['--offline-pair',oldPath,oldPath],
    ['--offline-pair','relative.json',newPath]
  ])assert.equal(run(args).status,2);
  const ci=run(['--ci-hold'],{CI:'true',GITHUB_ACTIONS:'true',NODE_ENV:'production'},dir);
  assert.equal(ci.status,0,ci.stderr);
  assert.equal(JSON.parse(ci.stdout).releaseDecision,'HOLD');
  assert.equal(JSON.parse(ci.stdout).productionReleaseAuthorized,false);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('Phase 1AP and Phase 1AQ CI gate regression: no provider trust or stock activation',()=>{
 for(const script of ['scripts/provider-authority-preflight.mjs',
   'scripts/phase1aq-trust-incident-preflight.mjs']){
  const s=spawnSync(process.execPath,[join(checkout,script),'--ci-hold'],{
    encoding:'utf8',timeout:8000
  });
  assert.equal(s.status,0,s.stderr);
  const report=JSON.parse(s.stdout);
  assert.equal(report.releaseDecision,'HOLD');
  assert.equal(report.productionReleaseAuthorized,false);
  assert.equal(report.stockPostingEnabled,false);
 }
});
