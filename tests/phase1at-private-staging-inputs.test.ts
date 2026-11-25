import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
 chmodSync,linkSync,mkdtempSync,mkdirSync,rmSync,symlinkSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readPrivateStagingReviewInputs} from '../scripts/lib/privateStagingReviewInputs';
import {REQUIRED_EVIDENCE_KINDS} from '../scripts/lib/stagingEvidenceIntegrity';

const repoRoot=fileURLToPath(new URL('../',import.meta.url));
const cli=fileURLToPath(new URL('../scripts/review-staging-acceptance.ts',import.meta.url));
const tsxLoader=import.meta.resolve('tsx');
const env={
 ...process.env,CI:'false',GITHUB_ACTIONS:'false',NODE_ENV:'test',
 STAGING_ACCEPTANCE_REVIEW:'YES',STAGING_PRIVATE_JSON_REVIEW_APPROVED:'YES'
};
const iso=(time:number)=>new Date(time).toISOString();

function syntheticAcceptance(){
 const now=Date.now();
 const h=60_000;
 const backup=now-120*h;
 return {
  changeTicket:'CHG-1AT-ISOLATED',stagingOrigin:'https://staging.synthetic.example.invalid',
  operatorId:'operator-001',independentSecurityReviewerId:'security-reviewer-002',
  independentInfrastructureReviewerId:'infra-reviewer-003',
  securityApprovalReference:'CI-SECURITY-REFERENCE',
  infrastructureApprovalReference:'CI-INFRA-REFERENCE',reviewerSignedAt:iso(now-20*h),
  networkIsolationEvidenceRef:'CI-ISOLATION-REFERENCE',
  proxyHeaderRewriteEvidenceRef:'CI-PROXY-REFERENCE',
  mysqlCaEvidenceRef:'CI-MYSQL-CA-REFERENCE',
  realHttpsBrowserMfaEvidenceRef:'CI-MFA-REFERENCE',
  outboundDispatchHeldEvidenceRef:'CI-DISPATCH-HOLD-REFERENCE',
  probe:{
   targetOrigin:'https://staging.synthetic.example.invalid',
   changeTicket:'CHG-1AT-ISOLATED',observedAt:iso(now-40*h),
   observedChecksPassed:true,failures:[],
   proxyIpOverwriteIndependentlyVerified:true,
   directListenerIsolationIndependentlyVerified:true,
   databaseTlsIndependentlyVerified:true,productionReleaseAuthorized:false
  },
  actualRestoreReview:{
   changeTicket:'CHG-1AT-ISOLATED',evidenceLocation:'CI-PRIVATE-VAULT-REFERENCE',
   operatorId:'operator-001',independentWitnessId:'independent-restore-004',
   witnessApprovalReference:'CI-WITNESS-REFERENCE',
   isolatedNetworkVerified:true,outboundDispatchDisabled:true,
   stagingTlsVerified:true,
   objectives:{maxRtoMinutes:60,maxRpoMinutes:5},
   evidence:{
    targetDatabase:'aaditech_staging_synthetic',
    sourceSnapshotSha256:'a'.repeat(64),restoredSnapshotSha256:'a'.repeat(64),
    backupCompletedAt:iso(backup),restoreStartedAt:iso(now-110*h),
    restoreCompletedAt:iso(now-80*h),sourceAsOf:iso(backup),
    recoveryPointAsOf:iso(backup-2*h),
    tableCountsMatch:true,sampledRecordHashesMatch:true,
    mfaKeyRecoveryVerified:true,independentReviewer:'independent-restore-004',
    reviewerSignoffAt:iso(now-70*h)
   }
  }
 };
}

function fixture(){
 const base=mkdtempSync(join(tmpdir(),'aaditech-phase1at-private-'));
 const privateRoot=join(base,'operator-private');
 const evidenceRoot=join(base,'evidence');
 mkdirSync(privateRoot,{mode:0o700});
 mkdirSync(evidenceRoot,{mode:0o700});
 const acceptance=syntheticAcceptance();
 const files=REQUIRED_EVIDENCE_KINDS.map(kind=>{
  const content='SYNTHETIC ONLY: '+kind;
  const path=kind+'.txt';
  writeFileSync(join(evidenceRoot,path),content,{mode:0o600});
  return {kind,path,sha256:createHash('sha256').update(content).digest('hex')};
 });
 const manifest={
  schemaVersion:1,changeTicket:acceptance.changeTicket,
  stagingOrigin:acceptance.stagingOrigin,files
 };
 const a=join(privateRoot,'acceptance.json'),m=join(privateRoot,'manifest.json');
 const write=(path:string,value:unknown)=>writeFileSync(path,JSON.stringify(value),{mode:0o600});
 write(a,acceptance);write(m,manifest);
 return {base,privateRoot,evidenceRoot,acceptance,manifest,a,m,write};
}

function runCli(args:string[],overrides:Record<string,string>={},cwd=repoRoot){
 return spawnSync(process.execPath,['--import',tsxLoader,cli,...args],{
  cwd,env:{...env,...overrides},encoding:'utf8',timeout:12_000,maxBuffer:48_000
 });
}

test('complete synthetic private staging inventory is inspectable but never a release approval',()=>{
 const f=fixture();
 try{
  const parsed=readPrivateStagingReviewInputs(f.a,f.m);
  assert.equal(parsed.acceptance.changeTicket,f.acceptance.changeTicket);
  assert.equal(parsed.manifest.files.length,12);
  const checked=runCli([f.a,f.m,f.evidenceRoot],{},f.base);
  assert.equal(checked.status,2,checked.stderr);
  assert.equal(checked.stderr,'');
  const report=JSON.parse(checked.stdout);
  assert.equal(report.submittedEvidenceComplete,true);
  assert.equal(report.integrityChecksPassed,true);
  assert.equal(report.checkedEvidenceFileCount,12);
  assert.equal(report.privateEvidenceInspected,true);
  assert.equal(report.productionReleaseAuthorized,false);
  assert.equal(report.signerIdentityExternallyVerified,false);
  assert.equal(report.independentlyWitnessedRestoreVerified,false);
  assert.equal(report.releaseDecision,'HOLD');
  assert.ok(!checked.stdout.includes(f.a));
  assert.ok(!checked.stdout.includes(f.acceptance.operatorId));
  assert.ok(!checked.stdout.includes(f.manifest.files[0].sha256));
 }finally{rmSync(f.base,{recursive:true,force:true});}
});

test('private JSON reader rejects wrong permissions, hardlinks, symlinks and wrong directories',()=>{
 const f=fixture(),alias=join(f.privateRoot,'linked.json'),hardlink=join(f.privateRoot,'hardlink.json');
 try{
  chmodSync(f.a,0o644);
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  chmodSync(f.a,0o600);
  chmodSync(f.privateRoot,0o750);
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  chmodSync(f.privateRoot,0o700);
  symlinkSync(f.a,alias);
  assert.throws(()=>readPrivateStagingReviewInputs(alias,f.m));
  linkSync(f.a,hardlink);
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  rmSync(hardlink);
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,join(f.evidenceRoot,'other.json')));
  assert.throws(()=>readPrivateStagingReviewInputs('relative.json',f.m));
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.a));
 }finally{rmSync(f.base,{recursive:true,force:true});}
});

test('reject injection fields, malformed JSON/UTF-8 and oversized private evidence',()=>{
 const f=fixture();
 try{
  f.write(f.a,{...f.acceptance,providerApiToken:'DO_NOT_LOG'});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  f.write(f.a,f.acceptance);
  f.write(f.m,{...f.manifest,productionReleaseAuthorized:true});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  f.write(f.m,f.manifest);
  f.write(f.a,{...f.acceptance,probe:{...f.acceptance.probe,providerKey:'DO_NOT_LOG'}});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  f.write(f.a,f.acceptance);
  writeFileSync(f.m,'{INVALID JSON',{mode:0o600});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  writeFileSync(f.m,Buffer.from([0xff,0xfe,0x80]),{mode:0o600});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
  f.write(f.m,f.manifest);
  writeFileSync(f.m,' '.repeat(32*1024+1),{mode:0o600});
  assert.throws(()=>readPrivateStagingReviewInputs(f.a,f.m));
 }finally{rmSync(f.base,{recursive:true,force:true});}
});

test('checkout files remain forbidden even if CLI launched from outside repository',()=>{
 const f=fixture(),internal=mkdtempSync(join(repoRoot,'.phase1at-synthetic-'));
 try{
  const a=join(internal,'acceptance.json'),m=join(internal,'manifest.json');
  f.write(a,f.acceptance);f.write(m,f.manifest);
  assert.throws(()=>readPrivateStagingReviewInputs(a,m));
  const result=runCli([a,m,f.evidenceRoot],{},f.base);
  assert.equal(result.status,2);
  assert.equal(result.stdout,'');
  assert.ok(!result.stderr.includes(a));
 }finally{
  rmSync(internal,{recursive:true,force:true});
  rmSync(f.base,{recursive:true,force:true});
 }
});

test('CI, production and missing approvals block reads and hide private data',()=>{
 const f=fixture();
 try{
  const args=[f.a,f.m,f.evidenceRoot];
  for(const overrides of [
   {CI:'true'},{GITHUB_ACTIONS:'true'},{NODE_ENV:'production'},
   {STAGING_ACCEPTANCE_REVIEW:'NO'},
   {STAGING_PRIVATE_JSON_REVIEW_APPROVED:'NO'}
  ]){
   const result=runCli(args,overrides);
   assert.equal(result.status,2);
   assert.equal(result.stdout,'');
   assert.ok(!result.stderr.includes(f.a));
   assert.ok(!result.stderr.includes(f.acceptance.operatorId));
  }
  for(const invalid of [['--authorize'],[f.a,f.m],['--ci-hold',f.a]]){
   const result=runCli(invalid);
   assert.equal(result.status,2);
   assert.equal(result.stdout,'');
  }
  const hold=runCli(['--ci-hold'],{CI:'true',GITHUB_ACTIONS:'true',NODE_ENV:'production'});
  assert.equal(hold.status,0,hold.stderr);
  assert.equal(JSON.parse(hold.stdout).releaseDecision,'HOLD');
  assert.equal(JSON.parse(hold.stdout).productionReleaseAuthorized,false);
 }finally{rmSync(f.base,{recursive:true,force:true});}
});
