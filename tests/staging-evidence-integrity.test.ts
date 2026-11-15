import test from 'node:test';
import assert from 'node:assert/strict';
import {tmpdir} from 'node:os';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync,chmodSync,linkSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {verifyStagingEvidenceFiles,REQUIRED_EVIDENCE_KINDS,
 type StagingEvidenceManifest} from '../scripts/lib/stagingEvidenceIntegrity';

const expected={changeTicket:'CHG-STAGING-2026-001',stagingOrigin:'https://staging.aaditechs.in'};
const repositoryRoot=fileURLToPath(new URL('../',import.meta.url));
function fixture(){
 const root=mkdtempSync(join(tmpdir(),'aaditech-evidence-'));
 const files=REQUIRED_EVIDENCE_KINDS.map(kind=>{
  const content='synthetic evidence '+kind;
  const name=kind+'.txt';
  writeFileSync(join(root,name),content,{mode:0o600});
  return {kind,path:name,sha256:createHash('sha256').update(content).digest('hex')};
 });
 return {root,manifest:{schemaVersion:1,...expected,files} as StagingEvidenceManifest};
}
test('12 owner-private evidence artifacts can be checked offline without approving production',()=>{
 const {root,manifest}=fixture();
 try{
  const report=verifyStagingEvidenceFiles(manifest,root,expected);
  assert.equal(report.integrityChecksPassed,true,JSON.stringify(report.problems));
  assert.equal(report.checkedEvidenceFileCount,12);
  assert.equal(report.productionReleaseAuthorized,false);
  assert.equal(report.signerIdentityExternallyVerified,false);
  assert.equal(report.evidenceTruthExternallyVerified,false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('file changes, missing categories, ticket mismatch and duplicates fail closed',()=>{
 const {root,manifest}=fixture();
 try{
  writeFileSync(join(root,manifest.files[0].path),'edited after signature');
  assert.equal(verifyStagingEvidenceFiles(manifest,root,expected).integrityChecksPassed,false);
  const dup={...manifest,files:[manifest.files[0],...manifest.files.slice(0,-1)]};
  assert.equal(verifyStagingEvidenceFiles(dup,root,expected).integrityChecksPassed,false);
  assert.equal(verifyStagingEvidenceFiles(manifest,root,{...expected,changeTicket:'CHG-DIFFERENT'}).integrityChecksPassed,false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('symlinks, traversal, malformed metadata and checkout evidence roots cannot bypass safety boundary',()=>{
 const {root,manifest}=fixture();
 try{
  const first=manifest.files[0];
  assert.equal(verifyStagingEvidenceFiles({...manifest,files:[{...first,path:'../passwd'},...manifest.files.slice(1)]},
   root,expected).integrityChecksPassed,false);
  const link='linked.txt';
  symlinkSync(join(root,first.path),join(root,link));
  assert.equal(verifyStagingEvidenceFiles({...manifest,files:[{...first,path:link},...manifest.files.slice(1)]},
   root,expected).integrityChecksPassed,false);
  const extra={...manifest,files:[{...first,providerToken:'SECRET'},...manifest.files.slice(1)]};
  assert.equal(verifyStagingEvidenceFiles(extra,root,expected).integrityChecksPassed,false);
  const upper={...manifest,files:[{...first,sha256:first.sha256.toUpperCase()},...manifest.files.slice(1)]};
  assert.equal(verifyStagingEvidenceFiles(upper,root,expected).integrityChecksPassed,false);
  assert.equal(verifyStagingEvidenceFiles(manifest,repositoryRoot,expected).integrityChecksPassed,false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('weak permissions, hardlinked evidence and root symlink always fail closed',()=>{
 const {root,manifest}=fixture();
 const first=join(root,manifest.files[0].path);
 const alias=root+'-symlink';
 try{
  chmodSync(first,0o644);
  assert.equal(verifyStagingEvidenceFiles(manifest,root,expected).integrityChecksPassed,false);
  chmodSync(first,0o600);
  chmodSync(root,0o750);
  assert.equal(verifyStagingEvidenceFiles(manifest,root,expected).integrityChecksPassed,false);
  chmodSync(root,0o700);
  symlinkSync(root,alias);
  assert.equal(verifyStagingEvidenceFiles(manifest,alias,expected).integrityChecksPassed,false);
  linkSync(first,join(root,'second-hardlink.txt'));
  assert.equal(verifyStagingEvidenceFiles(manifest,root,expected).integrityChecksPassed,false);
 }finally{
  rmSync(alias,{force:true});
  rmSync(root,{recursive:true,force:true});
 }
});
test('symlinked intermediate path components fail even when their target remains under root',()=>{
 const {root,manifest}=fixture();
 try{
  mkdirSync(join(root,'real'),{mode:0o700});
  const first=manifest.files[0];
  writeFileSync(join(root,'real','first.txt'),'synthetic evidence '+first.kind,{mode:0o600});
  symlinkSync(join(root,'real'),join(root,'alias'));
  const changed={...manifest,files:[{...first,path:'alias/first.txt'},...manifest.files.slice(1)]};
  assert.equal(verifyStagingEvidenceFiles(changed,root,expected).integrityChecksPassed,false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('cannot change checkout boundary by launching verification from external cwd',()=>{
 const {root,manifest}=fixture();
 const checkoutPacket=mkdtempSync(join(repositoryRoot,'.phase1as-synthetic-'));
 const oldCwd=process.cwd();
 try{
  for(const item of manifest.files)
   writeFileSync(join(checkoutPacket,item.path),'synthetic evidence '+item.kind,{mode:0o600});
  process.chdir(root);
  assert.equal(verifyStagingEvidenceFiles(manifest,checkoutPacket,expected).integrityChecksPassed,false);
  const external=verifyStagingEvidenceFiles(manifest,root,expected);
  assert.equal(external.integrityChecksPassed,true,JSON.stringify(external.problems));
  assert.equal(external.productionReleaseAuthorized,false);
 }finally{
  process.chdir(oldCwd);
  rmSync(checkoutPacket,{recursive:true,force:true});
  rmSync(root,{recursive:true,force:true});
 }
});
