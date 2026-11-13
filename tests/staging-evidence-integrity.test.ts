import test from 'node:test';
import assert from 'node:assert/strict';
import {tmpdir} from 'node:os';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyStagingEvidenceFiles,REQUIRED_EVIDENCE_KINDS,
 type StagingEvidenceManifest} from '../scripts/lib/stagingEvidenceIntegrity';

const expected={changeTicket:'CHG-STAGING-2026-001',stagingOrigin:'https://staging.aaditechs.in'};
function fixture(){
 const root=mkdtempSync(join(tmpdir(),'aaditech-evidence-'));
 const files=REQUIRED_EVIDENCE_KINDS.map(kind=>{
  const content='synthetic evidence '+kind;
  const name=kind+'.txt';
  writeFileSync(join(root,name),content);
  return {kind,path:name,sha256:createHash('sha256').update(content).digest('hex')};
 });
 return {root,manifest:{schemaVersion:1,...expected,files} as StagingEvidenceManifest};
}
test('12 private evidence artifacts can be checked offline without releasing data or approving production',()=>{
 const {root,manifest}=fixture();
 try{
  const report=verifyStagingEvidenceFiles(manifest,root,expected);
  assert.equal(report.integrityChecksPassed,true);
  assert.equal(report.checkedEvidenceFileCount,12);
  assert.equal(report.productionReleaseAuthorized,false);
  assert.equal(report.signerIdentityExternallyVerified,false);
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
test('symlinks, traversal and checkout evidence roots cannot bypass safety boundary',()=>{
 const {root,manifest}=fixture();
 try{
  const first=manifest.files[0];
  assert.equal(verifyStagingEvidenceFiles({...manifest,files:[{...first,path:'../passwd'},...manifest.files.slice(1)]},
   root,expected).integrityChecksPassed,false);
  const link='linked.txt';
  symlinkSync(join(root,first.path),join(root,link));
  assert.equal(verifyStagingEvidenceFiles({...manifest,files:[{...first,path:link},...manifest.files.slice(1)]},
   root,expected).integrityChecksPassed,false);
  assert.equal(verifyStagingEvidenceFiles(manifest,process.cwd(),expected).integrityChecksPassed,false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
