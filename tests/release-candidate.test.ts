import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {assessReleaseCandidate,captureCandidateFiles,validateCandidatePushContext,type CandidateSecurityAudit}
 from '../scripts/lib/releaseCandidate';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';

const SHA='a'.repeat(40);
const audit:CandidateSecurityAudit={
 baseline:{schemaVersion:1,developmentBaselinePassed:true,
  productionReleaseBlocked:true,productionReleaseAuthorized:false,currentCriticalHigh:0},
 triage:{schemaVersion:1,bySeverity:{critical:0,high:0,unknown:0,moderate:1,low:0}}
};
function fixture(){
 const root=mkdtempSync(join(tmpdir(),'aaditech-release-'));
 const paths=['dist/server.cjs','dist/index.html','dist/assets/client.js',
  'package.json','bun.lock',...MIGRATIONS.map(m=>'database/migrations/'+m+'.sql')];
 for(const p of paths){mkdirSync(dirname(join(root,p)),{recursive:true});
  writeFileSync(join(root,p),'synthetic candidate: '+p);
 }
 const args={sourceSha:SHA,sourceRef:'chore/phase0-foundation-20261106',
  root,audit,generatedAt:'2026-11-11T00:00:00Z'};
 return {root,args};
}
test('candidate hashes compiled assets, lock and every migration, but never authorizes release',()=>{
 const {root,args}=fixture();
 try{
  const a=assessReleaseCandidate(args);
  assert.equal(a.buildHashManifestComplete,true);
  assert.equal(a.productionReleaseAuthorized,false);
  assert.equal(a.productionReleaseBlocked,true);
  assert.equal(a.fileCount,19);
  assert.ok(a.files.every(f=>/^[a-f0-9]{64}$/.test(f.sha256)));
  assert.ok(a.files.some(f=>f.path==='dist/index.html'));
  assert.ok(a.files.some(f=>f.path==='database/migrations/0013_mfa_recovery_rotation.sql'));
  assert.ok(a.files.some(f=>f.path==='database/migrations/0014_inventory_opening_counts.sql'));
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('tampered compiled code changes artifact digest while source SHA alone remains unchanged',()=>{
 const {root,args}=fixture();
 try{
  const a=assessReleaseCandidate(args);
  writeFileSync(join(root,'dist/assets/client.js'),'tampered compiled JS');
  const b=assessReleaseCandidate(args);
  assert.notEqual(a.artifactSetSha256,b.artifactSetSha256);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('missing builds, symlinks, unsafe refs and security findings fail closed',()=>{
 const {root,args}=fixture();
 try{
  assert.throws(()=>assessReleaseCandidate({...args,sourceSha:'short'}));
  assert.throws(()=>assessReleaseCandidate({...args,sourceRef:'main'}));
  assert.throws(()=>assessReleaseCandidate({...args,audit:{
   ...audit,triage:{...audit.triage,bySeverity:{...audit.triage.bySeverity,high:1}}
  }}),/inconsistent/);
  assert.throws(()=>assessReleaseCandidate({...args,audit:{
   baseline:{...audit.baseline,developmentBaselinePassed:false},triage:audit.triage
  }}));
  rmSync(join(root,'dist/assets/client.js'));
  assert.throws(()=>captureCandidateFiles(root),/Incomplete/);
  symlinkSync(join(root,'package.json'),join(root,'dist/assets/client.js'));
  assert.throws(()=>captureCandidateFiles(root),/Symlinks forbidden/);
 }finally{rmSync(root,{recursive:true,force:true});}
});

// Phase 1Z provenance: CI must never label an ephemeral PR merge SHA as branch HEAD.
const pushContext={
 RELEASE_CANDIDATE_CI:'1',GITHUB_ACTIONS:'true',
 GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
 GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/chore/phase0-foundation-20261106',
 GITHUB_SHA:SHA
};
test('candidate source identity accepts only matching development branch push',()=>{
 assert.deepEqual(validateCandidatePushContext(pushContext,SHA),{
  sourceSha:SHA,sourceRef:'chore/phase0-foundation-20261106'
 });
});
test('PR merge, fork, wrong branch and mismatched checkout SHA never generate manifest',()=>{
 const bad=[
  {...pushContext,GITHUB_EVENT_NAME:'pull_request',GITHUB_HEAD_REF:'chore/phase0-foundation-20261106'},
  {...pushContext,GITHUB_EVENT_NAME:'workflow_dispatch'},
  {...pushContext,GITHUB_REF:'refs/heads/main'},
  {...pushContext,GITHUB_REPOSITORY:'attacker/fork'},
  {...pushContext,GITHUB_ACTIONS:'false'},
  {...pushContext,GITHUB_HEAD_REF:'unexpected'},
  {...pushContext,GITHUB_SHA:'b'.repeat(40)}
 ];
 for(const env of bad)assert.throws(()=>validateCandidatePushContext(env,SHA));
 assert.throws(()=>validateCandidatePushContext(pushContext,'short'));
});
test('unregistered SQL migration fails closed instead of silently omitting schema changes',()=>{
 const {root}=fixture();
 try{
  writeFileSync(join(root,'database/migrations/0014_not_registered.sql'),
   'CREATE TABLE should_not_ship(id INT);');
  assert.throws(()=>captureCandidateFiles(root),/Unregistered SQL migration/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
