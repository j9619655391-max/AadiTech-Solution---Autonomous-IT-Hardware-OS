import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {assessReleaseCandidate,captureCandidateFiles,type CandidateSecurityAudit}
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
  assert.equal(a.fileCount,18);
  assert.ok(a.files.every(f=>/^[a-f0-9]{64}$/.test(f.sha256)));
  assert.ok(a.files.some(f=>f.path==='dist/index.html'));
  assert.ok(a.files.some(f=>f.path==='database/migrations/0013_mfa_recovery_rotation.sql'));
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
