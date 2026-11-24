import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {assessMasterCompletionLedger,loadMasterCompletionLedger}
 from '../scripts/lib/masterCompletionLedger.mjs';
test('all thirty workstreams are recorded as held with genuine approval evidence missing',()=>{
 const src=loadMasterCompletionLedger(),result=assessMasterCompletionLedger(src);
 assert.equal(result.ledgerStructurallyValid,true,result.blockerCodes.join(','));
 assert.equal(result.trackedModules,30);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.productionReleaseBlocked,true);
 assert.equal(result.releaseDecision,'HOLD');
 assert.equal(result.genuineExternalEvidenceVerified,false);
 assert.equal(result.approvedCustomerDispatch,false);
 assert.equal(result.officialInventoryAndFinancePosting,false);
 assert.deepEqual(src.modules.map(x=>x.id),
  Array.from({length:30},(_,i)=>'M'+String(i+1).padStart(2,'0')));
 assert.equal(src.modules.filter(x=>x.engineeringStatus==='LEGACY_PREVIEW_ONLY').length,11);
 assert.equal(src.modules.filter(x=>x.engineeringStatus==='SERVER_INTERNAL_HELD').length,13);
 const m17=src.modules.find(x=>x.id==='M17');
 assert.equal(m17.engineeringStatus,'SERVER_INTERNAL_HELD');
 assert.equal(m17.sourcePath,'server/fieldService/router.ts');
 assert.equal(m17.externalApprovalRequired,true);
 assert.equal(m17.realExternalAuthorityVerified,false);
 assert.equal(m17.productionEnabled,false);
 assert.equal(m17.signedAcceptanceEvidence,null);
 assert.equal(m17.releaseDecision,'HOLD');
 const m16=src.modules.find(x=>x.id==='M16');
 assert.equal(m16.engineeringStatus,'SERVER_INTERNAL_HELD');
 assert.equal(m16.externalApprovalRequired,true);
 assert.equal(m16.productionEnabled,false);
 assert.equal(m16.signedAcceptanceEvidence,null);
});
test('ledger must deny fabricated approval flags and partial module removal',()=>{
 const data=loadMasterCompletionLedger();
 for(const fake of [
  {...data,releaseDecision:'GO'},
  {...data,productionReleaseAuthorized:true},
  {...data,sourceRepository:'not-authorized/other-repo'},
  {...data,modules:data.modules.slice(1)},
  {...data,modules:data.modules.map((x,i)=>i===4?{...x,
   realExternalAuthorityVerified:true,signedAcceptanceEvidence:'self-supplied'}:x)},
  {...data,modules:data.modules.map((x,i)=>i===3?{...x,
   engineeringStatus:'COMPLETED'}:x)},
  {...data,modules:data.modules.map((x,i)=>i===10?{...x,
   sourcePath:'../secrets/private.pem'}:x)}
 ])assert.equal(assessMasterCompletionLedger(fake).ledgerStructurallyValid,false);
});
test('zero-input CI admits HOLD only and never leaks provided credentials/paths',()=>{
 const file=fileURLToPath(new URL('../scripts/project-completion-preflight.mjs',import.meta.url));
 const cwd=fileURLToPath(new URL('../',import.meta.url));
 const run=args=>spawnSync(process.execPath,[file,...args],{
  cwd,encoding:'utf8',timeout:8000,maxBuffer:50000
 });
 const ok=run(['--ci-hold']);
 assert.equal(ok.status,0,ok.stderr);
 const report=JSON.parse(ok.stdout);
 assert.equal(report.ledgerStructurallyValid,true);
 assert.equal(report.trackedModules,30);
 assert.equal(report.productionReleaseAuthorized,false);
 for(const bad of [[],['--approve'],['--go-live'],
  ['--provider-token','DONT_ECHO_THIS_SECRET'],['--evidence','/tmp/owner-identity']]){
  const denied=run(bad);
  assert.equal(denied.status,2);
  assert.equal(denied.stdout,'');
  assert.match(denied.stderr,/HARD HOLD/);
  assert.ok(!denied.stderr.includes('DONT_ECHO_THIS_SECRET'));
  assert.ok(!denied.stderr.includes('/tmp/owner-identity'));
 }
});
