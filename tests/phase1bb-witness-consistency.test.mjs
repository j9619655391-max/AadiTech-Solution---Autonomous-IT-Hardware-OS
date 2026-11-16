import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,sign} from 'node:crypto';
import {fixture,now,h} from './support/phase1bbFixture.mjs';
import {ANCHOR_PURPOSE,phase1AyInclusionLeafHash} from '../scripts/lib/phase1AyWitnessArchiveRecovery.mjs';
import {BA_WITNESS_PURPOSE,phase1BaWitnessBytes} from '../scripts/lib/phase1BaAcceptanceEvidence.mjs';
import {phase1BbVerifyConsistencyProof,assessPhase1BbWitnessConsistency} from '../scripts/lib/phase1BbWitnessConsistency.mjs';

const digest=(...pieces)=>createHash('sha256').update(Buffer.concat(pieces)).digest();
const leaf=b=>digest(Buffer.from([0]),b);
const node=(l,r)=>digest(Buffer.from([1]),l,r);
function pivot(n){let k=1;while(k*2<n)k*=2;return k;}
function root(items){
 if(items.length===1)return leaf(items[0]);
 const k=pivot(items.length);
 return node(root(items.slice(0,k)),root(items.slice(k)));
}
function inclusion(i,items){
 if(items.length===1)return [];
 const k=pivot(items.length);
 return i<k?[...inclusion(i,items.slice(0,k)),root(items.slice(k))]:
  [...inclusion(i-k,items.slice(k)),root(items.slice(0,k))];
}
function subproof(m,items,b){
 if(m===items.length)return b?[]:[root(items)];
 const k=pivot(items.length);
 if(m<=k)return [...subproof(m,items.slice(0,k),b),root(items.slice(k))];
 return [...subproof(m-k,items.slice(k),false),root(items.slice(0,k))];
}
const hex=b=>b.toString('hex');
function consistency(oldSize,newSize,items){
 return oldSize===newSize?[]:subproof(oldSize,items.slice(0,newSize),true).map(hex);
}
function observations(oldSize=2,newSize=5){
 const f=fixture(),a=f.azPacket.archive;
 const archiveBody={
  schemaVersion:1,purpose:ANCHOR_PURPOSE,logRef:a.logRef,
  checkpointReceiptSha256:a.checkpointReceiptSha256,
  archiveObjectSha256:a.archiveObjectSha256,treeSize:oldSize,leafIndex:0,
  rootSha256:h(9),issuedAt:'2026-11-16T17:00:00.000Z',
  expiresAt:'2026-11-16T19:00:00.000Z',releaseDecision:'HOLD'
 };
 const archiveLeaf=phase1AyInclusionLeafHash(archiveBody);
 const items=[archiveLeaf,...Array.from({length:newSize-1},(_,i)=>Buffer.from('synthetic-proof-leaf-'+i))];
 const earlier=items.slice(0,oldSize),later=items.slice(0,newSize);
 const oldHash=hex(root(earlier)),newHash=hex(root(later));
 const proof=consistency(oldSize,newSize,items);
 const entries=f.actors.slice(0,2).map((actor,i)=>{
  const registered=f.azPacket.witnesses[i];
  const pin={role:'WITNESS',reviewerRef:actor.pin.sourceRef,
   authorityRef:actor.pin.authorityRef,keyId:actor.pin.keyId,
   publicKeyPem:actor.pin.publicKeyPem,publicKeySha256:actor.pin.publicKeySha256};
  const common={
   schemaVersion:1,purpose:BA_WITNESS_PURPOSE,
   packetSha256:f.records[0].body.packetSha256,
   witnessRef:registered.witnessRef,organizationRef:registered.organizationRef,
   administrativeAuthorityRef:registered.administrativeAuthorityRef,
   logRef:a.logRef,checkpointReceiptSha256:a.checkpointReceiptSha256,
   archiveObjectSha256:a.archiveObjectSha256,
   leafIndex:0,expiresAt:'2026-11-16T19:00:00.000Z',releaseDecision:'HOLD'
  };
  const earlierBody={...common,treeSize:oldSize,rootSha256:oldHash,
   observedAt:'2026-11-16T17:00:00.000Z'};
  const laterBody={...common,treeSize:newSize,rootSha256:newHash,
   observedAt:'2026-11-16T17:30:00.000Z'};
  const snap=(b,data)=>({
   body:b,signature:{
    reviewerRef:pin.reviewerRef,keyId:pin.keyId,
    signatureBase64:sign(null,phase1BaWitnessBytes(b),actor.privateKey).toString('base64')
   },inclusionProofSha256:inclusion(0,data).map(hex)
  });
  return {pin,previous:snap(earlierBody,earlier),
   current:snap(laterBody,later),consistencyProofSha256:proof};
 });
 return {azPacket:f.azPacket,observations:entries,actors:f.actors,now,items,oldSize,newSize};
}
test('RFC6962 minimal consistency proofs independently validate for 1..16 leaves',()=>{
 const items=Array.from({length:16},(_,i)=>Buffer.from('independent-append-only-leaf-'+i));
 for(let n=1;n<=16;n++)for(let m=1;m<=n;m++){
  const a=hex(root(items.slice(0,m))),b=hex(root(items.slice(0,n)));
  const proof=consistency(m,n,items);
  assert.equal(phase1BbVerifyConsistencyProof({
   oldSize:m,newSize:n,oldRootSha256:a,newRootSha256:b,proofSha256:proof
  }),true,'valid '+m+'/'+n);
  if(m<n&&proof.length){
   assert.equal(phase1BbVerifyConsistencyProof({
    oldSize:m,newSize:n,oldRootSha256:a,newRootSha256:b,
    proofSha256:proof.slice(0,-1)
   }),false,'truncated '+m+'/'+n);
   assert.equal(phase1BbVerifyConsistencyProof({
    oldSize:m,newSize:n,oldRootSha256:a,newRootSha256:b,
    proofSha256:[...proof,h(99999)]
   }),false,'extra node '+m+'/'+n);
  }
 }
});
test('cross-organization signed historical/current proofs remain external HOLD',()=>{
 const r=assessPhase1BbWitnessConsistency(observations());
 assert.equal(r.internalAppendOnlyConsistent,true,r.blockerCodes.join(','));
 assert.equal(r.distinctClaimedAuthorities,2);
 assert.equal(r.cryptographicallyCheckedPairs,2);
 assert.equal(r.independentWitnessKeyCustodyVerified,false);
 assert.equal(r.externallyAuthenticatedPublisher,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('different new root at same tree size quarantines cross-organization equivocation',()=>{
 const f=observations();
 f.observations[1].current.body.rootSha256=h(150);
 const r=assessPhase1BbWitnessConsistency(f);
 assert.equal(r.internalAppendOnlyConsistent,false);
 assert.ok(r.blockerCodes.includes('NEW_HEAD_WITNESS_EQUIVOCATION'));
 assert.ok(r.blockerCodes.includes('INVALID_SIGNED_WITNESS_HEAD'));
});
test('duplicate claimed administrative control or unregistered public key cannot count twice',()=>{
 const f=observations();
 f.observations[1].pin.authorityRef=f.observations[0].pin.authorityRef;
 const r=assessPhase1BbWitnessConsistency(f);
 assert.equal(r.internalAppendOnlyConsistent,false);
 assert.ok(r.blockerCodes.includes('WITNESS_COMMON_ADMIN_OR_DUPLICATE_ENROLLMENT'));
 assert.ok(r.blockerCodes.includes('WITNESS_SOURCE_ENROLLMENT_MISMATCH'));
});
test('missing head, truncated path, forged signature, wrong packet scope all reject',()=>{
 for(const change of [
  f=>{f.observations.pop();},
  f=>{f.observations[0].consistencyProofSha256.pop();},
  f=>{f.observations[0].current.signature.signatureBase64=Buffer.alloc(64,3).toString('base64');},
  f=>{f.observations[0].current.body.packetSha256=h(77);}
 ]){
  const f=observations();change(f);
  const r=assessPhase1BbWitnessConsistency(f);
  assert.equal(r.internalAppendOnlyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('reordered time, stale head and log/receipt substitution fail closed',()=>{
 for(const change of [
  f=>{f.observations[0].current.body.observedAt='2026-11-16T16:30:00.000Z';},
  f=>{f.observations[0].current.body.expiresAt='2026-11-16T17:59:00.000Z';},
  f=>{f.observations[0].current.body.logRef='unknown-checkpoint-log';},
  f=>{f.observations[0].previous.body.checkpointReceiptSha256=h(50);}
 ]){
  const f=observations();change(f);
  const r=assessPhase1BbWitnessConsistency(f);
  assert.equal(r.internalAppendOnlyConsistent,false);
  assert.equal(r.productionReleaseBlocked,true);
 }
});
test('same-size same-root requires empty proof; rollback and malformed proof reject',()=>{
 const f=observations();
 const a=hex(root(f.items.slice(0,4))),b=hex(root(f.items.slice(0,5)));
 assert.equal(phase1BbVerifyConsistencyProof({
  oldSize:4,newSize:4,oldRootSha256:a,newRootSha256:a,proofSha256:[]
 }),true);
 assert.equal(phase1BbVerifyConsistencyProof({
  oldSize:4,newSize:4,oldRootSha256:a,newRootSha256:b,proofSha256:[]
 }),false);
 assert.equal(phase1BbVerifyConsistencyProof({
  oldSize:4,newSize:4,oldRootSha256:a,newRootSha256:a,proofSha256:[h(3)]
 }),false);
 assert.throws(()=>phase1BbVerifyConsistencyProof({
  oldSize:5,newSize:4,oldRootSha256:b,newRootSha256:a,proofSha256:[]
 }));
 assert.throws(()=>phase1BbVerifyConsistencyProof({
  oldSize:1,newSize:2,oldRootSha256:h(1),newRootSha256:h(2),
  proofSha256:['A'.repeat(64)]
 }));
 assert.throws(()=>phase1BbVerifyConsistencyProof({
  oldSize:1,newSize:2,oldRootSha256:h(1),newRootSha256:h(2),
  proofSha256:Array(65).fill(h(4))
 }));
});
test('zero input, extra fields and unbounded witness list refuse activation',()=>{
 const r=assessPhase1BbWitnessConsistency();
 assert.equal(r.internalAppendOnlyConsistent,false);
 assert.ok(r.blockerCodes.includes('MISSING_CONSISTENCY_WITNESSES'));
 assert.equal(r.productionReleaseAuthorized,false);
 const f=observations();
 f.observations[0].extraneousSecret='SHOULD_NOT_BE_ACCEPTED';
 assert.throws(()=>assessPhase1BbWitnessConsistency(f));
 const g=observations();g.observations=Array.from({length:9},()=>g.observations[0]);
 assert.throws(()=>assessPhase1BbWitnessConsistency(g));
});

test('CLI exposes only zero-input witness-consistency HOLD and never echoes secrets',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const path=fileURLToPath(new URL('../scripts/phase1bb-consistency-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[path,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',GITHUB_ACTIONS:'true',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32768
 });
 const ok=run(['--ci-hold']);
 assert.equal(ok.status,0,ok.stderr);
 const r=JSON.parse(ok.stdout);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.externalLogHeadSourceAuthenticated,false);
 assert.equal(r.independentWitnessKeyCustodyVerified,false);
 for(const args of [[],['--approve'],['--external-key','REDACTED_SECRET'],
  ['--file','/tmp/private-witness-key'],['--ci-hold','--deploy']]){
  const denied=run(args);
  assert.equal(denied.status,2);
  assert.equal(denied.stdout,'');
  assert.match(denied.stderr,/HOLD/);
  assert.ok(!denied.stderr.includes('REDACTED_SECRET'));
  assert.ok(!denied.stderr.includes('/tmp/private-witness-key'));
 }
});

test('two valid independently signed append-only extensions with divergent roots still fork',()=>{
 const f=observations(2,5),forkLeaves=[...f.items];
 forkLeaves[3]=Buffer.from('alternate-branch-leaf-2026');
 const witness=f.observations[1];
 const signedHead={...witness.current.body,rootSha256:hex(root(forkLeaves))};
 witness.current.body=signedHead;
 witness.current.inclusionProofSha256=inclusion(0,forkLeaves).map(hex);
 witness.current.signature.signatureBase64=sign(null,
  phase1BaWitnessBytes(signedHead),f.actors[1].privateKey).toString('base64');
 witness.consistencyProofSha256=consistency(2,5,forkLeaves);
 const result=assessPhase1BbWitnessConsistency(f);
 assert.equal(result.internalAppendOnlyConsistent,false);
 assert.ok(result.blockerCodes.includes('NEW_HEAD_WITNESS_EQUIVOCATION'));
 assert.equal(result.blockerCodes.includes('INVALID_SIGNED_WITNESS_HEAD'),false);
 assert.equal(result.blockerCodes.includes('INVALID_ARCHIVE_INCLUSION_IN_HEAD'),false);
 assert.equal(result.blockerCodes.includes('APPEND_ONLY_CONSISTENCY_PROOF_INVALID'),false);
 assert.equal(result.productionReleaseAuthorized,false);
});
