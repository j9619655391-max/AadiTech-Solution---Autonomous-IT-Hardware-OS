import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
 ANCHOR_PURPOSE,RECOVERY_PURPOSE,phase1AyAnchorSigningBytes,
 phase1AyInclusionLeafHash,phase1AyVerifyInclusion,
 assessPhase1AyArchiveWitnesses,phase1AyRecoverySigningBytes,
 assessPhase1AyRecovery
} from '../scripts/lib/phase1AyWitnessArchiveRecovery.mjs';

const now=new Date('2026-11-16T16:10:00.000Z');
const digest=i=>i.toString(16).padStart(64,'0');
const sha=buffer=>createHash('sha256').update(buffer).digest();
const hashLeaf=body=>sha(Buffer.concat([Buffer.from([0]),phase1AyInclusionLeafHash(body)]));
const hashNode=(left,right)=>sha(Buffer.concat([Buffer.from([1]),left,right]));
function actor(n,role,organization){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 return {privateKey,pin:{role,reviewerRef:'reviewer-ref-'+n,
  keyId:'reviewer-key-'+n,authorityRef:organization,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:sha(publicKey.export({format:'der',type:'spki'})).toString('hex')}};
}
const detached=(msg,who)=>({reviewerRef:who.pin.reviewerRef,keyId:who.pin.keyId,
 signatureBase64:sign(null,msg,who.privateKey).toString('base64')});
function baseAnchor(override={}){
 return {schemaVersion:1,purpose:ANCHOR_PURPOSE,logRef:'checkpoint-log-001',
  checkpointReceiptSha256:digest(10),archiveObjectSha256:digest(20),
  treeSize:1,leafIndex:0,rootSha256:digest(1),
  issuedAt:'2026-11-16T16:00:00.000Z',
  expiresAt:'2026-11-16T17:00:00.000Z',releaseDecision:'HOLD',...override};
}
function makeTree(index=0,sibling=digest(80)){
 const body=baseAnchor({treeSize:2,leafIndex:index});
 const other=Buffer.from(sibling,'hex');
 const leaf=hashLeaf(body);
 const root=index===0?hashNode(leaf,other):hashNode(other,leaf);
 return {...body,rootSha256:root.toString('hex')};
}
function makeAnchor(who,body,proof=[]){
 return {body,signature:detached(phase1AyAnchorSigningBytes(body),who),
  inclusionProofSha256:proof};
}
function fixture(){
 const a=actor(1,'WITNESS','witness-org-001'),b=actor(2,'WITNESS','witness-org-002');
 const body=baseAnchor();body.rootSha256=hashLeaf(body).toString('hex');
 return {a,b,body,args:{logRef:body.logRef,checkpointReceiptSha256:body.checkpointReceiptSha256,
  archiveObjectSha256:body.archiveObjectSha256,anchors:[makeAnchor(a,body),makeAnchor(b,body)],
  pins:[a.pin,b.pin],now}};
}
test('valid cryptographic fixture and two claimed authorities stay externally unauthenticated HOLD',()=>{
 const f=fixture(),r=assessPhase1AyArchiveWitnesses(f.args);
 assert.equal(r.cryptographicallyConsistent,true);
 assert.equal(r.validProofs,2);
 assert.equal(r.distinctClaimedWitnessAuthorities,2);
 assert.equal(r.immutableExternalArchiveVerified,false);
 assert.equal(r.independentlyAuthenticatedWitnesses,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.deepEqual(r.blockerCodes,[
  'EXTERNAL_WITNESS_PROVENANCE_NOT_AUTHENTICATED',
  'IMMUTABLE_ARCHIVE_RETENTION_NOT_INDEPENDENTLY_VERIFIED'
 ]);
});
test('Merkle inclusion checks both positions, rejects truncated, altered and extra proof',()=>{
 const f=fixture();
 for(const i of [0,1]){
  const body=makeTree(i);
  assert.equal(phase1AyVerifyInclusion(body,[digest(80)]),true);
  assert.equal(phase1AyVerifyInclusion(body,[]),false);
  assert.equal(phase1AyVerifyInclusion(body,[digest(81)]),false);
  assert.equal(phase1AyVerifyInclusion(body,[digest(80),digest(80)]),false);
 }
 assert.throws(()=>phase1AyVerifyInclusion(f.body,['A'.repeat(64)]));
});
test('forged signature and substituted archive hash cannot become witnessed evidence',()=>{
 const f=fixture(),forged=structuredClone(f.args.anchors);
 forged[0].signature.signatureBase64=Buffer.alloc(64,3).toString('base64');
 let r=assessPhase1AyArchiveWitnesses({...f.args,anchors:forged});
 assert.equal(r.cryptographicallyConsistent,false);
 assert.ok(r.blockerCodes.includes('INVALID_ANCHOR_SIGNATURE'));
 r=assessPhase1AyArchiveWitnesses({...f.args,archiveObjectSha256:digest(999)});
 assert.ok(r.blockerCodes.includes('ANCHOR_SCOPE_OR_DIGEST_MISMATCH'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('duplicate administrative witness and missing quorum remain blocked',()=>{
 const f=fixture();
 const clone={...f.b.pin,authorityRef:f.a.pin.authorityRef};
 const r=assessPhase1AyArchiveWitnesses({...f.args,pins:[f.a.pin,clone]});
 assert.ok(r.blockerCodes.includes('REUSED_WITNESS_AUTHORITY'));
 assert.ok(r.blockerCodes.includes('WITNESS_QUORUM_UNAVAILABLE'));
 assert.equal(r.incidentQuarantineRequired,true);
 const missing=assessPhase1AyArchiveWitnesses();
 assert.ok(missing.blockerCodes.includes('MISSING_ANCHOR_EVIDENCE'));
 assert.equal(missing.productionReleaseBlocked,true);
 assert.equal(assessPhase1AyRecovery().productionReleaseBlocked,true);
});
test('expiry, future signatures, unknown pins and equivocation never authorize',()=>{
 const f=fixture();
 const expired=baseAnchor({expiresAt:'2026-11-16T16:05:00.000Z'});
 expired.rootSha256=hashLeaf(expired).toString('hex');
 const r=assessPhase1AyArchiveWitnesses({...f.args,anchors:[makeAnchor(f.a,expired)]});
 assert.ok(r.blockerCodes.includes('ANCHOR_EXPIRED_OR_FUTURE'));
 const unknown=assessPhase1AyArchiveWitnesses({...f.args,pins:[f.a.pin]});
 assert.ok(unknown.blockerCodes.includes('UNKNOWN_WITNESS_KEY'));
 const other=makeTree(0,digest(90)),first=makeTree(0,digest(80));
 const observations=[makeAnchor(f.a,first,[digest(80)]),makeAnchor(f.a,other,[digest(90)])];
 const conflict=assessPhase1AyArchiveWitnesses({...f.args,anchors:observations});
 assert.ok(conflict.blockerCodes.includes('WITNESS_TREE_EQUIVOCATION'));
 assert.equal(conflict.incidentQuarantineRequired,true);
});
test('reject extra release switches, malformed signatures and invalid tree index',()=>{
 const f=fixture();
 assert.throws(()=>phase1AyAnchorSigningBytes({...f.body,productionReleaseAuthorized:true}));
 assert.throws(()=>phase1AyAnchorSigningBytes({...f.body,releaseDecision:'GO'}));
 assert.throws(()=>phase1AyAnchorSigningBytes({...f.body,leafIndex:1}));
 const changed=structuredClone(f.args.anchors);
 changed[0].signature.signatureBase64='NOT_CANONICAL';
 assert.throws(()=>assessPhase1AyArchiveWitnesses({...f.args,anchors:changed}));
});
function recoveryBody(override={}){
 return {schemaVersion:1,purpose:RECOVERY_PURPOSE,incidentRef:'incident-restore-001',
  checkpointReceiptSha256:digest(31),restoredCheckpointReceiptSha256:digest(31),
  backupManifestSha256:digest(32),restoredManifestSha256:digest(32),
  revocationSnapshotSha256:digest(33),
  startedAt:'2026-11-16T15:00:00.000Z',
  completedAt:'2026-11-16T15:05:00.000Z',
  measuredRpoMs:0,rtoTargetMs:600000,rpoTargetMs:1000,
  outboundHeld:true,releaseDecision:'HOLD',...override};
}
function recoveryFixture(){
 const actors=[actor(3,'SECURITY','sec-org-003'),
  actor(4,'OPERATIONS','ops-org-004'),actor(5,'OWNER','owner-org-005')];
 const rehearsal=recoveryBody(),msg=phase1AyRecoverySigningBytes(rehearsal);
 return {rehearsal,signatures:actors.map(a=>detached(msg,a)),pins:actors.map(a=>a.pin),now};
}
test('three fixture-signed recovery roles never claim real encrypted restore or release',()=>{
 const r=assessPhase1AyRecovery(recoveryFixture());
 assert.equal(r.internalRehearsalCryptographicallyConsistent,true);
 assert.equal(r.realEncryptedRestoreVerified,false);
 assert.equal(r.independentRecoverySignoffVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('recovery mismatch, exceeded RTO/RPO, missing approver and role collision fail closed',()=>{
 const good=recoveryFixture();
 for(const item of [
  {...good,rehearsal:recoveryBody({restoredManifestSha256:digest(999)})},
  {...good,rehearsal:recoveryBody({measuredRpoMs:5000})},
  {...good,rehearsal:recoveryBody({rtoTargetMs:100})},
  {...good,pins:good.pins.slice(0,2)},
  {...good,pins:[good.pins[0],{...good.pins[1],authorityRef:good.pins[0].authorityRef},good.pins[2]]}
 ]){
  const r=assessPhase1AyRecovery(item);
  assert.equal(r.internalRehearsalCryptographicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
 assert.throws(()=>phase1AyRecoverySigningBytes(recoveryBody({outboundHeld:false})));
 assert.throws(()=>phase1AyRecoverySigningBytes(recoveryBody({releaseDecision:'GO'})));
});
test('Phase 1AY CI CLI accepts only zero-input HOLD',()=>{
 const path=fileURLToPath(new URL('../scripts/phase1ay-witness-recovery-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[path,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{...process.env,GITHUB_ACTIONS:'true',NODE_ENV:'production'},
  encoding:'utf8',timeout:8000,maxBuffer:32_768
 });
 const okay=run(['--ci-hold']);
 assert.equal(okay.status,0,okay.stderr);
 const obj=JSON.parse(okay.stdout);
 assert.equal(obj.productionReleaseAuthorized,false);
 assert.equal(obj.releaseDecision,'HOLD');
 assert.equal(obj.immutableExternalArchiveVerified,false);
 for(const args of [[],['--approve'],['--ci-hold','--file','/tmp/sensitive'],['--external']]){
  const bad=run(args);
  assert.equal(bad.status,2);
  assert.equal(bad.stdout,'');
  assert.match(bad.stderr,/HOLD/);
  assert.equal(bad.stderr.includes('/tmp/sensitive'),false);
 }
});
