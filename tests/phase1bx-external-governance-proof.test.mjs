import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {assessExternalGovernanceEvidence,createZeroInputHoldReport,
 signingPayload,EVIDENCE_TYPES,REQUIRED_RULESET_CONTROLS}
 from '../scripts/phase1bx-external-governance-proof.mjs';

// Disposable Ed25519 test material is generated in memory only; never a
// real GitHub reviewer, enrolled key or externally signed CI provenance.
const TARGET=Object.freeze({
 repository:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
 baseBranch:'main',prNumber:1,prAuthor:'j9619655391-max',
 developmentHead:'a'.repeat(40),baseSha:'b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b',
 prMergeCheckoutSha:'b'.repeat(40),challengeNonce:'c'.repeat(64),
 ciInputBundleSha256:'d'.repeat(64),productionReleaseAuthorized:false
});
const NOW='2026-11-18T09:00:00.000Z';
const login={
 'branch-ruleset':'real-admin-example',
 'security-review':'independent-security-example',
 'business-review':'independent-business-example',
 'ci-provenance':'ci-attestor-example',
 'external-worm-receipt':'offsite-auditor-example'
};
function fixture(){
 const authorities={},privateKeys={},evidence=[];
 for(const [type,role] of Object.entries(EVIDENCE_TYPES)){
  const id=type+'-key';
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const der=publicKey.export({format:'der',type:'spki'});
  authorities[id]={role,login:login[type],
   publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
   spkiSha256:createHash('sha256').update(der).digest('hex')};
  privateKeys[id]=privateKey;
  const statement={
   schemaVersion:1,type,role,signerId:id,signerLogin:login[type],
   repository:TARGET.repository,baseBranch:TARGET.baseBranch,
   prNumber:1,developmentHead:TARGET.developmentHead,
   baseSha:TARGET.baseSha,prMergeCheckoutSha:TARGET.prMergeCheckoutSha,
   challengeNonce:TARGET.challengeNonce,productionReleaseAuthorized:false,
   evidenceSha256:type==='ci-provenance'?TARGET.ciInputBundleSha256:'e'.repeat(64),
   issuedAt:'2026-11-18T08:00:00.000Z',
   expiresAt:'2026-11-18T10:00:00.000Z'
  };
  if(type==='branch-ruleset')statement.observedRuleset={
   protectionBranch:'main',minimumIndependentApprovals:2,
   ...Object.fromEntries(REQUIRED_RULESET_CONTROLS.map(k=>[k,true]))};
  if(type==='external-worm-receipt'){
   statement.wormSequence=101;
   statement.wormRetentionVerified=true;
   statement.witnessedCiBundleSha256=TARGET.ciInputBundleSha256;
  }
  const signature=sign(null,signingPayload(statement),privateKey).toString('base64');
  evidence.push({algorithm:'Ed25519',statement,signature});
 }
 return {authorities,privateKeys,evidence};
}
const evaluate=(overrides={})=>{
 const f=fixture();
 return assessExternalGovernanceEvidence({
  target:TARGET,authorities:f.authorities,evidence:f.evidence,now:NOW,
  ...overrides
 });
};
function mutate(type,fn){
 const f=fixture();
 const item=f.evidence.find(x=>x.statement.type===type);
 fn(item,f);
 return assessExternalGovernanceEvidence({
  target:TARGET,authorities:f.authorities,evidence:f.evidence,now:NOW
 });
}
test('BX disposable Ed25519 challenge quorum verifies caller-supplied keys, NEVER real external authority or production',()=>{
 const r=evaluate();
 assert.equal(r.suppliedKeySignaturesCryptographicallyConsistent,true,
  r.anomalyCodes.join(','));
 assert.equal(r.acceptedSuppliedRecordCount,5);
 assert.equal(r.independentGithubRulesetVerified,false);
 assert.equal(r.externalKeyProvenanceAuthenticated,false);
 assert.equal(r.authenticatedIndependentReviewerEnrollmentVerified,false);
 assert.equal(r.realGithubReviewSubmissionVerified,false);
 assert.equal(r.independentCIWorkloadIdentityVerified,false);
 assert.equal(r.externallyWitnessedWormReceiptVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BX no input CI remains zero-validity HARD HOLD, no external registry or network',()=>{
 const r=createZeroInputHoldReport();
 assert.equal(r.externalPacketCount,0);
 assert.equal(r.independentKeysSupplied,false);
 assert.equal(r.evidence.acceptedSuppliedRecordCount,0);
 assert.equal(r.evidence.productionReleaseAuthorized,false);
 assert.equal(r.evidence.releaseDecision,'HOLD');
 assert.ok(r.evidence.anomalyCodes.includes('BX_MISSING_INDEPENDENT_PROOF_security-review'));
});
test('BX signature verification rejects forged statements, tampered signatures, wrong algorithms and wrong key fingerprints',()=>{
 for(const f of [
  item=>item.statement.evidenceSha256='0'.repeat(64),
  item=>item.statement.repository='attacker/fork',
  item=>item.signature=Buffer.alloc(64,123).toString('base64'),
  item=>item.algorithm='RSA-SHA256',
  item=>item.signature='not-base64',
 ]){
  const r=mutate('security-review',f);
  assert.equal(r.suppliedKeySignaturesCryptographicallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
 const f=fixture();
 f.authorities['security-review-key'].spkiSha256='0'.repeat(64);
 const r=assessExternalGovernanceEvidence({target:TARGET,
  authorities:f.authorities,evidence:f.evidence,now:NOW});
 assert.ok(r.anomalyCodes.some(x=>x.includes('SIGNATURE_OR_ENROLLED_KEY_MISMATCH')));
});
test('BX wrong PR dev head, PR merge checkout SHA, main base or independent nonce rejected',()=>{
 for(const change of [
  {developmentHead:'f'.repeat(40)},
  {prMergeCheckoutSha:'f'.repeat(40)},
  {baseSha:'f'.repeat(40)},
  {challengeNonce:'f'.repeat(64)}
 ]){
  const target={...TARGET,...change};
  const f=fixture();
  const r=assessExternalGovernanceEvidence({target,
   authorities:f.authorities,evidence:f.evidence,now:NOW});
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('BX_SIGNED_STATEMENT_SOURCE_OR_ROLE_MISMATCH')));
  assert.equal(r.productionReleaseAuthorized,false);
 }
 const r=evaluate({target:{...TARGET,productionReleaseAuthorized:true}});
 assert.ok(r.anomalyCodes.includes('BX_INVALID_EXACT_HEAD_AND_CHALLENGE_TARGET'));
});
test('BX duplicate, missing, supernumerary or replayed proofs never satisfy full five-role quorum',()=>{
 const f=fixture();
 const signatures=[...f.evidence,f.evidence[0]];
 const dup=assessExternalGovernanceEvidence({target:TARGET,authorities:f.authorities,
  evidence:signatures,now:NOW});
 assert.equal(dup.suppliedKeySignaturesCryptographicallyConsistent,false);
 assert.ok(dup.anomalyCodes.some(x=>x.includes('REPLAY_OR_DUPLICATE_EVIDENCE_TYPE')));
 const missing=assessExternalGovernanceEvidence({target:TARGET,authorities:f.authorities,
  evidence:f.evidence.filter(x=>x.statement.type!=='external-worm-receipt'),now:NOW});
 assert.ok(missing.anomalyCodes.includes('BX_MISSING_INDEPENDENT_PROOF_external-worm-receipt'));
 assert.equal(missing.productionReleaseAuthorized,false);
});
test('BX no same signer, reused key, applicant self-review or swapped signer role may meet independent review quorum',()=>{
 const f=fixture();
 const business=f.evidence.find(x=>x.statement.type==='business-review');
 business.statement.signerId='security-review-key';
 business.statement.signerLogin=login['security-review'];
 const r=assessExternalGovernanceEvidence({target:TARGET,authorities:f.authorities,
  evidence:f.evidence,now:NOW});
 assert.equal(r.suppliedKeySignaturesCryptographicallyConsistent,false);
 assert.equal(r.acceptedSuppliedRecordCount,4);
 const self=mutate('security-review',item=>{item.statement.signerLogin=TARGET.prAuthor});
 assert.equal(self.suppliedKeySignaturesCryptographicallyConsistent,false);
 const swapped=mutate('security-review',item=>{item.statement.role='BUSINESS_OWNER'});
 assert.ok(swapped.anomalyCodes.some(x=>x.includes('SOURCE_OR_ROLE_MISMATCH')));
});
test('BX stale/future/expired signed evidence and overly broad freshness expiry fail',()=>{
 for(const [issuedAt,expiresAt] of [
  ['2026-11-17T08:00:00.000Z','2026-11-18T10:00:00.000Z'],
  ['2026-11-18T10:00:00.000Z','2026-11-18T11:00:00.000Z'],
  ['2026-11-17T07:00:00.000Z','2026-11-18T08:00:00.000Z'],
  ['2026-11-18T08:00:00Z','2026-11-18T10:00:00.000Z'],
  ['2026-11-18T08:00:00.000Z','2026-11-18T08:00:00.000Z']
 ]){
  const r=mutate('ci-provenance',item=>{
   item.statement.issuedAt=issuedAt;item.statement.expiresAt=expiresAt;
  });
  assert.ok(r.anomalyCodes.includes('BX_STALE_OR_FUTURE_SIGNED_EVIDENCE_ci-provenance'));
 }
});
test('BX honest cryptographic evidence must bind CI artifact digest, immutable WORM sequence and independent ruleset snapshot',()=>{
 for(const x of [
  mutate('ci-provenance',item=>{item.statement.evidenceSha256='f'.repeat(64)}),
  mutate('external-worm-receipt',item=>{item.statement.witnessedCiBundleSha256='f'.repeat(64)}),
  mutate('external-worm-receipt',item=>{item.statement.wormSequence=0}),
  mutate('external-worm-receipt',item=>{item.statement.wormRetentionVerified=false}),
  mutate('branch-ruleset',item=>{item.statement.observedRuleset.preventForcePush=false}),
  mutate('branch-ruleset',item=>{item.statement.observedRuleset.minimumIndependentApprovals=1})
 ])assert.equal(x.suppliedKeySignaturesCryptographicallyConsistent,false,x.anomalyCodes.join(','));
});
test('BX signature statement key-order canonicalization is deterministic and rejects unsupported values',()=>{
 const f=fixture();
 const statement=f.evidence[0].statement;
 assert.deepEqual(signingPayload(statement),signingPayload(
  Object.fromEntries(Object.entries(statement).reverse())));
 assert.throws(()=>signingPayload({...statement,broken:undefined}),/unsupported/);
 assert.throws(()=>signingPayload({...statement,broken:1.5}),/unsupported/);
 assert.throws(()=>signingPayload(null),/invalid/);
});
test('BX missing out-of-band keyring or artificially claimed signed authority cannot grant external acceptance',()=>{
 const f=fixture();
 const r=assessExternalGovernanceEvidence({target:TARGET,authorities:{},
  evidence:f.evidence,now:NOW});
 assert.equal(r.acceptedSuppliedRecordCount,0);
 assert.equal(r.externalKeyProvenanceAuthenticated,false);
 assert.equal(r.productionReleaseAuthorized,false);
 const fake=evaluate({target:{...TARGET,repository:'attacker/fork'}});
 assert.equal(fake.suppliedKeySignaturesCryptographicallyConsistent,false);
});
test('BX records cannot carry a signed production GO without violating exact source promise',()=>{
 const r=mutate('business-review',item=>{item.statement.productionReleaseAuthorized=true});
 assert.equal(r.suppliedKeySignaturesCryptographicallyConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
