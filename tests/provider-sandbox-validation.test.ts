import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {caseBody,reviewCaseBody,reviewCertBody,certificateBody,
 inspectOneHopCertificateChain,ChainInputError,ChainConflictError}
 from '../server/providerSandbox/validation';
import {providerSandboxMigrationTarget} from '../scripts/migrate-provider-sandbox';
const id=randomUUID(),pinId=randomUUID(),issuerId=randomUUID();
const document='a'.repeat(64),sigDoc='b'.repeat(64);
const base={pinId,issuerId,purpose:'SUPPLIER_ACK',registryReference:'REG-TEST-2026',
 identityDocumentSha256:document,signatoryReference:'Employee authority ticket 2026',
 signatoryDocumentSha256:sigDoc,evidenceRef:'CI-CORP-IDENTITY-2026'};
test('strict corporate and signatory claims are never externally authenticated',()=>{
 assert.deepEqual(caseBody(base),base);
 for(const delta of [
  {verified:true},{purpose:'LIVE_STOCK'},{identityDocumentSha256:'x'},
  {signatoryReference:'x'},{registryReference:'not canonical'}])
  assert.throws(()=>caseBody({...base,...delta}),ChainInputError);
 const review={decision:'REVIEWED_EVIDENCE_HELD',
  reason:'Inspected owner-entered corporate and signatory offline references only',
  evidenceRef:'CI-REVIEW-2026',registryInspected:true,signatoryInspected:true};
 assert.equal(reviewCaseBody(review).decision,'REVIEWED_EVIDENCE_HELD');
 assert.throws(()=>reviewCaseBody({...review,decision:'VERIFIED'}),ChainInputError);
 assert.throws(()=>reviewCaseBody({...review,signatoryInspected:false}),ChainInputError);
 const certReview={decision:'REVIEWED_CRYPTO_HELD',
  reason:'Reviewed signature, not full PKIX path or actual provider',
  evidenceRef:'CI-CERT-REVIEW-2026',certificateInspected:true,
  policyGapsAcknowledged:true};
 assert.equal(reviewCertBody(certReview).decision,'REVIEWED_CRYPTO_HELD');
 assert.throws(()=>reviewCertBody({...certReview,policyGapsAcknowledged:false}),ChainInputError);
 assert.throws(()=>reviewCertBody({...certReview,decision:'EXTERNALLY_VALID'}),ChainInputError);
});
test('one-hop Ed25519 X509 evidence matches separately pinned CA and original leaf SPKI, never full PKIX',()=>{
 const dir=mkdtempSync(join(tmpdir(),'aaditech-ci-x509-'));
 try{
  const run=(args:string[])=>execFileSync('openssl',args,{cwd:dir,stdio:'pipe'});
  run(['genpkey','-algorithm','ED25519','-out','ca.key']);
  run(['req','-x509','-new','-key','ca.key','-out','ca.crt','-days','3',
   '-subj','/CN=CI Provider CA/O=Example Test','-addext','basicConstraints=critical,CA:TRUE',
   '-addext','keyUsage=critical,keyCertSign,cRLSign']);
  run(['genpkey','-algorithm','ED25519','-out','leaf.key']);
  run(['req','-new','-key','leaf.key','-out','leaf.csr',
   '-subj','/CN=CI Authorized Person/O=Example Test']);
  writeFileSync(join(dir,'leaf.ext'),
   'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
  run(['x509','-req','-in','leaf.csr','-CA','ca.crt','-CAkey','ca.key',
   '-CAcreateserial','-out','leaf.crt','-days','2','-extfile','leaf.ext']);
  const root=readFileSync(join(dir,'ca.crt'),'utf8'),leaf=readFileSync(join(dir,'leaf.crt'),'utf8');
  const sha=(f:string)=>createHash('sha256').update(
   execFileSync('openssl',['pkey','-pubin','-inform','PEM','-outform','DER'],
    {input:execFileSync('openssl',['x509','-pubkey','-noout','-in',f],{cwd:dir}),
     cwd:dir})).digest('hex');
  const rootSha=sha('ca.crt'),leafSha=sha('leaf.crt');
  assert.deepEqual(certificateBody({caseId:id,rootCertificatePem:root,
   leafCertificatePem:leaf}),{caseId:id,rootCertificatePem:root,leafCertificatePem:leaf});
  const record=inspectOneHopCertificateChain(root,leaf,rootSha,leafSha);
  assert.equal(record.oneHopSignatureValid,true);
  assert.equal(record.rfc5280FullPathValidated,false);
  assert.equal(record.providerRealIdentityAuthenticated,false);
  assert.equal(record.rootSpkiSha256,rootSha);
  assert.equal(record.leafSpkiSha256,leafSha);
  assert.throws(()=>inspectOneHopCertificateChain(root,leaf,'c'.repeat(64),leafSha),
   ChainConflictError);
  assert.throws(()=>inspectOneHopCertificateChain(root,leaf,rootSha,'d'.repeat(64)),
   ChainConflictError);
  assert.throws(()=>inspectOneHopCertificateChain(root,root,rootSha,rootSha),
   ChainConflictError);
  assert.throws(()=>inspectOneHopCertificateChain(root,leaf,rootSha,leafSha,
   Date.now()+4*86_400_000),ChainConflictError);
  assert.throws(()=>certificateBody({caseId:id,rootCertificatePem:'<PRIVATE KEY>',
   leafCertificatePem:leaf}),ChainInputError);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('sandbox migration is refused on production or non-isolated targets',()=>{
 assert.equal(providerSandboxMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',
  NODE_ENV:'test'}),'ci');
 assert.equal(providerSandboxMigrationTarget({PROVIDER_SANDBOX_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_sandbox',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{PROVIDER_SANDBOX_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_sandbox',
  DB_SSL:'true',NODE_ENV:'production'},
 {PROVIDER_SANDBOX_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_prod',
  DB_SSL:'true',NODE_ENV:'development'}])assert.throws(()=>providerSandboxMigrationTarget(env));
});
