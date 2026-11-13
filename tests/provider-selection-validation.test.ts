import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {PROVIDER,nominationBody,policyBody,dossierBody,accessBody,reviewBody,
 inspectLocalPolicyDryRun,ChainInputError,ChainConflictError,RELEASE_BLOCKERS}
 from '../server/providerSelection/validation';
import {providerSelectionMigrationTarget} from '../scripts/migrate-provider-selection';
const id=randomUUID(),certId=randomUUID(),nominationId=randomUUID();
test('CCA-listed eMudhra is a named EVALUATION candidate, not approved trust provider',()=>{
 assert.equal(PROVIDER.code,'EMUDHRA_INDIA_CCA');
 assert.equal(PROVIDER.legalName,'eMudhra Limited');
 assert.ok(PROVIDER.authorityUrl.startsWith('https://cca.gov.in/'));
 assert.ok(PROVIDER.registryUrl.startsWith('https://www.mca.gov.in/'));
 assert.deepEqual(nominationBody({providerCode:PROVIDER.code,
  nominationTicket:'INTERNAL-PROVIDER-SELECTION-2026'}),
  {providerCode:PROVIDER.code,nominationTicket:'INTERNAL-PROVIDER-SELECTION-2026'});
 for(const providerCode of ['DIGICERT','CCA_APPROVED','TRUSTED','EMUDHRA_PREFERRED'])
  assert.throws(()=>nominationBody({providerCode,
   nominationTicket:'INTERNAL-PROVIDER-SELECTION-2026'}),ChainInputError);
 assert.throws(()=>nominationBody({providerCode:PROVIDER.code,
  nominationTicket:'INTERNAL-PROVIDER-SELECTION-2026',approved:true}),ChainInputError);
 assert.ok(RELEASE_BLOCKERS.length>=5);
});
test('policy OID, corporate dossier SHA-only references and no raw credential ingestion',()=>{
 const policy={nominationId,certId,policyOid:'1.2.3.4.5',
  cpsSha256:'a'.repeat(64),purpose:'SUPPLIER_ACK'};
 assert.deepEqual(policyBody(policy),policy);
 for(const attack of [{policyOid:'1.2.invalid'},{policyOid:'1.02.3'},
  {policyOid:'../../tmp/key'},{cpsSha256:'NOT_REAL'},
  {purpose:'LIVE_STOCK'},{providerValidated:true}])
  assert.throws(()=>policyBody({...policy,...attack}),ChainInputError);
 const dossier={nominationId,sandboxCaseId:id,registryReference:'REG-EXAMPLE-2026',
  companyMasterDataSha256:'b'.repeat(64),
  signatoryDelegationSha256:'c'.repeat(64),
  sourceEvidenceRef:'MCA-EVIDENCE-HASH-TICKET-2026'};
 assert.deepEqual(dossierBody(dossier),dossier);
 assert.throws(()=>dossierBody({...dossier,personIdCard:'PRIVATE'}),ChainInputError);
 assert.deepEqual(accessBody({nominationId,requestTicket:'SANDBOX-ACCESS-REQUEST-2026'}),
  {nominationId,requestTicket:'SANDBOX-ACCESS-REQUEST-2026'});
 assert.throws(()=>accessBody({nominationId,requestTicket:'SANDBOX-ACCESS-REQUEST-2026',
  apiKey:'SECRET'}),ChainInputError);
 const reviewed={decision:'REVIEWED_CANDIDATE_HELD',
  reason:'Inspected CCA public licensed CA directory; no contract or API credential exists',
  evidenceRef:'CCA-DUE-DILIGENCE-2026',
  officialListingInspected:true,contractMissingAcknowledged:true};
 assert.equal(reviewBody(reviewed,'REVIEWED_CANDIDATE_HELD',
  ['officialListingInspected','contractMissingAcknowledged']).decision,'REVIEWED_CANDIDATE_HELD');
 assert.throws(()=>reviewBody({...reviewed,decision:'TRUSTED'},
  'REVIEWED_CANDIDATE_HELD',['officialListingInspected','contractMissingAcknowledged']),ChainInputError);
 assert.throws(()=>reviewBody({...reviewed,contractMissingAcknowledged:false},
  'REVIEWED_CANDIDATE_HELD',['officialListingInspected','contractMissingAcknowledged']),ChainInputError);
});
test('strict OpenSSL one-hop policy OID verification has no CRL or operational authority',()=>{
 const dir=mkdtempSync(join(tmpdir(),'aaditech-named-ca-'));
 try{
  const run=(argv:string[])=>execFileSync('openssl',argv,{cwd:dir,stdio:'pipe'});
  run(['genpkey','-algorithm','ED25519','-out','root.key']);
  run(['req','-x509','-new','-key','root.key','-out','root.pem','-days','3',
   '-subj','/CN=CI Explicit Policy Root',
   '-addext','basicConstraints=critical,CA:TRUE',
   '-addext','keyUsage=critical,keyCertSign,cRLSign',
   '-addext','subjectKeyIdentifier=hash']);
  run(['genpkey','-algorithm','ED25519','-out','leaf.key']);
  run(['req','-new','-key','leaf.key','-out','leaf.csr',
   '-subj','/CN=CI-Signer-Only']);
  writeFileSync(join(dir,'leaf.ext'),
   'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'+
   'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'+
   'certificatePolicies=1.2.3.4.5\n');
  run(['x509','-req','-in','leaf.csr','-CA','root.pem','-CAkey','root.key',
   '-CAcreateserial','-out','leaf.pem','-days','2','-extfile','leaf.ext']);
  const root=readFileSync(join(dir,'root.pem'),'utf8'),
   leaf=readFileSync(join(dir,'leaf.pem'),'utf8');
  const env={NODE_ENV:'test',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'};
  const result=inspectLocalPolicyDryRun(root,leaf,'1.2.3.4.5',env);
  assert.equal(result.oneHopOpenSslPolicyTrialMatched,true);
  assert.equal(result.productionPathAccepted,false);
  assert.equal(result.providerPolicyApproved,false);
  assert.equal(result.trustedCrlOcspValidated,false);
  assert.throws(()=>inspectLocalPolicyDryRun(root,leaf,'1.2.3.4.6',env),
   ChainConflictError);
  assert.throws(()=>inspectLocalPolicyDryRun(root,leaf,'1.2.3.4.5',
   {...env,NODE_ENV:'production'}),ChainConflictError);
  assert.throws(()=>inspectLocalPolicyDryRun(root,leaf,'1.2.3.4.5',
   {...env,CRM_TEST_DB:'0',DB_NAME:'aaditech_prod'}),ChainConflictError);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('guarded Phase 1AN migration refuses production and unintended databases',()=>{
 assert.equal(providerSelectionMigrationTarget({CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(providerSelectionMigrationTarget({
  PROVIDER_SELECTION_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_named',DB_SSL:'true',NODE_ENV:'development'}),'staging');
 assert.throws(()=>providerSelectionMigrationTarget({
  PROVIDER_SELECTION_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_named',DB_SSL:'true',NODE_ENV:'production'}));
 assert.throws(()=>providerSelectionMigrationTarget({
  PROVIDER_SELECTION_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_live',DB_SSL:'true',NODE_ENV:'development'}));
});
