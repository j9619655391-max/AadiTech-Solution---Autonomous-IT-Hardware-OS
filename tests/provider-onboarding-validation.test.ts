import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync,writeFileSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {packetBody,packetReviewBody,revocationBody,artifactReviewBody,mcaBody,mcaReviewBody,
 offlineSignedRevocationCheck,isolatedSandbox,CCA_CURRENT_CPS_REFERENCE,
 ChainInputError,ChainConflictError,AO_BLOCKERS}
 from '../server/providerOnboarding/validation';
import {providerOnboardingMigrationTarget} from '../scripts/migrate-provider-onboarding';
const env={NODE_ENV:'test',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'};
test('Phase1AO inputs reject private contract, API credentials, real KYC or production flags',()=>{
 const packet={nominationId:randomUUID(),contractDocumentSha256:'a'.repeat(64),
  providerOnboardingRef:'CI-LEGAL-TICKET-2026',sandboxScopeRef:'CI-SCOPE-TICKET-2026'};
 assert.deepEqual(packetBody(packet),packet);
 for(const bad of [{providerApiKey:'SECRET'},{externalContractApproved:true},
  {contractDocumentSha256:'invalid'},{nominationId:'bad-uuid'}])
  assert.throws(()=>packetBody({...packet,...bad}),ChainInputError);
 for(const reviewRole of ['LEGAL','SECURITY']){
  const body={reviewRole,decision:'INSPECTED_HELD',
   reason:'Reviewed internal only; no genuine provider agreement or credentials',
   evidenceRef:'CI-REVIEWER-2026',noExternalContractAcknowledged:true,
   noLiveCredentialsAcknowledged:true};
  assert.equal(packetReviewBody(body).decision,'INSPECTED_HELD');
  assert.throws(()=>packetReviewBody({...body,decision:'APPROVED_LIVE'}),ChainInputError);
  assert.throws(()=>packetReviewBody({...body,noExternalContractAcknowledged:false}),
   ChainInputError);
 }
 assert.throws(()=>packetReviewBody({reviewRole:'PROVIDER',decision:'INSPECTED_HELD',
  reason:'Wrong reviewer role',evidenceRef:'TICKET',
  noExternalContractAcknowledged:true,noLiveCredentialsAcknowledged:true}),ChainInputError);
 assert.ok(CCA_CURRENT_CPS_REFERENCE.startsWith('https://cca.gov.in/'));
 assert.ok(AO_BLOCKERS.length>6);
 const mca={packetId:randomUUID(),dossierId:randomUUID(),
  mcaMasterDataSha256:'c'.repeat(64),signatoryMandateSha256:'d'.repeat(64),
  verificationTicket:'CI-MCA-NONPROD-2026'};
 assert.deepEqual(mcaBody(mca),mca);
 assert.throws(()=>mcaBody({...mca,personCard:'private'}),ChainInputError);
 const review={decision:'INSPECTED_HELD',reason:'Not independently authenticated by MCA',
  evidenceRef:'CI-MCA-REVIEW-2026',externalMcaAuthenticationMissingAcknowledged:true,
  signatoryAuthorityMissingAcknowledged:true};
 assert.equal(mcaReviewBody(review).decision,'INSPECTED_HELD');
 assert.throws(()=>mcaReviewBody({...review,decision:'VERIFIED'}),ChainInputError);
 assert.throws(()=>artifactReviewBody({decision:'TRUSTED',
  reason:'Internal cryptographic result only',evidenceRef:'CI-CERT-2026',
  issuerProvenanceMissingAcknowledged:true}),ChainInputError);
 assert.equal(isolatedSandbox(env),true);
 assert.equal(isolatedSandbox({...env,NODE_ENV:'production'}),false);
 assert.equal(isolatedSandbox({...env,DB_NAME:'aaditech_live'}),false);
});
test('Offline X509 CRL and OCSP signed by synthetic CA verify mathematically; tampering/revoked/expired sources fail',()=>{
 const dir=mkdtempSync(join(tmpdir(),'aaditech-ao-signed-status-'));
 const run=(argv:string[])=>execFileSync('openssl',argv,{cwd:dir,stdio:'pipe'});
 try{
  run(['genpkey','-algorithm','ED25519','-out','root.key']);
  run(['req','-x509','-new','-key','root.key','-out','root.pem','-days','3',
   '-subj','/CN=CI NonProduction Provider CA',
   '-addext','basicConstraints=critical,CA:TRUE',
   '-addext','keyUsage=critical,keyCertSign,cRLSign']);
  run(['genpkey','-algorithm','ED25519','-out','leaf.key']);
  run(['req','-new','-key','leaf.key','-out','leaf.csr','-subj','/CN=CI NonProduction Warehouse']);
  writeFileSync(join(dir,'leaf.ext'),'basicConstraints=critical,CA:FALSE\n'+
   'keyUsage=critical,digitalSignature\ncertificatePolicies=1.2.3.4.5\n');
  run(['x509','-req','-in','leaf.csr','-CA','root.pem','-CAkey','root.key',
   '-CAcreateserial','-out','leaf.pem','-days','2','-extfile','leaf.ext']);
  const serial=run(['x509','-in','leaf.pem','-noout','-serial']).toString().trim().split('=')[1];
  const validTo=run(['x509','-in','leaf.pem','-noout','-enddate']).toString().trim().split('=')[1];
  const fmt=(date:Date)=>date.toISOString().slice(2,4)+date.toISOString().slice(5,7)+
   date.toISOString().slice(8,10)+date.toISOString().slice(11,13)+
   date.toISOString().slice(14,16)+date.toISOString().slice(17,19)+'Z';
  mkdirSync(join(dir,'newcerts'));
  writeFileSync(join(dir,'serial'),'1000\n');
  writeFileSync(join(dir,'crlnumber'),'1000\n');
  writeFileSync(join(dir,'index.txt'),
   'V\t'+fmt(new Date(validTo))+'\t\t'+serial+'\tunknown\t/CN=CI NonProduction Warehouse\n');
  writeFileSync(join(dir,'ca.cnf'),
   '[ca]\ndefault_ca=CA_default\n[CA_default]\n'+
   'database=./index.txt\nnew_certs_dir=./newcerts\n'+
   'certificate=./root.pem\nprivate_key=./root.key\nserial=./serial\n'+
   'crlnumber=./crlnumber\ndefault_md=default\ndefault_crl_days=2\n'+
   'policy=policy_any\n[policy_any]\ncommonName=supplied\n');
  run(['ca','-gencrl','-config','ca.cnf','-out','crl.pem','-batch']);
  run(['crl','-in','crl.pem','-outform','DER','-out','crl.der']);
  run(['ocsp','-index','index.txt','-rsigner','root.pem','-rkey','root.key',
   '-CA','root.pem','-issuer','root.pem','-cert','leaf.pem',
   '-respout','ocsp.der','-ndays','2']);
  const root=readFileSync(join(dir,'root.pem'),'utf8'),
   leaf=readFileSync(join(dir,'leaf.pem'),'utf8'),
   crl=readFileSync(join(dir,'crl.der')).toString('base64'),
   ocsp=readFileSync(join(dir,'ocsp.der')).toString('base64');
  const trialId=randomUUID();
  const crlInput=revocationBody({trialId,artifactType:'CRL',artifactDerB64:crl});
  const ocspInput=revocationBody({trialId,artifactType:'OCSP',artifactDerB64:ocsp});
  assert.match(crlInput.digest,/^[a-f0-9]{64}$/);
  assert.match(ocspInput.digest,/^[a-f0-9]{64}$/);
  for(const [kind,data] of [['CRL',crl],['OCSP',ocsp]] as const){
   const proof=offlineSignedRevocationCheck(kind,data,root,leaf,env);
   assert.equal(proof.signedArtifactMathVerified,true);
   assert.equal(proof.actualExternalPublisherAuthenticated,false);
   assert.equal(proof.productionReady,false);
   assert.throws(()=>offlineSignedRevocationCheck(kind,data,root,leaf,
    {...env,DB_NAME:'aaditech_production'}),ChainConflictError);
   const corrupted=Buffer.from(data,'base64');
   // Corrupt the ASN.1 DER tag (always invalid); signed and unsigned fields differ.
   corrupted[0]^=0x80;
   assert.throws(()=>offlineSignedRevocationCheck(kind,
    corrupted.toString('base64'),root,leaf,env),ChainConflictError);
  }
  assert.throws(()=>revocationBody({trialId,artifactType:'CRL',
   artifactDerB64:crl,externalIssuerVerified:true}),ChainInputError);
  assert.throws(()=>revocationBody({trialId,artifactType:'INVALID',
   artifactDerB64:crl}),ChainInputError);
  assert.throws(()=>revocationBody({trialId,artifactType:'OCSP',
   artifactDerB64:'NOT-BASE64'}),ChainInputError);
  run(['ca','-revoke','leaf.pem','-config','ca.cnf','-batch']);
  run(['ca','-gencrl','-config','ca.cnf','-out','revoked.pem','-batch']);
  run(['crl','-in','revoked.pem','-outform','DER','-out','revoked.der']);
  assert.throws(()=>offlineSignedRevocationCheck('CRL',
   readFileSync(join(dir,'revoked.der')).toString('base64'),root,leaf,env),
   ChainConflictError);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('0027 migration restricted to disposable CI or approved isolated TLS staging',()=>{
 assert.equal(providerOnboardingMigrationTarget(env),'ci');
 assert.equal(providerOnboardingMigrationTarget({
  NODE_ENV:'development',DB_NAME:'aaditech_staging_provider',
  DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  PROVIDER_ONBOARDING_MIGRATION_APPROVED:'YES'}),'staging');
 assert.throws(()=>providerOnboardingMigrationTarget({
  NODE_ENV:'production',DB_NAME:'aaditech_staging_provider',DB_SSL:'true',
  STAGING_DISPOSABLE_CONFIRMED:'YES',PROVIDER_ONBOARDING_MIGRATION_APPROVED:'YES'}));
 assert.throws(()=>providerOnboardingMigrationTarget({
  NODE_ENV:'development',DB_NAME:'aaditech_live',DB_SSL:'true',
  STAGING_DISPOSABLE_CONFIRMED:'YES',PROVIDER_ONBOARDING_MIGRATION_APPROVED:'YES'}));
});
