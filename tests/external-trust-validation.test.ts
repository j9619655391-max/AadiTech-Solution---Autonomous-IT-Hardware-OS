import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import {validateIssuer,validateAuthority,validateAuthorityTemplate,validateRevocation,
 revocationTemplate,validateReview,authorityMessage,revocationMessage,
 verifySigned,digest,ChainInputError} from '../server/externalTrust/validation';
import {externalTrustMigrationTarget} from '../scripts/migrate-external-trust';
const issuer=generateKeyPairSync('ed25519');
const spki=issuer.publicKey.export({format:'der',type:'spki'}).toString('base64');
const partyId=randomUUID(),issuerId=randomUUID(),keyId=randomUUID(),
 now=new Date(Math.floor(Date.now()/1000)*1000);
const iso=(dt:Date)=>new Date(Math.floor(dt.getTime()/1000)*1000).toISOString().replace(/\.\d{3}Z$/,'.000Z');
const from=iso(new Date(now.getTime()-60_000)),until=iso(new Date(now.getTime()+3_600_000));
const sig=(v:object)=>sign(null,Buffer.from(JSON.stringify(v),'utf8'),issuer.privateKey).toString('base64');
test('owner-entered Ed25519 issuer candidate is NEVER authenticated external CA',()=>{
 const c=validateIssuer({partyKind:'SUPPLIER',partyId,
  issuerSpkiB64:spki,organizationRegistration:'ORG-REG-2026',
  evidenceRef:'OFFLINE-SELF-CLAIM-2026'});
 assert.match(c.issuerFingerprint,/^[a-f0-9]{64}$/);
 assert.equal(c.issuerSpkiB64,spki);
 assert.throws(()=>validateIssuer({partyKind:'SUPPLIER',partyId,issuerSpkiB64:spki,
  organizationRegistration:'ORG-REG-2026',evidenceRef:'OFFLINE-SELF-CLAIM-2026',
  trusted:true}),ChainInputError);
 assert.throws(()=>validateIssuer({partyKind:'CERTIFIED',partyId,
  issuerSpkiB64:spki,organizationRegistration:'ORG-REG-2026',
  evidenceRef:'OFFLINE-SELF-CLAIM-2026'}),ChainInputError);
});
test('exact source, issuer+candidate fingerprints and purposes bind signed authority',()=>{
 const input={issuerId,keyId,purpose:'SUPPLIER_ACK' as const,validFrom:from,validUntil:until};
 const message=authorityMessage({...input,issuerFingerprint:'a'.repeat(64),
  keyFingerprint:'b'.repeat(64),partyKind:'SUPPLIER',partyId,
  organizationRegistration:'ORG-REG-2026'});
 const signatureB64=sig(message);
 assert.equal(verifySigned(message,issuer.publicKey,signatureB64),true);
 assert.equal(verifySigned({...message,partyId:randomUUID()},issuer.publicKey,signatureB64),false);
 assert.equal(verifySigned({...message,purpose:'WAREHOUSE_GRN'},issuer.publicKey,signatureB64),false);
 assert.equal(message.issuerExternallyAuthenticated,false);
 assert.equal(message.organizationAuthorityVerified,false);
 assert.equal(message.stockPostingState,'DISABLED');
 assert.deepEqual(validateAuthority({...input,signatureB64}),{...input,signatureB64});
 assert.deepEqual(validateAuthorityTemplate(input),input);
 assert.match(digest(message),/^[0-9a-f]{64}$/);
 assert.throws(()=>validateAuthority({...input,signatureB64,orgVerified:true}),ChainInputError);
 assert.throws(()=>validateAuthority({...input,purpose:'ISSUED_PO',signatureB64}),ChainInputError);
});
test('signed revocations enforce sorted unique fingerprints, 24h TTL and fixed signature bytes',()=>{
 const a='a'.repeat(64),b='b'.repeat(64);
 const input={issuerId,sequenceNumber:1,issuedAt:from,expiresAt:until,
  revokedFingerprints:[a,b]};
 const message=revocationMessage({...input,issuerFingerprint:'c'.repeat(64),
  partyKind:'SUPPLIER',partyId});
 const signatureB64=sig(message);
 assert.equal(verifySigned(message,issuer.publicKey,signatureB64),true);
 assert.equal(verifySigned({...message,sequenceNumber:2},issuer.publicKey,signatureB64),false);
 assert.deepEqual(validateRevocation({...input,signatureB64}),{...input,signatureB64});
 assert.deepEqual(revocationTemplate(input),input);
 assert.equal(message.externalTrustEstablished,false);
 for(const attack of [{revokedFingerprints:[b,a]},{revokedFingerprints:[a,a]},
  {revokedFingerprints:['A'.repeat(64)]},{sequenceNumber:0},
  {expiresAt:iso(new Date(now.getTime()+48*3_600_000))},
  {signatureB64:'notbase64'},{trustedPublisher:true}])
  assert.throws(()=>validateRevocation({...input,signatureB64,...attack}),ChainInputError);
});
test('independent reviewer can only approve internal HELD state',()=>{
 const body={decision:'REVIEWED_HELD',reason:'Inspected registry document as an internal claim only',
  evidenceRef:'INTERNAL-REGISTRY-TICKET-2026',evidenceInspected:true};
 assert.deepEqual(validateReview(body,'REVIEWED_HELD'),body);
 assert.throws(()=>validateReview({...body,decision:'TRUSTED'},'REVIEWED_HELD'),ChainInputError);
 assert.throws(()=>validateReview({...body,evidenceInspected:false},'REVIEWED_HELD'),ChainInputError);
 assert.equal(validateReview({...body,decision:'REVIEWED_CRYPTO_HELD'},'REVIEWED_CRYPTO_HELD')
  .decision,'REVIEWED_CRYPTO_HELD');
});
test('guarded migration does not touch production or unapproved staging',()=>{
 assert.equal(externalTrustMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',
  NODE_ENV:'test'}),'ci');
 assert.equal(externalTrustMigrationTarget({EXTERNAL_TRUST_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_external',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const x of [{},{EXTERNAL_TRUST_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_external',
  DB_SSL:'true',NODE_ENV:'production'},
 {EXTERNAL_TRUST_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'production',
  DB_SSL:'true',NODE_ENV:'development'}])assert.throws(()=>externalTrustMigrationTarget(x));
});
