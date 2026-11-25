import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign,createHash} from 'node:crypto';
import {pinConfig,validateCredential,validateCredentialTemplate,
 credentialMessage,validateFeed,validateFeedTemplate,feedMessage,verify,
 validateReviewHeld,ChainInputError,sha} from '../server/providerBridge/validation';
import {transportAllowed,REVOCATION_PATH} from '../server/providerBridge/transport';
import {providerBridgeMigrationTarget} from '../scripts/migrate-provider-bridge';
const root=generateKeyPairSync('ed25519');
const spki=root.publicKey.export({format:'der',type:'spki'});
const hash=createHash('sha256').update(spki).digest('hex');
const pinId=randomUUID(),issuerId=randomUUID();
const env={PROVIDER_CODE:'TEST_PROVIDER',PROVIDER_HTTPS_ORIGIN:'https://provider.example.invalid',
 PROVIDER_ROOT_SPKI_B64:spki.toString('base64'),PROVIDER_ROOT_SHA256:hash,
 PROVIDER_TLS_SPKI_SHA256:'b'.repeat(64)};
const iso=(offset:number)=>new Date(Math.floor((Date.now()+offset)/1000)*1000).toISOString();
const signMessage=(msg:object)=>sign(null,Buffer.from(JSON.stringify(msg),'utf8'),root.privateKey).toString('base64');
test('preprovisioned public root requires matching separate Ed25519 SPKI pin and safe HTTPS DNS origin',()=>{
 const p=pinConfig(env);
 assert.equal(p.rootFingerprint,hash);assert.equal(p.origin,env.PROVIDER_HTTPS_ORIGIN);
 for(const bad of [
  {...env,PROVIDER_ROOT_SHA256:'a'.repeat(64)},
  {...env,PROVIDER_HTTPS_ORIGIN:'http://provider.example.invalid'},
  {...env,PROVIDER_HTTPS_ORIGIN:'https://127.0.0.1'},
  {...env,PROVIDER_HTTPS_ORIGIN:'https://localhost'},
  {...env,PROVIDER_HTTPS_ORIGIN:'https://provider.example.invalid:8443'},
  {...env,PROVIDER_HTTPS_ORIGIN:'https://provider.example.invalid/path'},
  {...env,PROVIDER_CODE:'test_lowercase'},
  {...env,PROVIDER_TLS_SPKI_SHA256:'not-a-sha'},
  {}])assert.throws(()=>pinConfig(bad));
 assert.equal(REVOCATION_PATH,'/.well-known/aaditech/revocations/latest');
});
test('root-signed credential is bound to provider, exact issuer/party/purpose and hard false external authority flags',()=>{
 const input={pinId,issuerId,purpose:'SUPPLIER_ACK' as const,
  validFrom:iso(-60_000),validUntil:iso(3_600_000)};
 const msg=credentialMessage({...input,providerCode:'TEST_PROVIDER',
  providerOrigin:env.PROVIDER_HTTPS_ORIGIN,rootFingerprint:hash,
  issuerFingerprint:'a'.repeat(64),partyKind:'SUPPLIER',partyId:randomUUID(),
  organizationRegistration:'REG-SUPPLIER-2026'});
 const signatureB64=signMessage(msg);
 assert.equal(verify(msg,root.publicKey,signatureB64),true);
 assert.equal(verify({...msg,partyId:randomUUID()},root.publicKey,signatureB64),false);
 assert.equal(msg.independentCorporateVerification,false);
 assert.equal(msg.externallyAuthenticatedRoot,false);
 assert.equal(msg.officialGrnVerified,false);
 assert.equal(msg.stockPosting,'DISABLED');
 assert.match(sha(JSON.stringify(msg)),/^[a-f0-9]{64}$/);
 assert.deepEqual(validateCredential({...input,signatureB64}),{...input,signatureB64});
 assert.deepEqual(validateCredentialTemplate(input),input);
 for(const bad of [{purpose:'ISSUED_PO'},{trusted:true},
  {validUntil:iso(31*86_400_000)},{signatureB64:'not-base64'}])
  assert.throws(()=>validateCredential({...input,signatureB64,...bad}),ChainInputError);
});
test('revocation signed feed is strictly canonical, contiguous-ready and cannot claim external transport',()=>{
 const input={pinId,sequenceNumber:1,publishedAt:iso(-60_000),
  validUntil:iso(60*60_000),revokedFingerprints:['a'.repeat(64),'b'.repeat(64)]};
 const msg=feedMessage({...input,providerCode:'TEST_PROVIDER',
  providerOrigin:env.PROVIDER_HTTPS_ORIGIN,rootFingerprint:hash});
 const signatureB64=signMessage(msg);
 assert.equal(verify(msg,root.publicKey,signatureB64),true);
 assert.equal(verify({...msg,sequenceNumber:2},root.publicKey,signatureB64),false);
 assert.equal(msg.externalPublisherVerified,false);
 assert.deepEqual(validateFeed({...input,signatureB64}),{...input,signatureB64});
 assert.deepEqual(validateFeedTemplate(input),input);
 for(const bad of [
  {sequenceNumber:0},{revokedFingerprints:['b'.repeat(64),'a'.repeat(64)]},
  {revokedFingerprints:['a'.repeat(64),'a'.repeat(64)]},
  {validUntil:iso(48*60*60_000)},{publisherAuthenticated:true},
  {signatureB64:'A'}])
  assert.throws(()=>validateFeed({...input,signatureB64,...bad}),ChainInputError);
});
test('only internally HELD reviews and pinned HTTPS staging transport accepted',()=>{
 const review={decision:'REVIEWED_HELD',reason:'Compared offline configured root pin to internal ticket',
  evidenceRef:'ROOT-REVIEW-TICKET-2026',evidenceInspected:true};
 assert.deepEqual(validateReviewHeld(review,'REVIEWED_HELD'),review);
 assert.throws(()=>validateReviewHeld({...review,decision:'TRUSTED'},'REVIEWED_HELD'),ChainInputError);
 assert.throws(()=>validateReviewHeld({...review,evidenceInspected:false},'REVIEWED_HELD'),ChainInputError);
 assert.throws(()=>transportAllowed(env));
 const staging={...env,PROVIDER_PINNED_FETCH_ENABLED:'YES',
  PROVIDER_PIN_FETCH_SCOPE:'ISOLATED_STAGING',NODE_ENV:'development',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true',DB_NAME:'aaditech_staging_provider_ci'};
 assert.equal(transportAllowed(staging).rootFingerprint,hash);
 assert.throws(()=>transportAllowed({...staging,NODE_ENV:'production'}));
 assert.throws(()=>transportAllowed({...staging,DB_NAME:'aaditech_production'}));
 assert.throws(()=>transportAllowed({...staging,DB_SSL:'false'}));
});
test('guarded migration rejects production and unintended target',()=>{
 assert.equal(providerBridgeMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',
  NODE_ENV:'test'}),'ci');
 assert.equal(providerBridgeMigrationTarget({PROVIDER_BRIDGE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_provider',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{PROVIDER_BRIDGE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_provider',
  DB_SSL:'true',NODE_ENV:'production'},
 {PROVIDER_BRIDGE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_production',
  DB_SSL:'true',NODE_ENV:'development'}])assert.throws(()=>providerBridgeMigrationTarget(env));
});
