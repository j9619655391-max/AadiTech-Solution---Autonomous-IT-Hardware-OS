import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {keyIdBody,challengeResponse,reviewBody,rotationBody,reasonEvidence,
 nonce,possessionMessage,sha256,verifyPossession,ChainInputError} from '../server/keyLifecycle/validation';
import {keyLifecycleMigrationTarget} from '../scripts/migrate-key-lifecycle';
const keyId=randomUUID(),newKeyId=randomUUID(),partyId=randomUUID();
test('one-time Ed25519 offline possession message binds candidate fingerprint and nonce',()=>{
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const args={challengeId:randomUUID(),keyId,
  keyFingerprint:'a'.repeat(64),partyKind:'SUPPLIER' as const,partyId,nonceB64:nonce()};
 const message=possessionMessage(args);
 const signatureB64=sign(null,Buffer.from(JSON.stringify(message),'utf8'),privateKey).toString('base64');
 assert.equal(verifyPossession(publicKey,message,signatureB64),true);
 assert.equal(verifyPossession(publicKey,{...message,nonceB64:nonce()},signatureB64),false);
 assert.equal(verifyPossession(publicKey,{...message,keyFingerprint:'b'.repeat(64)},signatureB64),false);
 assert.equal(message.identityAuthenticated,false);
 assert.equal(message.officialGrnAuthenticated,false);
 assert.equal(message.stockPosting,'DISABLED');
 assert.match(sha256(JSON.stringify(message)),/^[a-f0-9]{64}$/);
 assert.deepEqual(challengeResponse({challengeId:args.challengeId,nonceB64:args.nonceB64,
  signatureB64}),{challengeId:args.challengeId,nonceB64:args.nonceB64,signatureB64});
 for(const attack of [{nonceB64:'not-a-nonce'},
  {signatureB64:'X'}, {identityVerified:true}])
  assert.throws(()=>challengeResponse({challengeId:args.challengeId,
   nonceB64:args.nonceB64,signatureB64,...attack}),ChainInputError);
});
test('strict rotation and revocation contracts deny trust promotion and self-review',()=>{
 assert.deepEqual(keyIdBody({keyId}),{keyId});
 assert.throws(()=>keyIdBody({keyId,trustNow:true}),ChainInputError);
 const data={reason:'Internal security incident, rotate affected offline candidate',
  evidenceRef:'CI-KEY-LIFECYCLE-TICKET-2026'};
 assert.deepEqual(reasonEvidence(data),data);
 assert.deepEqual(rotationBody({oldKeyId:keyId,newKeyId,...data}),
  {oldKeyId:keyId,newKeyId,...data});
 assert.throws(()=>rotationBody({oldKeyId:keyId,newKeyId:keyId,...data}),ChainInputError);
 assert.throws(()=>rotationBody({oldKeyId:keyId,newKeyId,...data,externalTrust:true}),ChainInputError);
 assert.throws(()=>reasonEvidence({reason:'short',evidenceRef:data.evidenceRef}),ChainInputError);
 const review={decision:'REVIEWED_UNTRUSTED',...data,possessionInspected:true};
 assert.deepEqual(reviewBody(review),review);
 assert.throws(()=>reviewBody({...review,decision:'TRUSTED'}),ChainInputError);
 assert.throws(()=>reviewBody({...review,possessionInspected:false}),ChainInputError);
 assert.equal(reviewBody({...review,decision:'REJECTED_INTERNAL',
  possessionInspected:false}).decision,'REJECTED_INTERNAL');
});
test('migration refuses production or accidental live database',()=>{
 assert.equal(keyLifecycleMigrationTarget({CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(keyLifecycleMigrationTarget({KEY_LIFECYCLE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_lifecycle',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{KEY_LIFECYCLE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_lifecycle',
  DB_SSL:'true',NODE_ENV:'production'},
 {KEY_LIFECYCLE_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'live_crm',
  DB_SSL:'true',NODE_ENV:'development'}])
  assert.throws(()=>keyLifecycleMigrationTarget(env));
});
