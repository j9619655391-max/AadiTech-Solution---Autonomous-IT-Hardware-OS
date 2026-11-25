import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {randomUUID} from 'node:crypto';
import {validateKey,validateClaim,validateTemplate,validateKeyReview,
 validateClaimReview,signedMessage,verifyDetachedSignature,
 candidatePublicKey,messageDigest,proofHoldSnapshot,
 ChainInputError,ChainConflictError,verifyDeepFrozenSnapshot} from '../server/proofFoundation/validation';
import {signedProofMigrationTarget} from '../scripts/migrate-signed-proof';
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const spki=publicKey.export({format:'der',type:'spki'}).toString('base64');
const supplierId=randomUUID(),sourceId=randomUUID(),keyId=randomUUID();
const claimBase={keyId,kind:'SUPPLIER_ACK_ASSERTION' as const,
 sourceId,reference:'CLAIM-2026-1234',
 documentSha256:'a'.repeat(64),issuedAt:'2026-11-12T00:00:00.000Z'};
test('Ed25519 SPKI DER key candidate validates exact format and non-trust state',()=>{
 const key=validateKey({partyKind:'SUPPLIER',partyId:supplierId,publicKeySpkiB64:spki,
  evidenceRef:'OFFLINE-KEY-REG-2026'});
 assert.match(key.fingerprint,/^[0-9a-f]{64}$/);
 assert.equal(key.spkiB64,spki);
 assert.throws(()=>candidatePublicKey('not-base64'),ChainInputError);
 assert.throws(()=>candidatePublicKey(Buffer.alloc(44).toString('base64')),ChainInputError);
 assert.throws(()=>validateKey({partyKind:'SUPPLIER',partyId:supplierId,
  publicKeySpkiB64:spki,evidenceRef:'X',trusted:true}),ChainInputError);
 assert.throws(()=>validateKey({partyKind:'EXTERNALLY_TRUSTED',partyId:supplierId,
  publicKeySpkiB64:spki,evidenceRef:'OFFLINE-KEY-REG-2026'}),ChainInputError);
});
test('Canonical offline evidence detached Ed25519 signature matches only frozen source and exact bytes',()=>{
 const sourceSha256='b'.repeat(64);
 const message=signedMessage({...claimBase,sourceSha256,partyId:supplierId});
 const signed=sign(null,Buffer.from(JSON.stringify(message),'utf8'),privateKey).toString('base64');
 const parsed=validateClaim({...claimBase,signatureB64:signed});
 assert.equal(parsed.kind,'SUPPLIER_ACK_ASSERTION');
 assert.deepEqual(validateTemplate(claimBase),claimBase);
 assert.equal(verifyDetachedSignature(publicKey,message,signed),true);
 assert.equal(verifyDetachedSignature(publicKey,{...message,sourceSha256:'c'.repeat(64)},signed),false);
 assert.equal(verifyDetachedSignature(publicKey,{...message,kind:'PO_ISSUANCE_ASSERTION'},signed),false);
 assert.match(messageDigest(message),/^[0-9a-f]{64}$/);
 assert.equal(message.externalIdentityVerified,false);
 assert.equal(message.stockPostingState,'DISABLED');
 assert.deepEqual(verifyDeepFrozenSnapshot(message,message,messageDigest(message)),message);
 assert.throws(()=>verifyDeepFrozenSnapshot({...message,externalIdentityVerified:true},
  message,messageDigest(message)),ChainConflictError);
});
test('Exact key and signed proof review body requires inspection; no trusted states accepted',()=>{
 const positive={decision:'REVIEWED_UNTRUSTED',reason:'Independently inspected candidate key format',
  evidenceRef:'OFFLINE-KEY-WITNESS-2026',documentInspected:true};
 assert.equal(validateKeyReview(positive).decision,'REVIEWED_UNTRUSTED');
 assert.throws(()=>validateKeyReview({...positive,documentInspected:false}),ChainInputError);
 assert.throws(()=>validateKeyReview({...positive,decision:'TRUSTED'}),ChainInputError);
 assert.equal(validateClaimReview({...positive,decision:'REVIEWED_CRYPTO_ONLY'}).decision,
  'REVIEWED_CRYPTO_ONLY');
 assert.throws(()=>validateClaimReview({...positive,decision:'GRN_AUTHENTICATED'}),ChainInputError);
 const hold=proofHoldSnapshot(randomUUID(),'a'.repeat(64),randomUUID());
 assert.equal(hold.partyIdentity,'UNVERIFIED');assert.equal(hold.officialGrnVerified,false);
 assert.equal(hold.availableToSell,null);
 for(const extra of [{issuedAt:'2026-11-12T00:00:00Z'},
  {documentSha256:'A'.repeat(64)},{signatureB64:'x'}, {kind:'TRUSTED_GRN'},
  {verifiedSupplier:true}])
  assert.throws(()=>validateClaim({...claimBase,signatureB64:'A'.repeat(86)+'==',...extra}),ChainInputError);
});
test('Signed proof migration refuses production and unauthorized databases',()=>{
 assert.equal(signedProofMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(signedProofMigrationTarget({SIGNED_PROOF_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_proof',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{SIGNED_PROOF_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_proof',
  DB_SSL:'true',NODE_ENV:'production'},
 {SIGNED_PROOF_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'production',
  DB_SSL:'true',NODE_ENV:'development'}])
  assert.throws(()=>signedProofMigrationTarget(env));
});
