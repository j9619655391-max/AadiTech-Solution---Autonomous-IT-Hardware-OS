import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {validateClaim,validateClaimDecision,validatePack,validatePackDecision,
 claimDigest,packSnapshot,sha256,verifyOutbox,verifyExactSnapshot,
 heldGrnSnapshot,ChainInputError,ChainConflictError} from '../server/evidenceChain/validation';
import {sha} from '../server/dispatch/validation';
import {evidenceChainMigrationTarget} from '../scripts/migrate-evidence-chain';

const preparationId=randomUUID(),claimId=randomUUID(),observationId=randomUUID(),holdId=randomUUID();
const sample={preparationId,supplierAckRef:'SUPP-ACK-2026-001',evidenceRef:'DOC-ACK-2026-001',
 documentSha256:'a'.repeat(64)};
test('strict untrusted supplier acknowledgment claim body and document checksum',()=>{
 assert.deepEqual(validateClaim(sample),sample);
 assert.match(claimDigest(sample,'b'.repeat(64)),/^[0-9a-f]{64}$/);
 for(const update of [{status:'VERIFIED'}, {supplierAckRef:'lowercase-claim'},
  {supplierAckRef:'BAD\r\nBCC:fake'}, {documentSha256:'ABC'.repeat(21)+'A'},
  {documentSha256:'not-a-checksum'},{preparationId:'x'}, {evidenceRef:'bad'}]){
  assert.throws(()=>validateClaim({...sample,...update}),ChainInputError);
 }
 assert.throws(()=>sha256(null),ChainInputError);
});
test('independent reviewer decisions cannot claim external authority',()=>{
 const decision={decision:'ATTESTED_INTERNAL',reason:'Inspected the offline supplier claim evidence',
  reviewEvidenceRef:'REVIEW-ACK-2026-01',documentInspected:true};
 assert.deepEqual(validateClaimDecision(decision),decision);
 assert.throws(()=>validateClaimDecision({...decision,documentInspected:false}));
 assert.throws(()=>validateClaimDecision({...decision,decision:'SUPPLIER_VERIFIED'}));
 assert.throws(()=>validateClaimDecision({...decision,reason:'short'}));
 assert.equal(validateClaimDecision({...decision,decision:'DISPUTED_INTERNAL',
  documentInspected:false}).decision,'DISPUTED_INTERNAL');
 assert.deepEqual(validatePack({claimId,observationId}),{claimId,observationId});
 assert.throws(()=>validatePack({claimId,observationId,issue:true}));
 const packDecision={decision:'HELD_INTERNAL',reason:'All internal quarantine lines independently inspected',
  reviewEvidenceRef:'GRN-REVIEW-2026-001',custodyInspected:true};
 assert.deepEqual(validatePackDecision(packDecision),packDecision);
 assert.throws(()=>validatePackDecision({...packDecision,custodyInspected:false}));
 assert.throws(()=>validatePackDecision({...packDecision,decision:'STOCK_POSTED'}));
 assert.equal(validatePackDecision({...packDecision,decision:'REJECTED_INTERNAL',
  custodyInspected:false}).decision,'REJECTED_INTERNAL');
});
test('canonical PO and GRN HELD signatures reject body tampering',()=>{
 const outbox={format:'aaditech-supplier-PO-outbox-HELD-v1',preparationId,
  manifestSha256:'f'.repeat(64),decisionId:randomUUID(),
  dispatchState:'DISABLED',externalPoIssued:false};
 assert.deepEqual(verifyOutbox(Object.fromEntries(Object.entries(outbox).reverse()),
  sha(JSON.stringify(outbox)),{preparationId,manifestSha256:outbox.manifestSha256,
   decisionId:outbox.decisionId}),outbox);
 assert.throws(()=>verifyOutbox({...outbox,externalPoIssued:true},sha(JSON.stringify(outbox)),
  {preparationId,manifestSha256:outbox.manifestSha256,decisionId:outbox.decisionId}),
 ChainConflictError);
 const pack=packSnapshot({claimId,observationId,holdId,dispatchPreparationId:preparationId,
  outboxSha256:'a'.repeat(64),claimSha256:'b'.repeat(64),
  observationSha256:'c'.repeat(64),holdSha256:'d'.repeat(64),quantityTotal:5,lineCount:2});
 assert.equal(pack.externalPoIssued,false);
 assert.equal(pack.stockPostingState,'DISABLED');
 assert.deepEqual(verifyExactSnapshot(pack,pack,sha(JSON.stringify(pack))),pack);
 assert.throws(()=>verifyExactSnapshot({...pack,officialGrnCreated:true},pack,
  sha(JSON.stringify(pack))),ChainConflictError);
 const hold=heldGrnSnapshot(randomUUID(),sha(JSON.stringify(pack)),randomUUID());
 assert.equal(hold.stockPostingState,'DISABLED');
 assert.equal(hold.availableToSell,null);
});
test('migration strictly denied for production and unapproved staging',()=>{
 assert.equal(evidenceChainMigrationTarget({NODE_ENV:'test',CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci'}),'ci');
 assert.equal(evidenceChainMigrationTarget({NODE_ENV:'development',
  EVIDENCE_CHAIN_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_evidence',DB_SSL:'true'}),'staging');
 for(const env of [{}, {NODE_ENV:'production',DB_NAME:'aaditech_staging_evidence',
  EVIDENCE_CHAIN_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true'},
 {NODE_ENV:'development',DB_NAME:'production',
  EVIDENCE_CHAIN_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true'},
 {NODE_ENV:'development',DB_NAME:'aaditech_staging_evidence',
  EVIDENCE_CHAIN_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'false'}])
  assert.throws(()=>evidenceChainMigrationTarget(env));
});
