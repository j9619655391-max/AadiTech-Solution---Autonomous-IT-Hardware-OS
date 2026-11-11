import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {validateProposal,validateReview,canonicalLegs,journalManifest,journalDigest,
 balanceJournal,legDigest,journalHoldSnapshot,ChainInputError,ChainConflictError} from '../server/journalFoundation/validation';
import {journalFoundationMigrationTarget} from '../scripts/migrate-journal-foundation';
import {verifyDeepFrozenSnapshot} from '../server/stockFoundation/validation';
const releaseIntentId=randomUUID(),siteId=randomUUID(),productId=randomUUID();
const lines=[{productId,quantity:2,trackingMode:'SERIAL' as const,lotCode:null,
 serialNumbers:['SERIAL-A-2026','SERIAL-B-2026']},
 {productId:randomUUID(),quantity:3,trackingMode:'LOT' as const,
 lotCode:'LOT-MANIFEST-2026',serialNumbers:[]}];
test('proposal/review strict input forbids posting, forged proof flags and self-reported availability',()=>{
 assert.deepEqual(validateProposal({releaseIntentId}),{releaseIntentId});
 assert.throws(()=>validateProposal({releaseIntentId,stockPost:true}),ChainInputError);
 assert.throws(()=>validateProposal({releaseIntentId:'broken'}),ChainInputError);
 const body={decision:'REVIEWED_HELD',reason:'Checked duplicate legs against internal quarantine',
  evidenceRef:'INTERNAL-DOUBLE-ENTRY-REVIEW-2026',balancingInspected:true};
 assert.deepEqual(validateReview(body),body);
 assert.throws(()=>validateReview({...body,decision:'POSTED'}),ChainInputError);
 assert.throws(()=>validateReview({...body,balancingInspected:false}),ChainInputError);
 assert.throws(()=>validateReview({...body,reason:'tiny'}),ChainInputError);
 assert.equal(validateReview({...body,decision:'REJECTED_INTERNAL',
  balancingInspected:false}).decision,'REJECTED_INTERNAL');
});
test('canonical journal builds two balanced nonposting legs per SKU and sorted serial identity',()=>{
 const manifest=journalManifest({releaseIntentId,releaseSha256:'a'.repeat(64),siteId,lines});
 const totals=balanceJournal(manifest.legs);
 assert.equal(totals.legCount,4);
 assert.equal(totals.skuCount,2);
 assert.equal(totals.evidenceUnits,5);
 assert.equal(totals.postedUnits,0);
 assert.equal(manifest.journalPosted,false);
 assert.equal(manifest.postingState,'DISABLED');
 assert.equal(manifest.officialGrnVerified,false);
 assert.equal(manifest.availableToSell,null);
 assert.match(journalDigest(manifest),/^[0-9a-f]{64}$/);
 for(const leg of manifest.legs)assert.match(legDigest(leg),/^[0-9a-f]{64}$/);
 assert.deepEqual(verifyDeepFrozenSnapshot(manifest,manifest,journalDigest(manifest)),manifest);
 assert.throws(()=>verifyDeepFrozenSnapshot({...manifest,legs:[...manifest.legs,
  {...manifest.legs[0]}]},manifest,journalDigest(manifest)),ChainConflictError);
 assert.throws(()=>verifyDeepFrozenSnapshot({...manifest,legs:manifest.legs.map(l=>({
  ...l,serialNumbers:l.serialNumbers.map(s=>s==='SERIAL-A-2026'?'FORGED-2026':s)
 }))},manifest,journalDigest(manifest)),ChainConflictError);
 const hold=journalHoldSnapshot(randomUUID(),journalDigest(manifest),randomUUID());
 assert.equal(hold.stockPosted,false);assert.equal(hold.availableToSell,null);
});
test('journal rejects unbalanced/skipped/extra legs, invalid tracking, duplicated serial',()=>{
 const original=canonicalLegs(lines,siteId);
 assert.throws(()=>balanceJournal(original.slice(1)),ChainConflictError);
 assert.throws(()=>balanceJournal([...original,original[0],original[1]]),ChainConflictError);
 assert.throws(()=>balanceJournal(original.map((l,i)=>i===0?{...l,quantity:99}:l)),ChainConflictError);
 assert.throws(()=>canonicalLegs([...lines,lines[0]],siteId),ChainConflictError);
 assert.throws(()=>canonicalLegs([{...lines[0],serialNumbers:['SERIAL-A-2026','SERIAL-A-2026']}],siteId),
  ChainConflictError);
 assert.throws(()=>canonicalLegs([{...lines[0],trackingMode:'LOT' as const,lotCode:'LOT-X-2026'}],siteId),
  ChainConflictError);
});
test('migration guard rejects production and unauthorized staging',()=>{
 assert.equal(journalFoundationMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',
  NODE_ENV:'test'}),'ci');
 assert.equal(journalFoundationMigrationTarget({JOURNAL_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_journal',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const e of [{},{JOURNAL_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_journal',
  DB_SSL:'true',NODE_ENV:'production'},
 {JOURNAL_FOUNDATION_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'production',DB_SSL:'true',NODE_ENV:'development'},
 {JOURNAL_FOUNDATION_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_journal',DB_SSL:'false',NODE_ENV:'development'}])
  assert.throws(()=>journalFoundationMigrationTarget(e));
});
