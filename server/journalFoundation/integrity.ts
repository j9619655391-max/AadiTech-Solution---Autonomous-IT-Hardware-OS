import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {verifyReleaseHeld,zeroPosition} from '../stockFoundation/integrity';
import {verifyDeepFrozenSnapshot,ChainConflictError} from '../stockFoundation/validation';
import {sha} from '../dispatch/validation';
import {canonicalLegs,journalManifest,journalDigest,
 balanceJournal,legDigest,journalHoldSnapshot,type JournalLeg} from './validation';
function deny():never{
 throw new ChainConflictError('Unposted journal source, balancing, serial evidence or hard-zero inventory gate failed');
}
function jsonList(raw:unknown):unknown[]{
 let v:unknown=raw;
 if(typeof v==='string'){try{v=JSON.parse(v);}catch{deny();}}
 if(!Array.isArray(v))deny();
 return v;
}
export async function checkJournal(conn:PoolConnection,id:string){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,release_intent_id AS releaseIntentId,
  site_id AS siteId,prepared_by AS preparedBy,release_sha256 AS releaseSha256,
  manifest_sha256 AS manifestSha256,manifest_json AS manifestJson,
  status,posting_state AS postingState
  FROM inv_unposted_journal_headers WHERE id=?`,[id]);
 if(rows.length!==1)deny();
 const row=rows[0],release=await verifyReleaseHeld(conn,String(row.releaseIntentId));
 const [locked]=await conn.query<RowDataPacket[]>(`SELECT status,
   manifest_sha256 AS manifestSha256,manifest_json AS manifestJson,
   posting_state AS postingState FROM inv_unposted_journal_headers
   WHERE id=? FOR UPDATE`,[id]);
 if(locked.length!==1||row.status!==locked[0].status||
  row.manifestSha256!==locked[0].manifestSha256)deny();
 if(row.siteId!==release.source.siteId||row.preparedBy!==release.source.ownerId||
   row.releaseSha256!==release.intentSha256||row.postingState!=='DISABLED'||
   locked[0].postingState!=='DISABLED')deny();
 const expected=journalManifest({releaseIntentId:row.releaseIntentId,
  releaseSha256:release.intentSha256,siteId:release.source.siteId,
  lines:release.source.lines});
 const digest=journalDigest(expected);
 if(row.manifestSha256!==digest)deny();
 verifyDeepFrozenSnapshot(locked[0].manifestJson,expected,digest);
 const balanced=balanceJournal(expected.legs as JournalLeg[]);
 const [legs]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
  site_id AS siteId,account_code AS accountCode,entry_side AS side,
  quantity,tracking_mode AS trackingMode,lot_code AS lotCode,
  serials_json AS serialNumbers,leg_sha256 AS digest,posting_state AS postingState
  FROM inv_unposted_journal_legs WHERE journal_id=? ORDER BY product_id,account_code`,[id]);
 if(legs.length!==expected.legs.length)deny();
 for(let i=0;i<legs.length;i++){
  const a=legs[i],b=expected.legs[i] as JournalLeg;
  const serialized=jsonList(a.serialNumbers);
  if(a.postingState!=='DISABLED'||a.productId!==b.productId||a.siteId!==b.siteId||
   a.accountCode!==b.accountCode||a.side!==b.side||
   Number(a.quantity)!==b.quantity||a.trackingMode!==b.trackingMode||
   a.lotCode!==b.lotCode||a.digest!==legDigest(b))deny();
  verifyDeepFrozenSnapshot(serialized,b.serialNumbers,sha(JSON.stringify(b.serialNumbers)));
 }
 const expectedSerials=release.source.lines.flatMap(l=>l.serialNumbers.map(serial=>({
  productId:l.productId,siteId:release.source.siteId,serialNumber:serial
 }))).sort((a,b)=>a.productId.localeCompare(b.productId)||
  a.serialNumber.localeCompare(b.serialNumber));
 const [candidates]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
  site_id AS siteId,serial_number AS serialNumber,
  provenance_state AS provenanceState,ownership_state AS ownershipState
  FROM inv_unposted_serial_candidates WHERE journal_id=?
  ORDER BY product_id,serial_number`,[id]);
 if(candidates.length!==expectedSerials.length)deny();
 for(let i=0;i<candidates.length;i++){
  const a=candidates[i],b=expectedSerials[i];
  if(a.productId!==b.productId||a.siteId!==b.siteId||
   a.serialNumber!==b.serialNumber||a.provenanceState!=='UNVERIFIED'||
   a.ownershipState!=='NOT_ESTABLISHED')deny();
 }
 const [blockers]=await conn.query<RowDataPacket[]>(`SELECT
  external_po_verified AS externalPo,supplier_ack_authenticated AS ack,
  official_grn_verified AS grn,warehouse_release_authorized AS warehouse,
  stock_credit_state AS stockCredit FROM inv_unposted_source_blockers WHERE journal_id=?`,[id]);
 if(blockers.length!==1||blockers[0].externalPo!=='NO'||
  blockers[0].ack!=='NO'||blockers[0].grn!=='NO'||
  blockers[0].warehouse!=='NO'||blockers[0].stockCredit!=='DISABLED')deny();
 for(const line of release.source.lines)
  await zeroPosition(conn,release.source.siteId,line.productId);
 return {journalId:id,status:String(locked[0].status),manifest:expected,
  manifestSha256:digest,release,balanced};
}
export async function checkReviewedJournalHold(conn:PoolConnection,id:string){
 const state=await checkJournal(conn,id);
 if(state.status!=='REVIEWED_HELD')deny();
 const [reviews]=await conn.query<RowDataPacket[]>(`SELECT id,reviewer_id AS reviewerId,
  decision,balancing_inspected AS inspected FROM inv_unposted_journal_reviews
  WHERE journal_id=?`,[id]);
 if(reviews.length!==1||reviews[0].decision!=='REVIEWED_HELD'||
  reviews[0].reviewerId===state.release.source.ownerId||
  Number(reviews[0].inspected)!==1)deny();
 const [holds]=await conn.query<RowDataPacket[]>(`SELECT review_id AS reviewId,
  state,posting_state AS postingState,snapshot_sha256 AS digest,snapshot_json AS snapshot
  FROM inv_unposted_journal_holds WHERE journal_id=?`,[id]);
 if(holds.length!==1||holds[0].reviewId!==reviews[0].id||
  holds[0].state!=='HELD'||holds[0].postingState!=='DISABLED')deny();
 const expected=journalHoldSnapshot(id,state.manifestSha256,String(reviews[0].id));
 verifyDeepFrozenSnapshot(holds[0].snapshot,expected,String(holds[0].digest));
 return state;
}
