import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {sha} from '../dispatch/validation';
import {verifyExactSnapshot,heldGrnSnapshot} from '../evidenceChain/validation';
import {checkHeldSource,checkClaim,checkInternallyAttestedClaim,
 checkQuarantine,makePack,verifyPersistedPack} from '../evidenceChain/integrity';
import {ChainConflictError,releaseSnapshot,releaseHoldSnapshot,
 type ReleaseSource,type ReleaseLine} from './validation';
function deny():never{
 throw new ChainConflictError('Unverified supplier/GRN source, modified custody or stock ledger boundary');
}
export async function readHeldGrnSource(conn:PoolConnection,heldGrnId:string):Promise<ReleaseSource>{
 const [heldRows]=await conn.query<RowDataPacket[]>(`SELECT h.id,h.pack_id AS packId,
   h.decision_id AS decisionId,h.status AS holdState,
   h.stock_posting_state AS postingState,
   h.snapshot_sha256 AS holdSha256,h.snapshot_json AS holdJson,
   p.claim_id AS claimId,p.observation_id AS observationId,
   p.prepared_by AS preparedBy,p.status AS packStatus,
   p.pack_sha256 AS packSha256,p.pack_json AS packJson,
   c.preparation_id AS preparationId
   FROM inv_grn_held_records h
   JOIN inv_grn_reconciliation_packs p ON p.id=h.pack_id
   JOIN proc_ack_claims c ON c.id=p.claim_id
   WHERE h.id=?`,[heldGrnId]);
 if(heldRows.length!==1)deny();
 const h=heldRows[0];
 const source=await checkHeldSource(conn,String(h.preparationId));
 const [locked]=await conn.query<RowDataPacket[]>(`SELECT id,pack_id AS packId,
  decision_id AS decisionId,status AS holdState,stock_posting_state AS postingState,
  snapshot_sha256 AS holdSha256,snapshot_json AS holdJson
  FROM inv_grn_held_records WHERE id=? FOR UPDATE`,[heldGrnId]);
 if(locked.length!==1)deny();
 const live=locked[0];
 if(h.holdSha256!==live.holdSha256||h.packId!==live.packId||
  h.decisionId!==live.decisionId||source.ownerId!==h.preparedBy||
  h.packStatus!=='HELD_INTERNAL'||live.holdState!=='HELD'||live.postingState!=='DISABLED')deny();
 const claim=await checkClaim(conn,String(h.claimId),source);
 await checkInternallyAttestedClaim(conn,claim);
 const quarantine=await checkQuarantine(conn,String(h.observationId),source);
 const canonical=makePack(source,claim,quarantine);
 verifyPersistedPack(h.packJson,String(h.packSha256),canonical);
 const [decision]=await conn.query<RowDataPacket[]>(`SELECT id,reviewer_id AS reviewerId,
  decision,custody_inspected AS inspected FROM inv_grn_reconciliation_decisions
  WHERE id=? AND pack_id=?`,[live.decisionId,live.packId]);
 if(decision.length!==1||decision[0].decision!=='HELD_INTERNAL'||
  Number(decision[0].inspected)!==1||decision[0].reviewerId===source.ownerId)deny();
 const expected=heldGrnSnapshot(String(live.packId),String(h.packSha256),String(live.decisionId));
 verifyExactSnapshot(live.holdJson,expected,String(live.holdSha256));
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
   quantity,tracking_mode AS trackingMode,lot_code AS lotCode,
   serials_json AS serialNumbers FROM inv_inbound_lines WHERE observation_id=?
   ORDER BY product_id`,[quarantine.id]);
 if(rows.length!==quarantine.lineCount)deny();
 const lines:ReleaseLine[]=rows.map(row=>{
  const numbers=typeof row.serialNumbers==='string'?JSON.parse(row.serialNumbers):row.serialNumbers;
  if(!Array.isArray(numbers)||numbers.some(x=>typeof x!=='string'))deny();
  return {productId:String(row.productId),quantity:Number(row.quantity),
   trackingMode:row.trackingMode as ReleaseLine['trackingMode'],
   lotCode:row.lotCode as string|null,serialNumbers:numbers as string[]};
 });
 return {heldGrnId,heldGrnSha256:String(live.holdSha256),observationId:quarantine.id,
  siteId:source.siteId,ownerId:source.ownerId,holdId:source.holdId,lines};
}
export async function checkReleaseIntent(conn:PoolConnection,id:string){
 const [head]=await conn.query<RowDataPacket[]>(`SELECT id,held_grn_id AS heldGrnId,
   observation_id AS observationId,site_id AS siteId,prepared_by AS preparedBy,
   source_sha256 AS sourceSha256,intent_sha256 AS intentSha256,
   intent_json AS intentJson,status FROM inv_stock_release_intents WHERE id=?`,[id]);
 if(head.length!==1)deny();
 const r=head[0],source=await readHeldGrnSource(conn,String(r.heldGrnId));
 const [locked]=await conn.query<RowDataPacket[]>(`SELECT id,status,intent_sha256 AS intentSha256,
   intent_json AS intentJson FROM inv_stock_release_intents WHERE id=? FOR UPDATE`,[id]);
 if(locked.length!==1)deny();
 const expected=releaseSnapshot(source),hash=sha(JSON.stringify(expected));
 if(r.observationId!==source.observationId||r.siteId!==source.siteId||
  r.preparedBy!==source.ownerId||r.sourceSha256!==source.heldGrnSha256||
  r.intentSha256!==hash||locked[0].intentSha256!==hash||
  r.status!==locked[0].status)deny();
 verifyExactSnapshot(locked[0].intentJson,expected,hash);
 const [lines]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
  site_id AS siteId,observed_quantity AS quantity,tracking_mode AS trackingMode,
  lot_code AS lotCode,serials_json AS serialNumbers FROM inv_stock_release_intent_lines
  WHERE release_intent_id=? ORDER BY product_id`,[id]);
 if(lines.length!==source.lines.length)deny();
 for(let i=0;i<lines.length;i++){
  const actual=lines[i],original=source.lines[i],numbers=
   typeof actual.serialNumbers==='string'?JSON.parse(actual.serialNumbers):actual.serialNumbers;
  if(actual.productId!==original.productId||actual.siteId!==source.siteId||
   Number(actual.quantity)!==original.quantity||actual.trackingMode!==original.trackingMode||
   actual.lotCode!==original.lotCode||!Array.isArray(numbers)||
   JSON.stringify([...numbers].sort())!==JSON.stringify([...original.serialNumbers].sort()))deny();
 }
 return {id,source,status:String(locked[0].status),intentSha256:hash};
}
export async function verifyReleaseHeld(conn:PoolConnection,id:string){
 const state=await checkReleaseIntent(conn,id);
 if(state.status!=='REVIEWED_HELD')deny();
 const [reviews]=await conn.query<RowDataPacket[]>(`SELECT id,decision,
  reviewer_id AS reviewerId,source_inspected AS inspected
  FROM inv_stock_release_decisions WHERE release_intent_id=?`,[id]);
 if(reviews.length!==1||reviews[0].decision!=='REVIEWED_HELD'||
  reviews[0].reviewerId===state.source.ownerId||Number(reviews[0].inspected)!==1)deny();
 const [holds]=await conn.query<RowDataPacket[]>(`SELECT decision_id AS decisionId,
  state,posting_state AS postingState,snapshot_sha256 AS digest,snapshot_json AS snapshot
  FROM inv_stock_release_holds WHERE release_intent_id=?`,[id]);
 if(holds.length!==1||holds[0].decisionId!==reviews[0].id||
  holds[0].state!=='HELD'||holds[0].postingState!=='DISABLED')deny();
 const snapshot=releaseHoldSnapshot(id,state.intentSha256,String(reviews[0].id));
 verifyExactSnapshot(holds[0].snapshot,snapshot,String(holds[0].digest));
 return state;
}
export async function zeroPosition(conn:PoolConnection,site:string,product:string){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT available_quantity AS available,
 reserved_quantity AS reserved,picked_quantity AS picked,posted_quantity AS posted
 FROM inv_stock_position_gates WHERE site_id=? AND product_id=? FOR UPDATE`,[site,product]);
 if(rows.length!==1||[rows[0].available,rows[0].reserved,rows[0].picked,rows[0].posted]
  .some(x=>Number(x)!==0))deny();
}
