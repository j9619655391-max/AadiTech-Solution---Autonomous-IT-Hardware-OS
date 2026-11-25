import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {reconstructHoldHash} from '../intake/validation';
import {canonicalIntakeHash,validateInbound} from '../intake/validation';
import {verifyManifestJson} from '../dispatch/validation';
import {ChainConflictError,claimDigest,packSnapshot,
 verifyExactSnapshot,verifyOutbox} from './validation';

function bad():never{throw new ChainConflictError('Source evidence chain incomplete, altered, or not independently attested');}
export type HeldSource={
 preparationId:string;holdId:string;ownerId:string;siteId:string;requestId:string;
 supplierId:string;manifestSha256:string;outboxSha256:string;outboxId:string;
 holdSha256:string;destinationId:string;email:string;outboxDecisionId:string;
};
export async function checkHeldSource(conn:PoolConnection,preparationId:string):Promise<HeldSource>{
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT p.id AS preparationId,
  p.hold_id AS holdId,p.prepared_by AS ownerId,p.status AS preparationStatus,
  p.manifest_sha256 AS manifestSha256,p.manifest_json AS manifestJson,
  p.hold_sha256 AS holdSha256,p.destination_id AS destinationId,
  p.authorization_evidence_ref AS authorizationEvidenceRef,
  h.snapshot_json AS holdJson,h.snapshot_sha256 AS originalHoldSha256,
  h.status AS holdStatus,h.dispatch_state AS holdDispatchState,
  h.decision_id AS purchaseDecisionId,
  r.id AS requestId,r.created_by AS purchaseOwnerId,r.site_id AS siteId,
  r.supplier_id AS supplierId,r.status AS purchaseStatus,
  s.status AS supplierStatus,
  d.supplier_id AS destinationSupplierId,d.email,
  d.status AS destinationStatus,d.created_by AS destinationOwnerId,
  d.reviewed_by AS destinationReviewerId,
  review.id AS dispatchDecisionId,review.reviewer_id AS dispatchReviewerId,
  review.decision AS dispatchReviewDecision,
  o.id AS outboxId,o.state AS outboxState,o.dispatch_state AS outboxDispatchState,
  o.decision_id AS outboxDecisionId,o.snapshot_sha256 AS outboxSha256,
  o.snapshot_json AS outboxJson
  FROM proc_dispatch_preparations p
  JOIN proc_po_holds h ON h.id=p.hold_id
  JOIN proc_requests r ON r.id=h.request_id
  JOIN proc_suppliers s ON s.id=r.supplier_id
  JOIN proc_delivery_destinations d ON d.id=p.destination_id
  JOIN proc_dispatch_review_decisions review ON review.preparation_id=p.id
  JOIN proc_dispatch_outbox_holds o ON o.preparation_id=p.id
  WHERE p.id=? FOR UPDATE`,[preparationId]);
 if(rows.length!==1)bad();
 const r=rows[0];
 if(r.preparationStatus!=='APPROVED_INTERNAL'||r.dispatchReviewDecision!=='APPROVED_INTERNAL'||
  r.outboxState!=='HELD'||r.outboxDispatchState!=='DISABLED'||
  r.holdStatus!=='HELD'||r.holdDispatchState!=='DISABLED'||
  r.purchaseStatus!=='APPROVED_INTERNAL'||r.supplierStatus!=='REVIEWED_INTERNAL'||
  r.destinationStatus!=='REVIEWED_INTERNAL'||r.purchaseOwnerId!==r.ownerId||
  r.destinationOwnerId!==r.ownerId||r.destinationSupplierId!==r.supplierId||
  r.dispatchReviewerId===r.ownerId||r.destinationReviewerId===r.ownerId||
  !r.destinationReviewerId||!r.dispatchReviewerId||
  r.dispatchDecisionId!==r.outboxDecisionId||
  r.holdSha256!==r.originalHoldSha256||reconstructHoldHash(r.holdJson)!==r.holdSha256)
  bad();
 const manifest=verifyManifestJson(r.manifestJson,r.manifestSha256);
 if(manifest.holdId!==r.holdId||manifest.holdSha256!==r.holdSha256||
  manifest.supplierId!==r.supplierId||manifest.destinationId!==r.destinationId||
  manifest.email!==r.email||manifest.authorizationEvidenceRef!==r.authorizationEvidenceRef)
  bad();
 verifyOutbox(r.outboxJson,r.outboxSha256,{preparationId:r.preparationId,
  manifestSha256:r.manifestSha256,decisionId:r.dispatchDecisionId});
 const [review]=await conn.query<RowDataPacket[]>(
  "SELECT id,decision,reviewer_id AS reviewerId FROM proc_review_decisions WHERE id=? AND request_id=?",
  [r.purchaseDecisionId,r.requestId]);
 if(review.length!==1||review[0].decision!=='APPROVED_INTERNAL'||
  review[0].reviewerId===r.ownerId)bad();
 return {preparationId:r.preparationId,holdId:r.holdId,ownerId:r.ownerId,
  siteId:r.siteId,requestId:r.requestId,supplierId:r.supplierId,
  manifestSha256:r.manifestSha256,outboxSha256:r.outboxSha256,
  outboxId:r.outboxId,holdSha256:r.holdSha256,destinationId:r.destinationId,
  email:r.email,outboxDecisionId:r.outboxDecisionId};
}

export type ClaimSource={id:string;status:string;recordedBy:string;
 claimSha256:string;outboxSha256:string;documentSha256:string;
 preparationId:string;supplierAckRef:string;evidenceRef:string};
export async function checkClaim(conn:PoolConnection,claimId:string,source:HeldSource):Promise<ClaimSource>{
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,status,recorded_by AS recordedBy,
  preparation_id AS preparationId,outbox_id AS outboxId,
  supplier_ack_ref AS supplierAckRef,evidence_ref AS evidenceRef,
  document_sha256 AS documentSha256,outbox_sha256 AS outboxSha256,
  claim_sha256 AS claimSha256 FROM proc_ack_claims WHERE id=? FOR UPDATE`,[claimId]);
 if(rows.length!==1)bad();
 const c=rows[0];
 if(c.preparationId!==source.preparationId||c.outboxId!==source.outboxId||
  c.outboxSha256!==source.outboxSha256||c.recordedBy!==source.ownerId||
  claimDigest({preparationId:c.preparationId,supplierAckRef:c.supplierAckRef,
   evidenceRef:c.evidenceRef,documentSha256:c.documentSha256},
   source.outboxSha256)!==c.claimSha256)bad();
 return {id:c.id,status:c.status,recordedBy:c.recordedBy,
  claimSha256:c.claimSha256,outboxSha256:c.outboxSha256,documentSha256:c.documentSha256,
  preparationId:c.preparationId,supplierAckRef:c.supplierAckRef,evidenceRef:c.evidenceRef};
}
export async function checkInternallyAttestedClaim(conn:PoolConnection,claim:ClaimSource):Promise<void>{
 if(claim.status!=='ATTESTED_INTERNAL')bad();
 const [decisions]=await conn.query<RowDataPacket[]>(`SELECT decision,reviewer_id AS reviewerId,
   document_inspected AS inspected FROM proc_ack_claim_decisions WHERE claim_id=?`,[claim.id]);
 if(decisions.length!==1||decisions[0].decision!=='ATTESTED_INTERNAL'||
  decisions[0].reviewerId===claim.recordedBy||Number(decisions[0].inspected)!==1)bad();
}
export type QuarantineSource={id:string;observationSha256:string;
 quantityTotal:number;lineCount:number};
export async function checkQuarantine(conn:PoolConnection,observationId:string,
 source:HeldSource):Promise<QuarantineSource>{
 const [obs]=await conn.query<RowDataPacket[]>(`SELECT o.id,o.hold_id AS holdId,
  o.request_id AS requestId,o.site_id AS siteId,o.recorded_by AS recordedBy,
  o.delivery_evidence_ref AS deliveryEvidenceRef,
  o.physical_count_ref AS physicalCountRef,o.payload_sha256 AS payloadSha256,o.status,
  d.outcome,d.reviewer_id AS reviewerId
  FROM inv_inbound_observations o
  LEFT JOIN inv_inbound_decisions d ON d.observation_id=o.id WHERE o.id=? FOR UPDATE`,
  [observationId]);
 if(obs.length!==1)bad();
 const o=obs[0];
 if(o.holdId!==source.holdId||o.requestId!==source.requestId||
  o.siteId!==source.siteId||o.recordedBy!==source.ownerId||
  o.status!=='QUARANTINED_INTERNAL'||o.outcome!=='ACCEPT_QUARANTINE'||
  !o.reviewerId||o.reviewerId===source.ownerId)bad();
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT l.id,l.product_id AS productId,
   l.quantity,l.tracking_mode AS trackingMode,l.lot_code AS lotCode,
   l.serials_json AS serialNumbers,
   e.id AS eventId,e.quantity AS eventQuantity,e.product_id AS eventProductId,
   e.site_id AS eventSiteId,e.event_type AS eventType,
   e.recorded_by AS eventActor
   FROM inv_inbound_lines l LEFT JOIN inv_quarantine_custody_events e ON e.line_id=l.id
   WHERE l.observation_id=? ORDER BY l.product_id`,[observationId]);
 if(rows.length<1||rows.length>25)bad();
 const normalized=rows.map(row=>{
  const serials=typeof row.serialNumbers==='string'?
    JSON.parse(row.serialNumbers):row.serialNumbers;
  if(!row.eventId||row.eventQuantity!==row.quantity||
   row.eventProductId!==row.productId||row.eventSiteId!==source.siteId||
   row.eventType!=='QUARANTINE_WITNESS_ATTESTED'||row.eventActor!==o.reviewerId)bad();
  return {productId:String(row.productId),quantity:Number(row.quantity),
   trackingMode:row.trackingMode,lotCode:row.lotCode,serialNumbers:serials};
 });
 const validated=validateInbound({holdId:source.holdId,
  deliveryEvidenceRef:o.deliveryEvidenceRef,
  physicalCountRef:o.physicalCountRef,items:normalized});
 const hash=canonicalIntakeHash({
  ...validated,items:[...validated.items].sort((a,b)=>a.productId.localeCompare(b.productId))});
 if(hash!==o.payloadSha256)bad();
 const [purchaseLines]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,quantity
  FROM proc_request_items WHERE request_id=? ORDER BY product_id`,[source.requestId]);
 if(purchaseLines.length!==rows.length)bad();
 for(const line of purchaseLines){
  const observed=validated.items.find(x=>x.productId===line.productId);
  if(!observed||observed.quantity!==Number(line.quantity))bad();
 }
 const [serialRows]=await conn.query<RowDataPacket[]>(`SELECT product_id AS productId,
  serial_number AS serialNumber,site_id AS siteId FROM inv_quarantine_serials
  WHERE observation_id=? ORDER BY product_id,serial_number`,[observationId]);
 const expected=validated.items.flatMap(line=>line.serialNumbers.map(serial=>({
  productId:line.productId,serialNumber:serial,siteId:source.siteId
 }))).sort((a,b)=>a.productId.localeCompare(b.productId)||a.serialNumber.localeCompare(b.serialNumber));
 if(serialRows.length!==expected.length)bad();
 for(let i=0;i<serialRows.length;i++){
  const row=serialRows[i],match=expected[i];
  if(row.productId!==match.productId||row.serialNumber!==match.serialNumber||row.siteId!==match.siteId)
   bad();
 }
 return {id:o.id,observationSha256:o.payloadSha256,
  quantityTotal:validated.items.reduce((sum,line)=>sum+line.quantity,0),
  lineCount:validated.items.length};
}
export function makePack(source:HeldSource,claim:ClaimSource,observation:QuarantineSource){
 return packSnapshot({claimId:claim.id,observationId:observation.id,
  holdId:source.holdId,dispatchPreparationId:source.preparationId,
  outboxSha256:source.outboxSha256,claimSha256:claim.claimSha256,
  observationSha256:observation.observationSha256,holdSha256:source.holdSha256,
  quantityTotal:observation.quantityTotal,lineCount:observation.lineCount});
}
export function verifyPersistedPack(raw:unknown,digest:string,expected:ReturnType<typeof makePack>){
 return verifyExactSnapshot(raw,expected,digest);
}
