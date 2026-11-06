import { Router } from 'express';
import { createHash, randomUUID } from 'node:crypto';
import type { RowDataPacket } from 'mysql2/promise';
import { requireOwner } from '../auth/router';
import { getPool } from '../db';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function fail(res:import('express').Response,e:unknown){
  if(e && typeof e==='object' && 'code' in e && e.code==='ER_DUP_ENTRY'){
    res.status(409).json({error:'Concurrent preparation conflict; reload before retrying'});return;
  }
  console.error('Release preparation failed',e instanceof Error?e.name:'Unknown');
  res.status(503).json({error:'Release preparation service unavailable'});
}

router.get('/:id',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [owned]=await db.execute<RowDataPacket[]>(
      'SELECT id FROM sales_quote_drafts WHERE id=? AND created_by=? LIMIT 1',
      [req.params.id,res.locals.auth.userId]);
    if(!owned.length){res.status(404).json({error:'Draft not found'});return;}
    const [latest]=await db.execute<RowDataPacket[]>(
      'SELECT COALESCE(MAX(revision_number),0) AS n FROM sales_quote_draft_revisions WHERE quote_id=?',[req.params.id]);
    const currentRevision=Number(latest[0].n);
    const [rows]=await db.execute<RowDataPacket[]>(
      'SELECT p.id,p.revision_number,p.status,p.snapshot_sha256,p.created_at,o.dispatch_state FROM sales_quote_release_preparations p JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id WHERE p.quote_id=? ORDER BY p.revision_number DESC',[req.params.id]);
    res.json({draftId:req.params.id,currentRevision,preparations:rows.map(row=>({...row,
      stale:Number(row.revision_number)!==currentRevision}))});
  }catch(e){fail(res,e);}
});

router.post('/:id',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const input=req.body;
  if(!input||typeof input!=='object'||Array.isArray(input)||
    Object.keys(input).sort().join(',')!=='expectedRevision'||
    !Number.isSafeInteger(input.expectedRevision)||input.expectedRevision<0||input.expectedRevision>100000){
    res.status(400).json({error:'Exact expectedRevision required; no client-supplied recipient or amount accepted'});return;
  }
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  const conn=await db.getConnection();
  try{
    await conn.beginTransaction();
    // Parent lock serializes checks against approval and newly added revisions.
    const [drafts]=await conn.query<RowDataPacket[]>(
      'SELECT id,customer_id,lead_id,subtotal,tax_estimate,total_estimate FROM sales_quote_drafts WHERE id=? AND created_by=? FOR UPDATE',
      [req.params.id,res.locals.auth.userId]);
    if(!drafts.length){await conn.rollback();res.status(404).json({error:'Draft not found'});return;}
    const [revisions]=await conn.query<RowDataPacket[]>(
      'SELECT revision_number,subtotal,tax_estimate,total_estimate,line_snapshot FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number DESC LIMIT 1',
      [req.params.id]);
    const revision=revisions.length?Number(revisions[0].revision_number):0;
    if(revision!==input.expectedRevision){
      await conn.rollback();res.status(409).json({error:'Draft revision changed; reload before preparation'});return;
    }
    const [reviews]=await conn.query<RowDataPacket[]>(
      'SELECT id,decision FROM sales_quote_review_decisions WHERE quote_id=? AND revision_number=? LIMIT 1',
      [req.params.id,revision]);
    if(!reviews.length || reviews[0].decision!=='APPROVED_INTERNAL'){
      await conn.rollback();res.status(409).json({error:'Latest revision lacks an internal approved review'});return;
    }
    const [existing]=await conn.query<RowDataPacket[]>(
      'SELECT id,status,snapshot_sha256 FROM sales_quote_release_preparations WHERE quote_id=? AND revision_number=? LIMIT 1',
      [req.params.id,revision]);
    if(existing.length){
      await conn.commit();
      res.status(200).json({id:existing[0].id,revision,status:'HELD',
        snapshotSha256:existing[0].snapshot_sha256,replayed:true,dispatchState:'DISABLED',
        message:'Previously held preparation returned; no external delivery triggered.'});
      return;
    }
    let items:unknown,subtotal:string,tax:string,total:string;
    if(revision===0){
      const [rows]=await conn.query<RowDataPacket[]>(
        'SELECT product_id,sku_snapshot,name_snapshot,hsn_snapshot,quantity,unit_cost,unit_price,gst_rate,line_subtotal,line_tax_estimate FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',
        [req.params.id]);
      if(!rows.length)throw Error('Draft has no original items');
      items=rows;subtotal=String(drafts[0].subtotal);tax=String(drafts[0].tax_estimate);
      total=String(drafts[0].total_estimate);
    }else{
      const current=revisions[0];
      items=typeof current.line_snapshot==='string'?JSON.parse(current.line_snapshot):current.line_snapshot;
      if(!Array.isArray(items)||items.length===0)throw Error('Revision snapshot missing');
      subtotal=String(current.subtotal);tax=String(current.tax_estimate);total=String(current.total_estimate);
    }
    // Only internal data: no email, phone or delivery destination in the snapshot.
    const snapshot={format:'aaditech-internal-release-hold-v1',
      quoteId:req.params.id,revision,customerId:String(drafts[0].customer_id),
      leadId:drafts[0].lead_id?String(drafts[0].lead_id):null,
      reviewId:String(reviews[0].id),currency:'INR',subtotal,taxEstimate:tax,
      totalEstimate:total,items};
    const payload=JSON.stringify(snapshot);
    const digest=createHash('sha256').update(payload).digest('hex');
    const id=randomUUID();
    await conn.execute(`INSERT INTO sales_quote_release_preparations
      (id,quote_id,revision_number,internal_review_id,prepared_by,snapshot_sha256,snapshot_json,status)
      VALUES (?,?,?,?,?,?,?,'HELD')`,
      [id,req.params.id,revision,reviews[0].id,res.locals.auth.userId,digest,payload]);
    await conn.execute(`INSERT INTO sales_quote_outbox_holds
      (id,release_preparation_id,event_type,dispatch_state,payload_sha256)
      VALUES (?,?,'QUOTE_RELEASE_PREPARATION_HELD','DISABLED',?)`,
      [randomUUID(),id,digest]);
    await conn.commit();
    res.status(201).json({id,revision,status:'HELD',snapshotSha256:digest,
      replayed:false,dispatchState:'DISABLED',
      message:'Internal release preparation held. No customer message or external dispatch.'});
  }catch(e){await conn.rollback();fail(res,e);}finally{conn.release();}
});
export default router;
