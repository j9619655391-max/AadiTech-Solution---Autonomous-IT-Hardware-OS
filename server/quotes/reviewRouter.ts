import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import type { RowDataPacket } from 'mysql2/promise';
import { getPool } from '../db';
import { requireReviewer } from '../auth/router';
import { paise, rupees, QuoteInputError } from './money';
import { evaluateRevision, type RevisionProduct } from './revisions';
import { grossMarginBps, requiredMinimumMarginBps, reviewDecision } from './reviewPolicy';

const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function failure(res:import('express').Response,e:unknown){
  if(e instanceof QuoteInputError){res.status(400).json({error:e.message});return;}
  if(e && typeof e==='object' && 'code' in e && e.code==='ER_DUP_ENTRY'){
    res.status(409).json({error:'Decision already exists for this revision'});return;
  }
  console.error('Review request failure:',e instanceof Error?e.name:'Unknown');
  res.status(503).json({error:'Review service unavailable'});
}
router.get('/queue',async(req,res)=>{
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [rows]=await db.execute<RowDataPacket[]>(`SELECT q.id,q.created_by,q.created_at,
      COALESCE(r.revision_number,0) AS current_revision,
      CASE WHEN d.id IS NULL THEN 'AWAITING_REVIEW' ELSE d.decision END AS review_state
      FROM sales_quote_drafts q
      LEFT JOIN sales_quote_draft_revisions r ON r.quote_id=q.id
        AND r.revision_number=(SELECT MAX(rr.revision_number) FROM sales_quote_draft_revisions rr WHERE rr.quote_id=q.id)
      LEFT JOIN sales_quote_review_decisions d ON d.quote_id=q.id
        AND d.revision_number=COALESCE(r.revision_number,0)
      WHERE q.created_by<>? ORDER BY q.created_at DESC,q.id DESC LIMIT 100`,
      [res.locals.auth.userId]);
    res.json({items:rows});
  }catch(e){failure(res,e);}
});
router.get('/:id/brief',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [drafts]=await db.execute<RowDataPacket[]>(
      'SELECT id,created_by,subtotal,tax_estimate,total_estimate FROM sales_quote_drafts WHERE id=? AND created_by<>? LIMIT 1',
      [req.params.id,res.locals.auth.userId]);
    if(!drafts.length){res.status(404).json({error:'Draft not available for independent review'});return;}
    const [revisions]=await db.execute<RowDataPacket[]>(
      'SELECT revision_number,subtotal,tax_estimate,total_estimate,gross_margin_bps,review_status,line_snapshot FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number DESC LIMIT 1',
      [req.params.id]);
    const [items]=await db.execute<RowDataPacket[]>(
      'SELECT sku_snapshot,name_snapshot,quantity,unit_price,gst_rate,line_subtotal,line_tax_estimate FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',
      [req.params.id]);
    const latest=revisions[0]??null;
    res.json({draftId:req.params.id,drafterId:drafts[0].created_by,
      revision:latest?Number(latest.revision_number):0,
      subtotal:latest?.subtotal??drafts[0].subtotal,
      taxEstimate:latest?.tax_estimate??drafts[0].tax_estimate,
      totalEstimate:latest?.total_estimate??drafts[0].total_estimate,
      items:latest?(typeof latest.line_snapshot==='string'?JSON.parse(latest.line_snapshot):latest.line_snapshot):items,
      note:'Internal reviewer context only. No recipient details or customer contact data supplied.'});
  }catch(e){failure(res,e);}
});
router.get('/:id',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [owned]=await db.execute<RowDataPacket[]>(
      'SELECT id FROM sales_quote_drafts WHERE id=? AND created_by<>? LIMIT 1',[req.params.id,res.locals.auth.userId]);
    if(!owned.length){res.status(404).json({error:'Draft not found'});return;}
    const [rev]=await db.execute<RowDataPacket[]>(
      'SELECT COALESCE(MAX(revision_number),0) AS n FROM sales_quote_draft_revisions WHERE quote_id=?',[req.params.id]);
    const currentRevision=Number(rev[0].n);
    const [decisions]=await db.execute<RowDataPacket[]>(
      'SELECT revision_number,owner_user_id,decision,reason,override_requested,gross_margin_bps,minimum_margin_bps,subtotal,created_at FROM sales_quote_review_decisions WHERE quote_id=? ORDER BY revision_number ASC',
      [req.params.id]);
    const current=decisions.find(v=>Number(v.revision_number)===currentRevision)??null;
    res.json({draftId:req.params.id,currentRevision,effectiveDecision:current,history:decisions});
  }catch(e){failure(res,e);}
});
router.post('/:id',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const input=req.body;
  if(!input||typeof input!=='object'||Array.isArray(input)||
    Object.keys(input).some(k=>!['expectedRevision','decision','reason','overrideRequested'].includes(k))||
    !Number.isSafeInteger(input.expectedRevision)||input.expectedRevision<0||input.expectedRevision>100000||
    !['APPROVED_INTERNAL','REJECTED_INTERNAL'].includes(input.decision)||
    typeof input.reason!=='string'||input.reason.trim().length<5||input.reason.trim().length>1000||
    typeof input.overrideRequested!=='boolean'){
    res.status(400).json({error:'Expected revision, decision, reason and explicit override flag required'});return;
  }
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  const conn=await db.getConnection();
  try{
    await conn.beginTransaction();
    const [drafts]=await conn.query<RowDataPacket[]>(
      'SELECT id,subtotal FROM sales_quote_drafts WHERE id=? AND created_by<>? FOR UPDATE',
      [req.params.id,res.locals.auth.userId]);
    if(!drafts.length){await conn.rollback();res.status(404).json({error:'Draft not found'});return;}
    const [rev]=await conn.query<RowDataPacket[]>(
      'SELECT revision_number,subtotal,gross_margin_bps,line_snapshot FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number DESC LIMIT 1',
      [req.params.id]);
    const version=rev.length?Number(rev[0].revision_number):0;
    if(version!==input.expectedRevision){
      await conn.rollback();res.status(409).json({error:'Draft has newer revision. Reload before reviewing.'});return;
    }
    const [existing]=await conn.query<RowDataPacket[]>(
      'SELECT id FROM sales_quote_review_decisions WHERE quote_id=? AND revision_number=? LIMIT 1',
      [req.params.id,version]);
    if(existing.length){await conn.rollback();res.status(409).json({error:'This revision was already reviewed'});return;}
    let subtotal:string,margin:number;
    if(version===0){
      const [original]=await conn.query<RowDataPacket[]>(
        'SELECT quantity,unit_cost,unit_price FROM sales_quote_draft_items WHERE quote_id=?',[req.params.id]);
      if(!original.length)throw new QuoteInputError('Draft is missing items');
      let cost=0n;
      for(const item of original)cost+=paise(String(item.unit_cost))*BigInt(item.quantity);
      subtotal=String(drafts[0].subtotal);
      margin=grossMarginBps(subtotal,rupees(cost));
    }else{
      subtotal=String(rev[0].subtotal);
      margin=Number(rev[0].gross_margin_bps);
      if(!Number.isSafeInteger(margin))throw Error('Corrupted revision margin');
    }
    const min=requiredMinimumMarginBps(process.env.QUOTE_MIN_MARGIN_BPS);
    const reviewed=reviewDecision({decision:input.decision,
      reason:input.reason,overrideRequested:input.overrideRequested,marginBps:margin,minimumBps:min});
    await conn.execute(`INSERT INTO sales_quote_review_decisions
      (id,quote_id,revision_number,owner_user_id,decision,reason,override_requested,gross_margin_bps,minimum_margin_bps,subtotal)
      VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [randomUUID(),req.params.id,version,res.locals.auth.userId,input.decision,input.reason.trim(),
        input.overrideRequested,margin,min,subtotal]);
    await conn.commit();
    res.status(201).json({draftId:req.params.id,revision:version,...reviewed,
      grossMarginBps:margin,minimumMarginBps:min,
      message:'Internal owner review recorded. No customer quote, invoice, stock movement or external message generated.'});
  }catch(e){await conn.rollback();failure(res,e);}finally{conn.release();}
});
export default router;
