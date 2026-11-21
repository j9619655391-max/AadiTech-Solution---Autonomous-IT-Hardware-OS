import { Router } from 'express';
import { randomUUID, createHash } from 'node:crypto';
import type { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import { getPool } from '../db';
import { requireOwner } from '../auth/router';
import { calculateLine, paise, rupees, QuoteInputError } from './money';
import { evaluateRevision, type RevisionProduct } from './revisions';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const draftNumber=(id:string)=>'ADQ-'+id;
class QuoteConflictError extends Error {}

function failed(res:import('express').Response,e:unknown) {
  if(e instanceof QuoteInputError){res.status(400).json({error:e.message});return;}
  if(e instanceof QuoteConflictError){res.status(409).json({error:e.message});return;}
  console.error('Quote draft operation failed',e instanceof Error?e.name:'Unknown');
  res.status(503).json({error:'Draft quotation service unavailable'});
}
router.get('/',async(req,res)=>{
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [rows]=await db.query<RowDataPacket[]>(`SELECT q.id,q.customer_id,q.lead_id,q.subtotal,q.tax_estimate,q.total_estimate,q.created_at,
      c.name AS customer_name FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id
      WHERE q.created_by=? ORDER BY q.created_at DESC,q.id DESC LIMIT 100`,[res.locals.auth.userId]);
    res.json({items:rows.map(row=>({...row,draftNumber:draftNumber(String(row.id))}))});
  }catch(e){failed(res,e);}
});
router.get('/:id',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [rows]=await db.query<RowDataPacket[]>(`SELECT * FROM sales_quote_drafts WHERE id=? AND created_by=? LIMIT 1`,
      [req.params.id,res.locals.auth.userId]);
    if(!rows.length){res.status(404).json({error:'Draft not found'});return;}
    const [items]=await db.query<RowDataPacket[]>(`SELECT position,product_id,sku_snapshot,name_snapshot,hsn_snapshot,quantity,unit_price,gst_rate,line_subtotal,line_tax_estimate FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position`,[req.params.id]);
    res.json({draft:{...rows[0],draftNumber:draftNumber(String(rows[0].id))},items});
  }catch(e){failed(res,e);}
});
router.post('/',async(req,res)=>{
  const body=req.body;
  if(!body || typeof body!=='object' || Array.isArray(body) ||
     Object.keys(body).some(k=>!['customerId','leadId','items'].includes(k)) ||
     !uuid.test(body.customerId) ||
     (body.leadId!=null && !uuid.test(body.leadId)) ||
     !Array.isArray(body.items) || body.items.length===0 || body.items.length>40 ||
     body.items.some((item:unknown)=>!item || typeof item!=='object' || Array.isArray(item) ||
       Object.keys(item as object).sort().join(',')!=='productId,quantity' ||
       !uuid.test((item as any).productId) ||
       !Number.isSafeInteger((item as any).quantity) || (item as any).quantity < 1 || (item as any).quantity>1000)){
    res.status(400).json({error:'Use a valid customer, optional lead and 1–40 product/quantity lines'});return;
  }
  const idempotencyKey=req.header('idempotency-key');
  if(!idempotencyKey || !uuid.test(idempotencyKey)){
    res.status(400).json({error:'A UUID Idempotency-Key header is required'});return;
  }
  const requestHash=createHash('sha256').update(JSON.stringify({
    customerId:body.customerId,leadId:body.leadId??null,items:body.items
  })).digest('hex');
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  const connection=await db.getConnection();
  try {
    await connection.beginTransaction();
    // Unique (actor,key) insert serializes concurrent retries; rollback
    // clears reservations when the corresponding draft is not committed.
    const [claim]=await connection.execute<ResultSetHeader>(
      'INSERT IGNORE INTO sales_quote_create_requests (actor_id,request_key,request_hash) VALUES (?,?,?)',
      [res.locals.auth.userId,idempotencyKey,requestHash]);
    const [claims]=await connection.query<RowDataPacket[]>(
      'SELECT request_hash,quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=? FOR UPDATE',
      [res.locals.auth.userId,idempotencyKey]);
    if(!claims.length)throw new Error('Missing idempotency reservation');
    if(claims[0].request_hash!==requestHash)
      throw new QuoteConflictError('Idempotency key already used for a different draft');
    if(claim.affectedRows===0){
      if(!claims[0].quote_id)throw new Error('Existing request without committed draft');
      const existingId=String(claims[0].quote_id);
      const [prior]=await connection.query<RowDataPacket[]>(
        'SELECT id,customer_id,subtotal,tax_estimate,total_estimate FROM sales_quote_drafts WHERE id=? AND created_by=?',
        [existingId,res.locals.auth.userId]);
      const [items]=await connection.query<RowDataPacket[]>(
        'SELECT COUNT(*) AS n FROM sales_quote_draft_items WHERE quote_id=?',[existingId]);
      if(!prior.length)throw new Error('Idempotency reference missing draft');
      await connection.commit();
      res.status(200).json({
        id:existingId,draftNumber:draftNumber(existingId),replayed:true,status:'DRAFT',
        customerId:prior[0].customer_id,subtotal:prior[0].subtotal,
        taxEstimate:prior[0].tax_estimate,totalEstimate:prior[0].total_estimate,
        lineCount:Number(items[0].n),
        message:'Previously saved internal draft returned. No new draft created.'
      });
      return;
    }
    const [customer]=await connection.query<RowDataPacket[]>('SELECT id,name FROM crm_customers WHERE id=? AND deleted_at IS NULL FOR UPDATE',[body.customerId]);
    if(!customer.length)throw new QuoteInputError('Active customer not found');
    if(body.leadId){
      const [lead]=await connection.query<RowDataPacket[]>('SELECT id,company FROM crm_leads WHERE id=? AND deleted_at IS NULL FOR UPDATE',[body.leadId]);
      if(!lead.length)throw new QuoteInputError('Active lead not found');
    }
    let sum=0n,tax=0n;
    const snapshot=[];
    const used=new Set<string>();
    for(const item of body.items as {productId:string;quantity:number}[]) {
      if(used.has(item.productId))throw new QuoteInputError('Duplicate product lines; combine quantities');
      used.add(item.productId);
      const [products]=await connection.query<RowDataPacket[]>('SELECT id,sku,brand,model,hsn,unitCost,sellingPrice,minPrice,gstRate FROM crm_products WHERE id=? AND deleted_at IS NULL FOR UPDATE',[item.productId]);
      if(!products.length)throw new QuoteInputError('Active catalog product not found');
      const p=products[0];
      if(paise(String(p.sellingPrice))<paise(String(p.minPrice)))throw new QuoteInputError('Product selling price below minimum');
      const line=calculateLine(String(p.sellingPrice),item.quantity,String(p.gstRate));
      sum+=line.subtotal;tax+=line.tax;
      snapshot.push({id:p.id,sku:p.sku,name:p.brand+' '+p.model,hsn:p.hsn,quantity:item.quantity,cost:String(p.unitCost),price:String(p.sellingPrice),gstRate:String(p.gstRate),...line});
    }
    // Addition overflow protection for aggregate.
    if(sum+tax>9999999999999999n)throw new QuoteInputError('Aggregate total too large');
    const id=randomUUID();
    await connection.execute(`INSERT INTO sales_quote_drafts (id,customer_id,lead_id,created_by,subtotal,tax_estimate,total_estimate)
      VALUES (?,?,?,?,?,?,?)`,[id,body.customerId,body.leadId??null,res.locals.auth.userId,rupees(sum),rupees(tax),rupees(sum+tax)]);
    for(let i=0;i<snapshot.length;i++){
      const p=snapshot[i];
      await connection.execute(`INSERT INTO sales_quote_draft_items
        (id,quote_id,position,product_id,sku_snapshot,name_snapshot,hsn_snapshot,quantity,unit_cost,unit_price,gst_rate,line_subtotal,line_tax_estimate)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,[randomUUID(),id,i+1,p.id,p.sku,p.name,p.hsn,p.quantity,p.cost,p.price,p.gstRate,rupees(p.subtotal),rupees(p.tax)]);
    }
    await connection.execute(
      'UPDATE sales_quote_create_requests SET quote_id=? WHERE actor_id=? AND request_key=?',
      [id,res.locals.auth.userId,idempotencyKey]);
    await connection.commit();
    res.status(201).json({id,draftNumber:draftNumber(id),replayed:false,status:'DRAFT',customerId:body.customerId,subtotal:rupees(sum),taxEstimate:rupees(tax),totalEstimate:rupees(sum+tax),lineCount:snapshot.length,
      message:'Internal draft saved only. Not approved, sent, reserved or invoiced.'});
  }catch(e){await connection.rollback();failed(res,e);}
  finally{connection.release();}
});

router.get('/:id/revisions',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try {
    const [owned]=await db.execute<RowDataPacket[]>(
      'SELECT id FROM sales_quote_drafts WHERE id=? AND created_by=? LIMIT 1',
      [req.params.id,res.locals.auth.userId]);
    if(!owned.length){res.status(404).json({error:'Draft not found'});return;}
    const [rows]=await db.execute<RowDataPacket[]>(
      'SELECT revision_number,actor_id,reason,subtotal,tax_estimate,total_estimate,gross_margin_bps,review_status,line_snapshot,created_at FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number ASC',
      [req.params.id]);
    res.json({draftId:req.params.id,revisions:rows.map(row=>({...row,
      line_snapshot:typeof row.line_snapshot==='string'?JSON.parse(row.line_snapshot):row.line_snapshot}))});
  }catch(e){failed(res,e);}
});

router.post('/:id/revisions',async(req,res)=>{
  if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
  const body=req.body;
  if(!body || typeof body!=='object' || Array.isArray(body) ||
    Object.keys(body).some(k=>!['expectedRevision','reason','items'].includes(k)) ||
    !Number.isSafeInteger(body.expectedRevision) || body.expectedRevision<0 || body.expectedRevision>100000 ||
    typeof body.reason!=='string' || !body.reason.trim() || body.reason.trim().length>500 ||
    !Array.isArray(body.items) || body.items.length<1 || body.items.length>40 ||
    body.items.some((item:unknown)=>!item || typeof item!=='object' || Array.isArray(item) ||
      Object.keys(item as object).sort().join(',')!=='productId,quantity' ||
      !uuid.test((item as any).productId) ||
      !Number.isSafeInteger((item as any).quantity) || (item as any).quantity<1 || (item as any).quantity>1000)){
    res.status(400).json({error:'Expected version, reason and valid product quantities required'});return;
  }
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  const conn=await db.getConnection();
  try{
    await conn.beginTransaction();
    // This parent row serializes revision creation for this draft.
    const [owned]=await conn.query<RowDataPacket[]>(
      'SELECT id FROM sales_quote_drafts WHERE id=? AND created_by=? FOR UPDATE',
      [req.params.id,res.locals.auth.userId]);
    if(!owned.length){await conn.rollback();res.status(404).json({error:'Draft not found'});return;}
    const [current]=await conn.query<RowDataPacket[]>(
      'SELECT COALESCE(MAX(revision_number),0) AS revision FROM sales_quote_draft_revisions WHERE quote_id=?',
      [req.params.id]);
    const version=Number(current[0].revision);
    if(version!==body.expectedRevision){
      await conn.rollback();res.status(409).json({error:'Draft revision changed. Refresh history first.'});return;
    }
    const [original]=await conn.query<RowDataPacket[]>(
      'SELECT product_id,sku_snapshot,name_snapshot,hsn_snapshot,unit_cost,unit_price,gst_rate FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',
      [req.params.id]);
    const originalById=new Map(original.map(v=>[String(v.product_id),v]));
    const provided=new Set<string>();
    const snapshot:RevisionProduct[]=[];
    for(const item of body.items as {productId:string;quantity:number}[]){
      if(provided.has(item.productId))throw new QuoteInputError('Duplicate product in revision');
      provided.add(item.productId);
      const saved=originalById.get(item.productId);
      if(!saved)throw new QuoteInputError('Revision product must belong to the saved original draft');
      snapshot.push({productId:item.productId,sku:String(saved.sku_snapshot),
        name:String(saved.name_snapshot),hsn:String(saved.hsn_snapshot),
        quantity:item.quantity,unitCost:String(saved.unit_cost),
        unitPrice:String(saved.unit_price),gstRate:String(saved.gst_rate)});
    }
    if(provided.size!==originalById.size)throw new QuoteInputError('Revision must contain every original product');
    const rawPolicy=process.env.QUOTE_MIN_MARGIN_BPS??'1500';
    if(!/^\d{1,5}$/.test(rawPolicy))throw new Error('Invalid QUOTE_MIN_MARGIN_BPS configuration');
    const result=evaluateRevision(snapshot,Number(rawPolicy));
    await conn.execute(`INSERT INTO sales_quote_draft_revisions
      (id,quote_id,revision_number,actor_id,reason,subtotal,tax_estimate,total_estimate,gross_margin_bps,review_status,line_snapshot)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [randomUUID(),req.params.id,version+1,res.locals.auth.userId,body.reason.trim(),
        result.subtotal,result.taxEstimate,result.totalEstimate,result.grossMarginBps,result.reviewStatus,JSON.stringify(result.lines)]);
    await conn.commit();
    res.status(201).json({draftId:req.params.id,revision:version+1,...result,
      message:'Internal draft revision saved. Not approved, sent, ordered or invoiced.'});
  }catch(e){await conn.rollback();failed(res,e);}finally{conn.release();}
});

export default router;
