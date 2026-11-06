import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import type { RowDataPacket } from 'mysql2/promise';
import { getPool } from '../db';
import { requireOwner } from '../auth/router';
import { calculateLine, paise, rupees, QuoteInputError } from './money';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function failed(res:import('express').Response,e:unknown) {
  if(e instanceof QuoteInputError){res.status(400).json({error:e.message});return;}
  console.error('Quote draft operation failed',e instanceof Error?e.name:'Unknown');
  res.status(503).json({error:'Draft quotation service unavailable'});
}
router.get('/',async(req,res)=>{
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  try{
    const [rows]=await db.query<RowDataPacket[]>(`SELECT q.id,q.customer_id,q.lead_id,q.subtotal,q.tax_estimate,q.total_estimate,q.created_at,
      c.name AS customer_name FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id
      WHERE q.created_by=? ORDER BY q.created_at DESC,q.id DESC LIMIT 100`,[res.locals.auth.userId]);
    res.json({items:rows});
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
    res.json({draft:rows[0],items});
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
  const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
  const connection=await db.getConnection();
  try {
    await connection.beginTransaction();
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
    await connection.commit();
    res.status(201).json({id,status:'DRAFT',customerId:body.customerId,subtotal:rupees(sum),taxEstimate:rupees(tax),totalEstimate:rupees(sum+tax),lineCount:snapshot.length,
      message:'Internal draft saved only. Not approved, sent, reserved or invoiced.'});
  }catch(e){await connection.rollback();failed(res,e);}
  finally{connection.release();}
});
export default router;
