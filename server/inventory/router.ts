import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {ResultSetHeader,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {parsePagination,InputError} from '../crm/validation';
import {InventoryConflictError,InventoryInputError,inventoryId,
  openingRequestHash,validateOpeningCount,validateSite} from './validation';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});

function fail(res:Response,error:unknown){
 if(error instanceof InventoryInputError||error instanceof InputError){
  res.status(400).json({error:error.message});return;
 }
 if(error instanceof InventoryConflictError ||
    (error&&typeof error==='object'&&'code' in error&&error.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Inventory record already exists or conflicts with this request'});return;
 }
 console.error('Inventory operation unavailable',error instanceof Error?error.name:'Unknown');
 res.status(503).json({error:'Inventory service unavailable'});
}
router.get('/sites',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(
   'SELECT id,code,name,created_at FROM inventory_sites ORDER BY code LIMIT 100');
  res.json({items:rows,authority:'OWNER_ATTESTED_SITE_ONLY'});
 }catch(e){fail(res,e);}
});
router.post('/sites',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let site:ReturnType<typeof validateSite>;
 try{site=validateSite(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const id=randomUUID();
  await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
   [id,site.code,site.name,res.locals.auth.userId]);
  res.status(201).json({id,...site,authority:'OWNER_ENTERED_SITE_ONLY'});
 }catch(e){fail(res,e);}
});
router.get('/opening-counts',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const {limit,offset,page}=parsePagination(req.query);
  const [rows]=await db.query<RowDataPacket[]>(`SELECT c.id,c.product_id AS productId,
    p.sku,p.brand,p.model,c.site_id AS siteId,s.code AS siteCode,s.name AS siteName,
    c.quantity,c.evidence_ref AS evidenceRef,c.attested_by AS attestedBy,
    c.recorded_at AS recordedAt
    FROM inventory_opening_counts c
    JOIN inventory_sites s ON s.id=c.site_id
    JOIN crm_products p ON p.id=c.product_id
    ORDER BY c.recorded_at DESC,c.id DESC LIMIT ? OFFSET ?`,[limit,offset]);
  const [counts]=await db.query<RowDataPacket[]>('SELECT COUNT(*) AS total FROM inventory_opening_counts');
  res.json({items:rows,total:Number(counts[0].total),page,limit,
   status:'OPENING_COUNTS_ONLY',availableToSell:null,reservations:null,
   disclaimer:'Owner-attested historical opening counts, not verified current stock, inventory availability, receivables or procurement receipts.'});
 }catch(e){fail(res,e);}
});
router.post('/opening-counts',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateOpeningCount>;
 try{input=validateOpeningCount(req.body);}catch(e){fail(res,e);return;}
 const key=req.get('idempotency-key');
 if(!inventoryId(key)){res.status(400).json({error:'UUID Idempotency-Key required'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const actor=String(res.locals.auth.userId),hash=openingRequestHash(input);
 let conn:Awaited<ReturnType<typeof db.getConnection>>|undefined;
 try{
  conn=await db.getConnection();
  await conn.beginTransaction();
  const [claim]=await conn.execute<ResultSetHeader>(
   'INSERT IGNORE INTO inventory_opening_requests(actor_id,request_key,request_hash) VALUES (?,?,?)',
   [actor,key,hash]);
  const [requests]=await conn.query<RowDataPacket[]>(
   'SELECT request_hash,count_id FROM inventory_opening_requests WHERE actor_id=? AND request_key=? FOR UPDATE',
   [actor,key]);
  const existing=requests[0];
  if(!existing)throw Error('Inventory request reservation missing');
  if(existing.request_hash!==hash)
   throw new InventoryConflictError('Idempotency key used with different count');
  if(claim.affectedRows===0){
   if(!existing.count_id)throw Error('Incomplete inventory request reservation');
   const [prior]=await conn.query<RowDataPacket[]>(
    'SELECT id,product_id AS productId,site_id AS siteId,quantity,evidence_ref AS evidenceRef FROM inventory_opening_counts WHERE id=?',
    [existing.count_id]);
   if(!prior.length)throw Error('Prior opening count missing');
   await conn.commit();
   res.status(200).json({...prior[0],replayed:true,status:'OPENING_COUNT_ONLY',
    availableToSell:null,reservations:null});return;
  }
  const [products]=await conn.query<RowDataPacket[]>(
   'SELECT id FROM crm_products WHERE id=? AND deleted_at IS NULL FOR UPDATE',[input.productId]);
  const [sites]=await conn.query<RowDataPacket[]>(
   'SELECT id FROM inventory_sites WHERE id=? FOR UPDATE',[input.siteId]);
  if(!products.length||!sites.length)
   throw new InventoryInputError('Active product and registered site are required');
  const id=randomUUID();
  await conn.execute(
   'INSERT INTO inventory_opening_counts(id,product_id,site_id,quantity,evidence_ref,attested_by) VALUES (?,?,?,?,?,?)',
   [id,input.productId,input.siteId,input.quantity,input.evidenceRef,actor]);
  await conn.execute(
   'UPDATE inventory_opening_requests SET count_id=? WHERE actor_id=? AND request_key=?',
   [id,actor,key]);
  await conn.commit();
  res.status(201).json({id,...input,replayed:false,status:'OPENING_COUNT_ONLY',
   availableToSell:null,reservations:null,
   message:'Immutable owner-attested opening count saved. No stock was received, issued, sold, reserved or declared available.'});
 }catch(e){
  if(conn)await conn.rollback().catch(()=>{});
  fail(res,e);
 }finally{conn?.release();}
});
export default router;
