import {Router} from 'express';
import {randomUUID} from 'node:crypto';
import type {RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner} from '../auth/router';
import {lockActiveCrmOwner,CRMOwnerInactiveError,validId} from '../crm/repository';
import {
 ServiceTicketInputError,validateTicketCreate,validateTicketTransition,isInternalTicketStatus
} from './validation';

const router=Router();
router.use((_req,res,next)=>{
 res.setHeader('Cache-Control','no-store');
 res.setHeader('X-Content-Type-Options','nosniff');
 next();
});
router.use(requireOwner);
function fail(res:import('express').Response,error:unknown){
 if(error instanceof CRMOwnerInactiveError){res.status(403).json({error:'Active OWNER account required'});return;}
 if(error instanceof ServiceTicketInputError){res.status(400).json({error:error.message});return;}
 console.error('Internal service ticket unavailable:',error instanceof Error?error.name:'Unknown');
 res.status(503).json({error:'Internal service desk unavailable'});
}
const listProjection=`t.id,t.customer_id AS customerId,c.name AS customerName,
 t.guide_id AS guideId,t.subject,t.description,t.priority,t.status,t.version,
 t.customer_consent_state AS customerConsentState,
 t.external_dispatch_state AS externalDispatchState,
 t.created_at AS createdAt,t.updated_at AS updatedAt`;
const ownerScope=`JOIN crm_customers c ON c.id=t.customer_id AND c.deleted_at IS NULL
 AND EXISTS (SELECT 1 FROM crm_audit_events creator
  WHERE creator.entity_type='customers' AND creator.entity_id=c.id
   AND creator.operation='CREATE' AND creator.actor_user_id=t.owner_user_id)`;

router.get('/',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Internal service desk unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(
   `SELECT ${listProjection} FROM service_tickets_internal t ${ownerScope}
    WHERE t.owner_user_id=? ORDER BY t.created_at DESC,t.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,limit:100,mode:'INTERNAL_HELD',externalDispatchEnabled:false});
 }catch(e){fail(res,e);}
});

router.get('/:id',async(req,res)=>{
 if(!validId(req.params.id)){res.status(400).json({error:'Invalid ticket ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Internal service desk unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(
   `SELECT ${listProjection} FROM service_tickets_internal t ${ownerScope}
    WHERE t.id=? AND t.owner_user_id=? LIMIT 1`,[req.params.id,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'Internal ticket not found'});return;}
  const [history]=await db.query<RowDataPacket[]>(`SELECT operation,from_status AS fromStatus,
    to_status AS toStatus,note,version_after AS versionAfter,created_at AS createdAt
    FROM service_ticket_audit_internal WHERE ticket_id=?
    ORDER BY version_after ASC`,[req.params.id]);
  res.json({ticket:rows[0],history,mode:'INTERNAL_HELD',externalDispatchEnabled:false});
 }catch(e){fail(res,e);}
});

router.post('/',async(req,res)=>{
 let input:ReturnType<typeof validateTicketCreate>;
 try{input=validateTicketCreate(req.body);}
 catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Internal service desk unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await lockActiveCrmOwner(conn,res.locals.auth.userId);
  const [customers]=await conn.query<RowDataPacket[]>(
   `SELECT c.id FROM crm_customers c WHERE c.id=? AND c.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM crm_audit_events creator
     WHERE creator.entity_type='customers' AND creator.entity_id=c.id
      AND creator.operation='CREATE' AND creator.actor_user_id=?) FOR UPDATE`,
   [input.customerId,res.locals.auth.userId]);
  if(customers.length!==1){
   await conn.rollback();res.status(404).json({error:'Active owned customer not found'});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO service_tickets_internal
   (id,owner_user_id,customer_id,guide_id,subject,description,priority)
   VALUES (?,?,?,?,?,?,?)`,
   [id,res.locals.auth.userId,input.customerId,input.guideId,input.subject,input.description,input.priority]);
  await conn.execute(`INSERT INTO service_ticket_audit_internal
   (id,ticket_id,actor_user_id,operation,from_status,to_status,note,version_after)
   VALUES (?,?,?,'CREATE',NULL,'OPEN_INTERNAL',?,1)`,
   [randomUUID(),id,res.locals.auth.userId,'Internal first-response record only; customer consent not verified']);
  await conn.commit();
  res.status(201).json({ticket:{id,customerId:input.customerId,guideId:input.guideId,
   subject:input.subject,description:input.description,priority:input.priority,
   status:'OPEN_INTERNAL',version:1,customerConsentState:'UNVERIFIED',
   externalDispatchState:'DISABLED'},mode:'INTERNAL_HELD',externalDispatchEnabled:false,
   message:'Internal service ticket saved only. No customer consent, SLA or repair verified; no message sent.'});
 }catch(e){await conn.rollback();fail(res,e);}finally{conn.release();}
});

router.patch('/:id/status',async(req,res)=>{
 if(!validId(req.params.id)){res.status(400).json({error:'Invalid ticket ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Internal service desk unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await lockActiveCrmOwner(conn,res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT t.id,t.status,t.version
   FROM service_tickets_internal t ${ownerScope}
   WHERE t.id=? AND t.owner_user_id=? FOR UPDATE`,[req.params.id,res.locals.auth.userId]);
  if(rows.length!==1){await conn.rollback();res.status(404).json({error:'Internal ticket not found'});return;}
  const old=rows[0];
  if(!isInternalTicketStatus(old.status))throw new Error('Corrupt internal ticket status');
  const input=validateTicketTransition(req.body,old.status);
  if(input.expectedVersion!==old.version){
   await conn.rollback();res.status(409).json({error:'Ticket changed; reload before updating'});return;
  }
  await conn.execute(`UPDATE service_tickets_internal SET status=?,version=version+1 WHERE id=?`,
   [input.nextStatus,req.params.id]);
  await conn.execute(`INSERT INTO service_ticket_audit_internal
   (id,ticket_id,actor_user_id,operation,from_status,to_status,note,version_after)
   VALUES (?,?,?,'STATUS_CHANGE',?,?,?,?)`,
   [randomUUID(),req.params.id,res.locals.auth.userId,old.status,input.nextStatus,input.note,old.version+1]);
  await conn.commit();
  res.json({ticketId:req.params.id,status:input.nextStatus,version:old.version+1,
   mode:'INTERNAL_HELD',externalDispatchEnabled:false,
   message:'Internal status recorded; customer contact, SLA and repair remain unverified.'});
 }catch(e){await conn.rollback();fail(res,e);}finally{conn.release();}
});

export default router;
