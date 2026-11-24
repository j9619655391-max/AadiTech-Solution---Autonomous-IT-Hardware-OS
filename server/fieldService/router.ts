import {Router,type Response} from 'express';
import {randomUUID} from 'node:crypto';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner} from '../auth/router';
import {CRMOwnerInactiveError,lockActiveCrmOwner,validId} from '../crm/repository';
import {ServiceTicketInputError,verifyInternalTicketAuditForAppend,maskCredentialLikeTicketText,MAX_INTERNAL_AUDIT_APPEND_EVENTS,type InternalTicketAuditEvent} from '../serviceDesk/validation';
import {validateHeldFieldPlan} from './validation';

const router=Router();
const hold={mode:'INTERNAL_HELD',externalDispatchEnabled:false,technicianAssignmentEnabled:false,replacementApprovalEnabled:false} as const;
router.use((_req,res,next)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');next();
});
router.use(requireOwner);
function fail(res:Response,e:unknown){
 if(e instanceof ServiceTicketInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof CRMOwnerInactiveError){res.status(403).json({error:'Active OWNER account required'});return;}
 if((e as {code?:string})?.code==='ER_DUP_ENTRY'){res.status(409).json({error:'Internal plan already exists',...hold});return;}
 console.error('Internal field plan unavailable:',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Internal field service unavailable'});
}
const scope="JOIN crm_customers c ON c.id=t.customer_id AND c.deleted_at IS NULL "+
 "AND EXISTS (SELECT 1 FROM crm_audit_events creator WHERE creator.entity_type='customers' "+
 "AND creator.entity_id=c.id AND creator.operation='CREATE' AND creator.actor_user_id=t.owner_user_id AND (SELECT COUNT(*) FROM crm_audit_events origin WHERE origin.entity_type=creator.entity_type AND origin.entity_id=creator.entity_id AND origin.operation='CREATE')=1)";
interface AuditRow extends RowDataPacket,InternalTicketAuditEvent{actorUserId:string}

router.get('/',async(req,res)=>{
 if(Object.keys(req.query).length!==1||!validId(req.query.ticketId)){
  res.status(400).json({error:'Exact ticketId query required'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'Internal field service unavailable'});return;}
 try{
  // A single statement scopes the source and returns at most two plans.
  const [rows]=await db.query<RowDataPacket[]>(
   "SELECT t.id AS ticketId,t.version AS currentTicketVersion,p.id,p.kind,p.note,p.status,p.source_ticket_version AS sourceTicketVersion,"+
   "p.customer_consent_state AS customerConsentState,p.external_dispatch_state AS externalDispatchState,p.owner_user_id AS planOwner,"+
   "a.actor_user_id AS auditActor,a.operation,sa.to_status AS sourceStatus,sa.actor_user_id AS sourceActor,p.created_at AS createdAt "+
   "FROM service_tickets_internal t "+scope+
   " LEFT JOIN field_service_plans_internal p ON p.ticket_id=t.id "+
   "LEFT JOIN field_service_plan_audit_internal a ON a.plan_id=p.id "+
   "LEFT JOIN service_ticket_audit_internal sa ON sa.ticket_id=t.id AND sa.version_after=p.source_ticket_version "+
   "WHERE t.id=? AND t.owner_user_id=? ORDER BY p.kind LIMIT 3",
   [req.query.ticketId,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'Internal ticket not found'});return;}
  if(rows.length>2)throw Error('Field plan bound exceeded');
  const items=rows.filter(row=>row.id!==null).map(row=>{
   if(row.planOwner!==res.locals.auth.userId||row.auditActor!==res.locals.auth.userId||
      row.operation!=='CREATE_HELD'||row.sourceActor!==res.locals.auth.userId||
      row.sourceStatus!=='TRIAGED_INTERNAL'||!Number.isSafeInteger(row.sourceTicketVersion)||
      row.sourceTicketVersion<2||row.sourceTicketVersion>=1000||row.sourceTicketVersion>row.currentTicketVersion||
      row.status!=='PLANNING_HELD'||row.customerConsentState!=='UNVERIFIED'||
      row.externalDispatchState!=='DISABLED'||(row.kind!=='WORK_ORDER'&&row.kind!=='RMA'))
    throw Error('Internal field plan provenance inconsistent');
   const note=maskCredentialLikeTicketText(row.note);
   return {id:row.id,ticketId:row.ticketId,kind:row.kind,note:note.text,noteRedacted:note.redacted,
    status:row.status,sourceTicketVersion:row.sourceTicketVersion,customerConsentState:row.customerConsentState,
    externalDispatchState:row.externalDispatchState,createdAt:row.createdAt};
  });
  res.json({ticketId:req.query.ticketId,items,...hold});
 }catch(e){fail(res,e);}
});

router.post('/',async(req,res)=>{
 let input:ReturnType<typeof validateHeldFieldPlan>;
 try{input=validateHeldFieldPlan(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();const conn:PoolConnection|null=db?await db.getConnection().catch(()=>null):null;
 if(!conn){res.status(503).json({error:'Internal field service unavailable'});return;}
 let discard=false;
 try{
  await conn.beginTransaction();
  await lockActiveCrmOwner(conn,res.locals.auth.userId);
  const [source]=await conn.query<RowDataPacket[]>(
   "SELECT t.version,t.status,t.customer_consent_state AS consent,t.external_dispatch_state AS dispatch "+
   "FROM service_tickets_internal t "+scope+" WHERE t.id=? AND t.owner_user_id=? FOR UPDATE",
   [input.ticketId,res.locals.auth.userId]);
  if(source.length!==1){await conn.rollback();res.status(404).json({error:'Internal ticket not found'});return;}
  const t=source[0];
  if(t.version!==input.expectedTicketVersion||t.status!=='TRIAGED_INTERNAL'){
   await conn.rollback();res.status(409).json({error:'Current triaged ticket version required',...hold});return;
  }
  if(t.consent!=='UNVERIFIED'||t.dispatch!=='DISABLED')throw Error('Source ticket HOLD inconsistent');
  const [audit]=await conn.query<AuditRow[]>(
   "SELECT version_after AS versionAfter,operation,from_status AS fromStatus,to_status AS toStatus,actor_user_id AS actorUserId "+
   "FROM service_ticket_audit_internal WHERE ticket_id=? ORDER BY version_after DESC LIMIT "+MAX_INTERNAL_AUDIT_APPEND_EVENTS+" FOR SHARE",
   [input.ticketId]);
  verifyInternalTicketAuditForAppend(audit,{currentVersion:t.version,currentStatus:'TRIAGED_INTERNAL',ownerUserId:res.locals.auth.userId});
  const id=randomUUID();
  await conn.execute("INSERT INTO field_service_plans_internal(id,ticket_id,owner_user_id,source_ticket_version,kind,note) VALUES (?,?,?,?,?,?)",
   [id,input.ticketId,res.locals.auth.userId,input.expectedTicketVersion,input.kind,input.note]);
  await conn.execute("INSERT INTO field_service_plan_audit_internal(plan_id,actor_user_id,operation) VALUES (?,?,'CREATE_HELD')",
   [id,res.locals.auth.userId]);
  await conn.commit();
  res.status(201).json({plan:{id,ticketId:input.ticketId,sourceTicketVersion:input.expectedTicketVersion,kind:input.kind,note:input.note,
   status:'PLANNING_HELD',customerConsentState:'UNVERIFIED',externalDispatchState:'DISABLED'},...hold});
 }catch(e){try{await conn.rollback();}catch{discard=true;conn.destroy();}fail(res,e);}
 finally{if(!discard)conn.release();}
});
export default router;
