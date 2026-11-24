import { randomUUID } from 'node:crypto';
import type { Pool, PoolConnection, RowDataPacket } from 'mysql2/promise';
import { definitions, isMinPriceAboveSellingPrice, type CRMEntity, type Input } from './validation';

export interface CRMRepository {
  list(entity: CRMEntity, limit: number, offset: number, actor: string): Promise<{ items: object[]; total: number }>;
  get(entity: CRMEntity, id: string, actor: string): Promise<object | null>;
  create(entity: CRMEntity, fields: Input, actor: string): Promise<object>;
  update(entity: CRMEntity, id: string, version: number, fields: Input, actor: string): Promise<object | 'not_found' | 'conflict'>;
  remove(entity: CRMEntity, id: string, version: number, actor: string): Promise<'deleted' | 'not_found' | 'conflict'>;
}
const tables: Record<CRMEntity,string>={customers:'crm_customers',leads:'crm_leads',products:'crm_products'};
const idPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validId(id: unknown): id is string {return typeof id === 'string' && idPattern.test(id);}
function clean(entity:CRMEntity,row:RowDataPacket):object {
  const columns=['id',...Object.keys(definitions[entity]),'version','created_at','updated_at'];
  return Object.fromEntries(columns.filter(k=>row[k]!==undefined).map(k=>[k,row[k]]));
}
// Phase 1EK: historical CRM rows have no creator FK. The application’s
// transactionally written CREATE audit event is the only current actor-bound
// provenance available. Missing or foreign provenance must fail closed,
// never be silently assigned to a different OWNER or treated as legal tenancy.
const creatorScope=(alias:string)=>`EXISTS (SELECT 1 FROM crm_audit_events creator
 WHERE creator.entity_type=? AND creator.entity_id=${alias}.id
 AND creator.operation='CREATE' AND creator.actor_user_id=? AND (SELECT COUNT(*) FROM crm_audit_events origin WHERE origin.entity_type=creator.entity_type AND origin.entity_id=creator.entity_id AND origin.operation='CREATE')=1)`;
// A role/status check in the HTTP middleware is not enough: the account may
// be disabled or demoted before a later transaction takes its first write lock.
// The shared auth_users row lock serializes CRM mutation against such changes.
export class CRMOwnerInactiveError extends Error {
 constructor(){super('Active OWNER account required');this.name='CRMOwnerInactiveError';}
}
export type OwnerGuardMode='DIRECT_DEVELOPMENT'|'DEFINER_PROCEDURE'|'HOLD';
export function ownerGuardMode(env:NodeJS.ProcessEnv):OwnerGuardMode{
 const mode=env.NODE_ENV??'development';
 const setting=env.AUTH_OWNER_GUARD_MODE??'';
 if(!['development','test','staging','production'].includes(mode))return 'HOLD';
 // A privileged SQL user is never a valid reason to fall back to raw
 // auth_users SELECT from staging or production runtime connections.
 if(mode==='staging'||mode==='production')
  return setting==='procedure'?'DEFINER_PROCEDURE':'HOLD';
 if(setting==='procedure')return 'DEFINER_PROCEDURE';
 if(!setting||setting==='direct')return 'DIRECT_DEVELOPMENT';
 return 'HOLD';
}
export async function lockActiveCrmOwner(
 connection:Pick<PoolConnection,'query'>,actor:string
):Promise<void>{
 const mode=ownerGuardMode(process.env);
 if(mode==='HOLD')throw Error('Runtime OWNER authorization guard unconfigured');
 if(mode==='DEFINER_PROCEDURE'){
  try{
   // One atomic read/locking statement on the SAME application transaction.
   // No SELECT/UPDATE grant on auth_users required for the runtime principal.
   await connection.query('CALL aaditech_guard_active_owner(?)',[actor]);
  }catch(error){
   const e=error as {code?:unknown;sqlState?:unknown;sqlMessage?:unknown};
   if(e?.code==='ER_SIGNAL_EXCEPTION'&&e.sqlState==='45000'&&
      e.sqlMessage==='AUTH_OWNER_INACTIVE')
    throw new CRMOwnerInactiveError();
   // Missing routine/EXECUTE, drift, lock timeout or any MySQL error MUST
   // propagate; never retry using raw auth_users reads.
   throw error;
  }
  return;
 }
 const [owners]=await connection.query<RowDataPacket[]>(
  'SELECT role,status FROM auth_users WHERE id=? FOR UPDATE',[actor]);
 if(owners.length!==1||owners[0].role!=='OWNER'||owners[0].status!=='ACTIVE')
  throw new CRMOwnerInactiveError();
}
export class MySQLCRMRepository implements CRMRepository {
  constructor(private readonly db:Pool){}
  async list(entity:CRMEntity,limit:number,offset:number,actor:string) {
    const table=tables[entity],scope=creatorScope('record');
    const [rows]=await this.db.query<RowDataPacket[]>(`SELECT record.* FROM ${table} record
      WHERE record.deleted_at IS NULL AND ${scope}
      ORDER BY record.created_at DESC,record.id DESC LIMIT ? OFFSET ?`,
      [entity,actor,limit,offset]);
    const [counts]=await this.db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
      FROM ${table} record WHERE record.deleted_at IS NULL AND ${scope}`,[entity,actor]);
    return {items:rows.map(x=>clean(entity,x)),total:Number(counts[0].total)};
  }
  async get(entity:CRMEntity,id:string,actor:string) {
    const [rows]=await this.db.query<RowDataPacket[]>(`SELECT record.* FROM ${tables[entity]} record
      WHERE record.id=? AND record.deleted_at IS NULL AND ${creatorScope('record')} LIMIT 1`,
      [id,entity,actor]);
    return rows[0]?clean(entity,rows[0]):null;
  }
  private async audit(connection:PoolConnection,entity:CRMEntity,id:string,actor:string,operation:'CREATE'|'UPDATE'|'DELETE',before:object|null,after:object|null) {
    await connection.execute('INSERT INTO crm_audit_events (id,actor_user_id,entity_type,entity_id,operation,before_data,after_data) VALUES (?,?,?,?,?,?,?)',
      [randomUUID(),actor,entity,id,operation,before?JSON.stringify(before):null,after?JSON.stringify(after):null]);
  }
  async create(entity:CRMEntity,fields:Input,actor:string) {
    const connection=await this.db.getConnection();const id=randomUUID();
    try {
      await connection.beginTransaction();
      await lockActiveCrmOwner(connection,actor);
      const keys=Object.keys(fields);
      await connection.execute(`INSERT INTO ${tables[entity]} (id,${keys.join(',')}) VALUES (?,${keys.map(()=>'?').join(',')})`,[id,...keys.map(k=>fields[k] as string | number | null)]);
      const [rows]=await connection.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=?`,[id]);
      const after=clean(entity,rows[0]);
      await this.audit(connection,entity,id,actor,'CREATE',null,after);
      await connection.commit();return after;
    } catch(e){await connection.rollback();throw e;} finally{connection.release();}
  }
  async update(entity:CRMEntity,id:string,version:number,fields:Input,actor:string):Promise<object|'not_found'|'conflict'> {
    const connection=await this.db.getConnection();
    try {
      await connection.beginTransaction();
      await lockActiveCrmOwner(connection,actor);
      const [beforeRows]=await connection.query<RowDataPacket[]>(`SELECT record.* FROM ${tables[entity]} record WHERE record.id=?
        AND record.deleted_at IS NULL AND ${creatorScope('record')} FOR UPDATE`,[id,entity,actor]);
      if(!beforeRows.length){await connection.rollback();return 'not_found';}
      if(beforeRows[0].version!==version){await connection.rollback();return 'conflict';}
      const before=clean(entity,beforeRows[0]);const keys=Object.keys(fields);
      // Enforce minPrice vs sellingPrice even when modified separately.
      if(entity==='products'){
        const min=fields.minPrice??beforeRows[0].minPrice;
        const sell=fields.sellingPrice??beforeRows[0].sellingPrice;
        if(isMinPriceAboveSellingPrice(min,sell)){await connection.rollback();return 'conflict';}
      }
      await connection.execute(`UPDATE ${tables[entity]} SET ${keys.map(k=>k+'=?').join(',')},version=version+1 WHERE id=?`,[...keys.map(k=>fields[k] as string | number | null),id]);
      const [rows]=await connection.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=?`,[id]);const after=clean(entity,rows[0]);
      await this.audit(connection,entity,id,actor,'UPDATE',before,after);
      await connection.commit();return after;
    }catch(e){await connection.rollback();throw e;}finally{connection.release();}
  }
  async remove(entity:CRMEntity,id:string,version:number,actor:string):Promise<'deleted'|'not_found'|'conflict'> {
    const connection=await this.db.getConnection();
    try{
      await connection.beginTransaction();
      await lockActiveCrmOwner(connection,actor);
      const [beforeRows]=await connection.query<RowDataPacket[]>(`SELECT record.* FROM ${tables[entity]} record WHERE record.id=?
        AND record.deleted_at IS NULL AND ${creatorScope('record')} FOR UPDATE`,[id,entity,actor]);
      if(!beforeRows.length){await connection.rollback();return 'not_found';}
      if(beforeRows[0].version!==version){await connection.rollback();return 'conflict';}
      const before=clean(entity,beforeRows[0]);
      await connection.execute(`UPDATE ${tables[entity]} SET deleted_at=UTC_TIMESTAMP(3),version=version+1 WHERE id=?`,[id]);
      await this.audit(connection,entity,id,actor,'DELETE',before,null);
      await connection.commit();return 'deleted';
    }catch(e){await connection.rollback();throw e;}finally{connection.release();}
  }
}
