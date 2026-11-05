import { randomUUID } from 'node:crypto';
import type { Pool, PoolConnection, RowDataPacket } from 'mysql2/promise';
import { definitions, type CRMEntity, type Input } from './validation';

export interface CRMRepository {
  list(entity: CRMEntity, limit: number, offset: number): Promise<{ items: object[]; total: number }>;
  get(entity: CRMEntity, id: string): Promise<object | null>;
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
export class MySQLCRMRepository implements CRMRepository {
  constructor(private readonly db:Pool){}
  async list(entity:CRMEntity,limit:number,offset:number) {
    const table=tables[entity];
    const [rows]=await this.db.query<RowDataPacket[]>(`SELECT * FROM ${table} WHERE deleted_at IS NULL ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`,[limit,offset]);
    const [counts]=await this.db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM ${table} WHERE deleted_at IS NULL`);
    return {items:rows.map(x=>clean(entity,x)),total:Number(counts[0].total)};
  }
  async get(entity:CRMEntity,id:string) {
    const [rows]=await this.db.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=? AND deleted_at IS NULL LIMIT 1`,[id]);
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
      const keys=Object.keys(fields);
      await connection.execute(`INSERT INTO ${tables[entity]} (id,${keys.join(',')}) VALUES (?,${keys.map(()=>'?').join(',')})`,[id,...keys.map(k=>fields[k])]);
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
      const [beforeRows]=await connection.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=? AND deleted_at IS NULL FOR UPDATE`,[id]);
      if(!beforeRows.length){await connection.rollback();return 'not_found';}
      if(beforeRows[0].version!==version){await connection.rollback();return 'conflict';}
      const before=clean(entity,beforeRows[0]);const keys=Object.keys(fields);
      // Enforce minPrice vs sellingPrice even when modified separately.
      if(entity==='products'){
        const min=fields.minPrice??beforeRows[0].minPrice;
        const sell=fields.sellingPrice??beforeRows[0].sellingPrice;
        if(Number(min)>Number(sell)){await connection.rollback();return 'conflict';}
      }
      await connection.execute(`UPDATE ${tables[entity]} SET ${keys.map(k=>k+'=?').join(',')},version=version+1 WHERE id=?`,[...keys.map(k=>fields[k]),id]);
      const [rows]=await connection.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=?`,[id]);const after=clean(entity,rows[0]);
      await this.audit(connection,entity,id,actor,'UPDATE',before,after);
      await connection.commit();return after;
    }catch(e){await connection.rollback();throw e;}finally{connection.release();}
  }
  async remove(entity:CRMEntity,id:string,version:number,actor:string):Promise<'deleted'|'not_found'|'conflict'> {
    const connection=await this.db.getConnection();
    try{
      await connection.beginTransaction();
      const [beforeRows]=await connection.query<RowDataPacket[]>(`SELECT * FROM ${tables[entity]} WHERE id=? AND deleted_at IS NULL FOR UPDATE`,[id]);
      if(!beforeRows.length){await connection.rollback();return 'not_found';}
      if(beforeRows[0].version!==version){await connection.rollback();return 'conflict';}
      const before=clean(entity,beforeRows[0]);
      await connection.execute(`UPDATE ${tables[entity]} SET deleted_at=UTC_TIMESTAMP(3),version=version+1 WHERE id=?`,[id]);
      await this.audit(connection,entity,id,actor,'DELETE',before,null);
      await connection.commit();return 'deleted';
    }catch(e){await connection.rollback();throw e;}finally{connection.release();}
  }
}
