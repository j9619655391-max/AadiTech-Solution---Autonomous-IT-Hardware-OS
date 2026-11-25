import type {Pool, ResultSetHeader, RowDataPacket} from 'mysql2/promise';
import {rateWindowBucket} from '../../server/auth/limiter';

export const RETENTION_BUCKET_DAYS=7;
export const MAX_DELETE_BATCH=250;
// No deletion of auth_security_events, auth_users, TOTP secrets or recovery
// code history. Those require separate legal retention, backup and signoff.
export function assertSafeRetentionEnvironment(env:NodeJS.ProcessEnv,apply:boolean){
 if(env.DB_NAME!=='aaditech_ci'||env.CRM_TEST_DB!=='1'||env.NODE_ENV!=='test')
  throw Error('Retention tool permits only disposable aaditech_ci test database');
 if(apply&&env.RETENTION_APPLY!=='YES_DELETE_TEST_ONLY')
  throw Error('Explicit RETENTION_APPLY=YES_DELETE_TEST_ONLY confirmation required');
}
export function rateBucketCutoff(now:number):number{
 if(!Number.isSafeInteger(now)||now<RETENTION_BUCKET_DAYS*86400000)
  throw Error('Invalid clock for retention');
 // Keep the current bucket plus at least seven full days of historical buckets.
 return rateWindowBucket(now-RETENTION_BUCKET_DAYS*86400000);
}
const targets=[
 {table:'auth_sessions',predicate:'expires_at < UTC_TIMESTAMP(3)',index:'expires_at'},
 {table:'auth_step_up_sessions',predicate:'expires_at < UTC_TIMESTAMP(3)',index:'expires_at'},
 {table:'auth_mfa_challenges',predicate:'expires_at < UTC_TIMESTAMP(3)',index:'expires_at'},
 {table:'auth_login_rate_buckets',predicate:'window_bucket < ?',index:'window_bucket'}
] as const;
export interface RetentionReport{
 mode:'dry-run'|'apply';
 target:'disposable-ci';
 cutoffWindow:number;
 counts:Record<string,number>;
 deleted:Record<string,number>;
 protectedTables:string[];
}
export async function runRetention(db:Pool,env:NodeJS.ProcessEnv,apply=false,now=Date.now()):Promise<RetentionReport>{
 assertSafeRetentionEnvironment(env,apply);
 const cutoffWindow=rateBucketCutoff(now);
 const counts:Record<string,number>={},deleted:Record<string,number>={};
 for(const target of targets){
  const params=target.table==='auth_login_rate_buckets'?[cutoffWindow]:[];
  const [rows]=await db.execute<RowDataPacket[]>(
   'SELECT COUNT(*) AS n FROM '+target.table+' WHERE '+target.predicate,params);
  counts[target.table]=Number(rows[0].n);
  deleted[target.table]=0;
 }
 if(apply){
  // No unrestricted DELETE. Small bounded batches limit locking and avoid
  // long-running transactions; future scheduler must be separately approved.
  for(const target of targets){
   const params=target.table==='auth_login_rate_buckets'?[cutoffWindow]:[];
   while(true){
    const [result]=await db.execute<ResultSetHeader>(
     'DELETE FROM '+target.table+' WHERE '+target.predicate+
      ' ORDER BY '+target.index+' ASC LIMIT '+MAX_DELETE_BATCH,params);
    deleted[target.table]+=result.affectedRows;
    if(result.affectedRows<MAX_DELETE_BATCH)break;
   }
  }
 }
 return {mode:apply?'apply':'dry-run',target:'disposable-ci',cutoffWindow,
  counts,deleted,protectedTables:[
   'auth_users','auth_security_events','auth_totp_credentials',
   'auth_totp_recovery_codes','schema_migrations'
  ]};
}
