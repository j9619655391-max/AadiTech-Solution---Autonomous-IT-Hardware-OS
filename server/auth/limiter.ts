import {createHash} from 'node:crypto';
import type {Pool} from 'mysql2/promise';

// Fixed 15-minute buckets provide atomic multi-worker limits without storing raw
// email or IP addresses. Counts are applied BEFORE password verification.
const WINDOW_MS=15*60*1000;
export function rateWindowBucket(now=Date.now()):number {
 return Math.floor(now/WINDOW_MS);
}
export function rateKey(kind:'account'|'ip'|'stepup',value:string):string {
 return createHash('sha256').update('aaditech-auth-v1:'+kind+':'+value).digest('hex');
}
export async function reserveLoginAttempt(db:Pool,email:string,ip:string){
 const window=rateWindowBucket();
 const keys=[{hash:rateKey('account',email),limit:6},{hash:rateKey('ip',ip),limit:30}];
 // A failed DB write must fail closed; no in-memory fallback.
 for(const item of keys){
  await db.execute(`INSERT INTO auth_login_rate_buckets (key_hash,window_bucket,attempt_count)
   VALUES (?,?,1) ON DUPLICATE KEY UPDATE attempt_count=attempt_count+1`,[item.hash,window]);
  const [rows]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
   'SELECT attempt_count FROM auth_login_rate_buckets WHERE key_hash=? AND window_bucket=?',
   [item.hash,window]);
  if(Number(rows[0]?.attempt_count)>item.limit)return false;
 }
 return true;
}
export async function reserveStepUpAttempt(db:Pool,userId:string) {
 const hash=rateKey('stepup',userId),window=rateWindowBucket();
 await db.execute(`INSERT INTO auth_login_rate_buckets (key_hash,window_bucket,attempt_count)
   VALUES (?,?,1) ON DUPLICATE KEY UPDATE attempt_count=attempt_count+1`,[hash,window]);
 const [rows]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
   'SELECT attempt_count FROM auth_login_rate_buckets WHERE key_hash=? AND window_bucket=?',[hash,window]);
 return Number(rows[0]?.attempt_count)<=6;
}
