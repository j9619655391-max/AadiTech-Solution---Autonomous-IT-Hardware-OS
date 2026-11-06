import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';

async function main(){
  const config=getDatabaseConfig();
  if(!config.host || !config.user || !config.password || !config.database)throw Error('Database config required');
  const db=await mysql.createConnection(config);let locked=false;
  try{
    const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
    if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
    locked=true;
    const [deps]=await db.query<any[]>("SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency')");
    if(Number(deps[0].n)!==4)throw Error('Apply migrations 0001–0004 first');
    const id='0005_quote_revisions',sql=readFileSync('database/migrations/0005_quote_revisions.sql','utf8');
    const checksum=createHash('sha256').update(sql).digest('hex');
    const [rows]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
    if(rows.length){if(rows[0].checksum!==checksum)throw Error('Applied migration checksum changed');console.log('Already applied',id);return;}
    for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(v=>v.trim()).filter(Boolean))await db.query(statement);
    await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
    console.log('Applied',id);
  }finally{
    if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
    await db.end();
  }
}
main().catch(e=>{console.error('Migration failed',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
