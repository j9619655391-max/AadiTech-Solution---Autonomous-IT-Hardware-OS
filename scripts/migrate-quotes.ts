import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';

async function main() {
  const config=getDatabaseConfig();
  if(!config.host || !config.user || !config.password || !config.database)
    throw Error('Configure DB_HOST, DB_USER, DB_PASSWORD and DB_NAME before migrations.');
  const db=await mysql.createConnection(config);
  let locked=false;
  try{
    const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations', 15) AS acquired");
    if(locks[0]?.acquired!==1)throw Error('Unable to lock migrations');
    locked=true;
    const [deps]=await db.query<any[]>("SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('0001_auth','0002_crm')");
    if(Number(deps[0].n)!==2)throw Error('First apply auth and CRM migrations');
    const id='0003_quote_drafts';
    const sql=readFileSync('database/migrations/0003_quote_drafts.sql','utf8');
    const checksum=createHash('sha256').update(sql).digest('hex');
    const [rows]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
    if(rows.length){if(rows[0].checksum!==checksum)throw Error('Migration checksum changed; aborting');console.log('Already applied',id);return;}
    const statements=sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean);
    for(const statement of statements)await db.query(statement);
    await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
    console.log('Migration applied',id);
  }finally{
    if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
    await db.end();
  }
}
main().catch(e=>{console.error('Quote migration failed:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
