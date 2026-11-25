import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';

async function main() {
  const cfg=getDatabaseConfig();
  if(!cfg.host || !cfg.database || !cfg.user || !cfg.password) throw new Error('DB_HOST, DB_NAME, DB_USER, DB_PASSWORD required');
  const db=await mysql.createConnection(cfg);let locked=false;
  try{
    const [lock]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations', 15) AS acquired");
    if(lock[0]?.acquired!==1) throw new Error('Could not obtain migration lock');
    locked=true;
    // Auth schema is a required predecessor; this migration must never initialize legacy schema.
    const [tables]=await db.query<any[]>("SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN ('schema_migrations','auth_users')");
    if(Number(tables[0]?.count)!==2) throw new Error('First apply auth migration: bun run db:migrate:auth');
    const file='database/migrations/0002_crm.sql', id='0002_crm';
    const sql=readFileSync(file,'utf8'),checksum=createHash('sha256').update(sql).digest('hex');
    const [applied]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
    if(applied.length) {
      if(applied[0].checksum!==checksum) throw new Error('Migration checksum mismatch; do not edit applied migrations');
      console.log('Already applied:',id);return;
    }
    const statements=sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean);
    for(const statement of statements)await db.query(statement);
    await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
    console.log('Migration applied:',id);
  }finally{
    if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
    await db.end();
  }
}
main().catch(err=>{console.error('Migration failed:',err instanceof Error?err.message:'Unknown');process.exitCode=1;});
