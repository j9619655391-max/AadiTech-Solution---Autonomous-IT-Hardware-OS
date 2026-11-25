import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';

async function main() {
  const config = getDatabaseConfig();
  if (!config.host || !config.database || !config.user || !config.password) throw new Error('DB_HOST, DB_NAME, DB_USER, DB_PASSWORD required');
  const connection = await mysql.createConnection(config);
  let locked = false;
  try {
    const [lockRows] = await connection.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations', 15) AS acquired");
    if (lockRows[0]?.acquired !== 1) throw new Error('Could not acquire auth migration lock');
    locked = true;
    await connection.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      id VARCHAR(100) PRIMARY KEY,
      checksum CHAR(64) NOT NULL,
      applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    const migrationId = '0001_auth';
    const sql = readFileSync('database/migrations/0001_auth.sql', 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const [applied] = await connection.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id = ?', [migrationId]);
    if (applied.length) {
      if (applied[0].checksum !== checksum) throw new Error('Migration checksum changed; refusing to continue');
      console.log('Migration already applied:', migrationId);
      return;
    }
    // MySQL DDL implicitly commits. Each statement is idempotent, and a failed
    // migration can be safely rerun after fixing the underlying problem.
    const statements = sql.split(';').map(x => x.trim()).filter(Boolean);
    for (const statement of statements) await connection.query(statement);
    await connection.execute('INSERT INTO schema_migrations (id, checksum) VALUES (?, ?)', [migrationId, checksum]);
    console.log('Migration applied:', migrationId);
  } finally {
    if (locked) await connection.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
    await connection.end();
  }
}
main().catch(e => { console.error('Migration failed:', e.message); process.exitCode = 1; });
