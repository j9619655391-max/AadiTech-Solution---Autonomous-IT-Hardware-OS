import 'dotenv/config';
import mysql from 'mysql2/promise';
import { randomUUID } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';
import { hashPassword } from '../server/auth/crypto';

async function main() {
  const email = (process.env.AADITECH_OWNER_EMAIL || '').trim().toLowerCase();
  const name = (process.env.AADITECH_OWNER_NAME || 'AadiTech Owner').trim();
  const password = process.env.AADITECH_OWNER_PASSWORD || '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || name.length < 2) throw new Error('Valid AADITECH_OWNER_EMAIL and AADITECH_OWNER_NAME required');
  const passwordHash = await hashPassword(password);
  const config = getDatabaseConfig();
  if (!config.host || !config.database || !config.user || !config.password) throw new Error('Database configuration required');
  const db = await mysql.createConnection(config);
  try {
    await db.beginTransaction();
    const [users] = await db.execute<any[]>('SELECT id FROM auth_users LIMIT 1 FOR UPDATE');
    if (users.length) throw new Error('Owner already exists. Bootstrap cannot update or create additional owners.');
    await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)', [randomUUID(), email, name, passwordHash, 'OWNER']);
    await db.commit();
    console.log('Owner created:', email);
  } catch (e) {
    await db.rollback();
    throw e;
  } finally {
    await db.end();
  }
}
main().catch(e => { console.error('Owner bootstrap failed:', e.message); process.exitCode = 1; });
