import { Router, type Request, type Response, type NextFunction } from 'express';
import {randomUUID} from 'node:crypto';
import { getPool } from '../db';
import type {ResultSetHeader} from 'mysql2/promise';
import { hashToken, newSecret, verifyPassword } from './crypto';

const router = Router();
const COOKIE = 'aaditech_session';
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const attempts = new Map<string, { count: number; reset: number }>();
const MAX_ATTEMPTS = 6;
const WINDOW_MS = 15 * 60 * 1000;

function getSessionCookie(req: Request): string | null {
  const header = req.headers.cookie || '';
  const raw = header.split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  const value = raw?.slice(COOKIE.length + 1);
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

function cookieOptions() {
  return { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' as const, path: '/api', maxAge: SESSION_DURATION_MS };
}

function isSameOrigin(req: Request): boolean {
  const origin = req.headers.origin;
  if (!origin) return true; // Non-browser clients may omit Origin; session CSRF token is still mandatory.
  const allowed = process.env.APP_URL;
  if (!allowed) return process.env.NODE_ENV !== 'production';
  try { return new URL(origin).origin === new URL(allowed).origin; } catch { return false; }
}

export interface Session { userId: string; email: string; role: 'OWNER' | 'REVIEWER'; csrf: string; }
async function getSession(req: Request): Promise<Session | null> {
  const cookie = getSessionCookie(req);
  const db = getPool();
  if (!cookie || !db) return null;
  const [rows] = await db.execute<any[]>(`SELECT u.id AS userId,u.email,u.role,s.csrf_token AS csrf
    FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at > UTC_TIMESTAMP(3) AND u.status='ACTIVE' LIMIT 1`, [hashToken(cookie)]);
  return rows.length ? rows[0] as Session : null;
}

async function enforceRole(req: Request,res: Response,next: NextFunction,allowed:readonly Session['role'][]){
  try{
    const session=await getSession(req);
    if(!session){res.status(401).json({error:'Authentication required'});return;}
    if(!allowed.includes(session.role)){res.status(403).json({error:'Insufficient role privileges'});return;}
    if(['POST','PUT','PATCH','DELETE'].includes(req.method) &&
      (!isSameOrigin(req)||req.header('x-csrf-token')!==session.csrf)){
      res.status(403).json({error:'Invalid request verification'});return;
    }
    res.locals.auth=session;
    next();
  }catch{res.status(503).json({error:'Authentication service unavailable'});}
}
export function requireOwner(req:Request,res:Response,next:NextFunction){
  return enforceRole(req,res,next,['OWNER']);
}
export function requireReviewer(req:Request,res:Response,next:NextFunction){
  return enforceRole(req,res,next,['REVIEWER']);
}
export function requireAuthenticated(req:Request,res:Response,next:NextFunction){
  return enforceRole(req,res,next,['OWNER','REVIEWER']);
}

router.post('/login', async (req, res) => {
  if (!isSameOrigin(req)) { res.status(403).json({ error: 'Invalid request origin' }); return; }
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (email.length > 191 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length > 1024) {
    res.status(400).json({ error: 'Invalid credentials' }); return;
  }
  // Initial single-instance limiter. Replace with persistent/shared limiter before multi-worker deployment.
  const key = (req.ip || 'unknown') + ':' + email;
  const now = Date.now();
  const current = attempts.get(key);
  const state = current && current.reset > now ? current : { count: 0, reset: now + WINDOW_MS };
  if (state.count >= MAX_ATTEMPTS) { res.status(429).json({ error: 'Too many attempts' }); return; }
  const db = getPool();
  if (!db) { res.status(503).json({ error: 'Authentication service unavailable' }); return; }
  try {
    const [users] = await db.execute<any[]>('SELECT id,email,role,password_hash FROM auth_users WHERE email=? AND status=? LIMIT 1', [email, 'ACTIVE']);
    const user = users[0];
    // Generic failure response; do not leak whether an account exists.
    const valid = user ? await verifyPassword(password, user.password_hash) : false;
    if (!valid) {
      state.count++;
      attempts.set(key, state);
      res.status(401).json({ error: 'Invalid credentials' }); return;
    }
    attempts.delete(key);
    const token = newSecret();
    const csrf = newSecret();
    await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 8 HOUR))',
      [hashToken(token),user.id,csrf]);
    res.cookie(COOKIE, token, cookieOptions());
    res.json({ user: { id: user.id, email: user.email, role: user.role }, csrfToken: csrf });
  } catch {
    res.status(503).json({ error: 'Authentication service unavailable' });
  }
});

router.get('/me', requireAuthenticated, (req, res) => {
  const { userId, email, role, csrf } = res.locals.auth as Session;
  res.setHeader('Cache-Control', 'no-store');
  res.json({ user: { id: userId, email, role }, csrfToken: csrf });
});

router.post('/logout', requireAuthenticated, async (req, res) => {
  const db = getPool();
  const token = getSessionCookie(req);
  if (!db || !token) { res.status(503).json({ error: 'Authentication service unavailable' }); return; }
  try {
    await db.execute('DELETE FROM auth_sessions WHERE token_hash=?', [hashToken(token)]);
    res.clearCookie(COOKIE, { path: '/api', httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    res.status(204).end();
  } catch { res.status(503).json({ error: 'Authentication service unavailable' }); }
});

router.post('/revoke-my-sessions',requireAuthenticated,async(req,res)=>{
 const pool=getPool();
 if(!pool){res.status(503).json({error:'Authentication service unavailable'});return;}
 const userId=(res.locals.auth as Session).userId;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // Lock user row before revocation so any concurrent account lifecycle writes
  // are serialized. The session table records are deleted transactionally.
  const [rows]=await conn.execute<any[]>('SELECT id FROM auth_users WHERE id=? AND status=? FOR UPDATE',[userId,'ACTIVE']);
  if(rows.length!==1)throw Error('User no longer active');
  const [result]=await conn.execute<ResultSetHeader>('DELETE FROM auth_sessions WHERE user_id=?',[userId]);
  await conn.execute(
   'INSERT INTO auth_security_events (id,actor_user_id,target_user_id,event_type,revoked_session_count) VALUES (?,?,?,?,?)',
   [randomUUID(),userId,userId,'OWN_SESSIONS_REVOKED',result.affectedRows]);
  await conn.commit();
  res.clearCookie(COOKIE,{path:'/api',httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production'});
  res.status(200).json({revokedSessions:result.affectedRows,signInRequired:true});
 }catch(e){
  await conn.rollback();
  console.error('Self session revocation failed',e instanceof Error?e.name:'Unknown');
  res.status(503).json({error:'Authentication service unavailable'});
 }finally{conn.release();}
});

export default router;
