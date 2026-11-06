// The server owns the session; the CSRF token stays only in tab memory.
let csrfToken: string | null = null;
let stepUpToken: string | null = null;
let stepUpExpiresAt = 0;

export interface OwnerUser {
  id: string;
  email: string;
  role: 'OWNER' | 'REVIEWER';
}

interface SessionResponse {
  user: OwnerUser;
  csrfToken: string;
}

async function parseResponse(response: Response): Promise<SessionResponse> {
  if (!response.ok) throw new Error(response.status === 401 ? 'Please sign in.' : 'Authentication service unavailable.');
  const value: unknown = await response.json();
  if (!value || typeof value !== 'object' || !('user' in value) || !('csrfToken' in value)) throw new Error('Invalid session response.');
  const session = value as SessionResponse;
  if (!['OWNER','REVIEWER'].includes(session.user?.role) || typeof session.csrfToken !== 'string') throw new Error('Invalid session response.');
  csrfToken = session.csrfToken;
  stepUpToken = null;
  stepUpExpiresAt = 0;
  return session;
}

export async function currentSession(): Promise<SessionResponse> {
  return parseResponse(await fetch('/api/auth/me', { credentials: 'same-origin', cache: 'no-store' }));
}

export async function loginOwner(email: string, password: string): Promise<SessionResponse> {
  return parseResponse(await fetch('/api/auth/login', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  }));
}

export async function logoutOwner(): Promise<void> {
  try {
    if (!csrfToken) return;
    const response = await fetch('/api/auth/logout', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'x-csrf-token': csrfToken }
    });
    if (!response.ok) throw new Error('Logout could not be confirmed by the server. Please try again.');
  } finally {
    // Do not retain a CSRF secret after logout has been attempted.
    csrfToken = null;
    stepUpToken = null;
    stepUpExpiresAt = 0;
  }
}

export async function verifyCurrentPassword(currentPassword:string):Promise<void>{
 if(!csrfToken)throw Error('Sign in again.');
 const response=await fetch('/api/auth/step-up',{
  method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','x-csrf-token':csrfToken},
  body:JSON.stringify({currentPassword})
 });
 if(!response.ok){
  stepUpToken=null;stepUpExpiresAt=0;
  if(response.status===429)throw Error('Too many verification attempts. Try again later.');
  throw Error('Current password could not be verified.');
 }
 const value=await response.json() as {stepUpToken:string;expiresInSeconds:number};
 if(!/^[A-Za-z0-9_-]{43}$/.test(value.stepUpToken))throw Error('Invalid verification response');
 stepUpToken=value.stepUpToken;
 stepUpExpiresAt=Date.now()+Math.min(300,value.expiresInSeconds)*1000;
}
export function hasRecentVerification():boolean{
 return Boolean(stepUpToken&&Date.now()<stepUpExpiresAt);
}
export async function sensitiveFetch(input:string,init:RequestInit):Promise<Response>{
 if(!hasRecentVerification())throw Error('Verify your current password to continue.');
 const headers=new Headers(init.headers);
 headers.set('x-step-up-token',stepUpToken!);
 const result=await authenticatedFetch(input,{...init,headers});
 if(result.status===403){stepUpToken=null;stepUpExpiresAt=0;}
 return result;
}

export async function revokeMySessions(): Promise<number> {
 if(!csrfToken||!hasRecentVerification())throw Error('Verify your current password first.');
 const response=await fetch('/api/auth/revoke-my-sessions',{
  method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','x-csrf-token':csrfToken,'x-step-up-token':stepUpToken!},body:'{}'
 });
 if(!response.ok)throw Error('Could not revoke sessions. Please retry.');
 const value=await response.json() as {revokedSessions:number};
 csrfToken=null;stepUpToken=null;stepUpExpiresAt=0;
 return value.revokedSessions;
}

export async function authenticatedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    if (!csrfToken) throw new Error('Session expired. Sign in again.');
    headers.set('x-csrf-token', csrfToken);
  }
  const result = await fetch(input, { ...init, headers, credentials: 'same-origin', cache: 'no-store' });
  if (result.status === 401) {
    csrfToken = null;
    stepUpToken = null;
    stepUpExpiresAt = 0;
    window.dispatchEvent(new Event('aaditech:session-expired'));
  }
  return result;
}
