// The server owns the session; the CSRF token stays only in tab memory.
let csrfToken: string | null = null;

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
  }
}

export async function revokeMySessions(): Promise<number> {
 if(!csrfToken)throw Error('Session expired. Sign in again.');
 const response=await fetch('/api/auth/revoke-my-sessions',{
  method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','x-csrf-token':csrfToken},body:'{}'
 });
 if(!response.ok)throw Error('Could not revoke sessions. Please retry.');
 const value=await response.json() as {revokedSessions:number};
 csrfToken=null;
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
    window.dispatchEvent(new Event('aaditech:session-expired'));
  }
  return result;
}
