import React, { useEffect, useState } from 'react';
import { currentSession, loginOwner, completeMFALogin, logoutOwner, revokeMySessions, verifyCurrentPassword, type OwnerUser } from '../services/authClient';
import { SecurityAdminPanel } from './SecurityAdminPanel';
import { ReviewerWorkspace } from './ReviewerWorkspace';
import { MFASettings } from './MFASettings';

interface AuthGateProps { children: React.ReactNode }
type State = { status: 'checking' } | { status: 'logged_out'; error?: string } | { status: 'mfa_challenge'; challengeToken:string; error?:string } | { status: 'authenticated'; user: OwnerUser };

export function AuthGate({ children }: AuthGateProps) {
  const [state, setState] = useState<State>({ status: 'checking' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode,setMfaCode]=useState('');
  const [showMFA,setShowMFA]=useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [showRevoke, setShowRevoke] = useState(false);
  const [revokePassword, setRevokePassword] = useState('');
  const [revokeError, setRevokeError] = useState('');

  useEffect(() => {
    let active = true;
    currentSession().then(s => {
      if (active) setState({ status: 'authenticated', user: s.user });
    }).catch(() => {
      if (active) setState({ status: 'logged_out' });
    });
    const onExpired = () => setState({ status: 'logged_out', error: 'Your session has expired. Please sign in again.' });
    window.addEventListener('aaditech:session-expired', onExpired);
    return () => { active = false; window.removeEventListener('aaditech:session-expired', onExpired); };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setState({ status: 'logged_out' });
    try {
      const session = await loginOwner(email, password);
      setPassword('');
      if('mfaRequired' in session){
        setState({status:'mfa_challenge',challengeToken:session.challengeToken});
      }else setState({ status: 'authenticated', user: session.user });
    } catch (error) {
      setState({ status: 'logged_out', error: error instanceof Error ? error.message : 'Unable to sign in.' });
    } finally {
      setSubmitting(false);
    }
  }

  async function submitMFA(event:React.FormEvent){
    event.preventDefault();
    if(state.status!=='mfa_challenge')return;
    setSubmitting(true);
    try{
      const verified=await completeMFALogin(state.challengeToken,mfaCode.trim());
      setMfaCode('');setState({status:'authenticated',user:verified.user});
    }catch(e){
      setState({status:'mfa_challenge',challengeToken:state.challengeToken,
        error:e instanceof Error?e.message:'MFA verification failed'});
    }finally{setSubmitting(false);}
  }

  async function logout() {
    try {
      await logoutOwner();
      setState({ status: 'logged_out' });
    } catch (error) {
      setState({ status: 'logged_out', error: error instanceof Error ? error.message : 'Could not verify logout.' });
    }
  }

  async function revokeAll() {
    if (!window.confirm('Revoke all your sessions, including this one, and sign out?')) return;
    try {
      await verifyCurrentPassword(revokePassword);
      await revokeMySessions();
      setShowSecurity(false);
      setShowRevoke(false);
      setRevokePassword('');
      setState({ status: 'logged_out' });
    } catch (error) {
      setRevokeError(error instanceof Error ? error.message : 'Could not revoke sessions.');
    }
  }

  if (state.status === 'checking') {
    return <div className="min-h-screen bg-slate-950 text-slate-200 grid place-items-center" role="status">Checking secure session…</div>;
  }

  if(state.status==='mfa_challenge'){
    return <main className="min-h-screen bg-slate-950 text-slate-100 grid place-items-center p-5">
      <form onSubmit={submitMFA} className="rounded-xl border border-slate-700 bg-slate-900 p-7 w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">Authenticator verification</h1>
        <p className="text-sm text-slate-400">Enter a six-digit authenticator code or one unused 20-character recovery code. No session is created until this succeeds.</p>
        <input value={mfaCode} onChange={e=>setMfaCode(e.target.value)}
          autoComplete="one-time-code" autoFocus required maxLength={20}
          className="w-full bg-slate-950 border border-slate-600 rounded p-3" aria-label="Authenticator or recovery code"/>
        {state.error&&<p role="alert" className="text-rose-300 text-sm">{state.error}</p>}
        <button type="submit" disabled={submitting} className="bg-cyan-600 w-full rounded p-3 disabled:opacity-40">Verify and sign in</button>
        <button type="button" onClick={()=>{setMfaCode('');setState({status:'logged_out'});}}
          className="text-sm text-slate-400">Cancel and sign in again</button>
      </form>
    </main>;
  }
  if (state.status === 'logged_out') {
    return <main className="min-h-screen bg-slate-950 text-slate-100 grid place-items-center p-5">
      <form onSubmit={submit} className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-8 shadow-xl space-y-5">
        <div>
          <h1 className="text-2xl font-bold text-white">AadiTech Solution</h1>
          <p className="mt-1 text-sm text-slate-400">Private Hardware OS · Authorized Staff Sign In</p>
        </div>
        <label className="block text-sm font-medium">Work email
          <input autoComplete="username" type="email" required maxLength={191} value={email} onChange={e => setEmail(e.target.value)}
            className="mt-2 w-full rounded-lg bg-slate-950 border border-slate-600 px-3 py-3 outline-none focus:border-cyan-400" />
        </label>
        <label className="block text-sm font-medium">Password
          <input autoComplete="current-password" type="password" required value={password} onChange={e => setPassword(e.target.value)}
            className="mt-2 w-full rounded-lg bg-slate-950 border border-slate-600 px-3 py-3 outline-none focus:border-cyan-400" />
        </label>
        {state.error && <p role="alert" className="rounded-lg border border-rose-700 bg-rose-950/50 p-3 text-sm text-rose-200">{state.error}</p>}
        <button type="submit" disabled={submitting} className="w-full rounded-lg bg-cyan-600 py-3 font-semibold hover:bg-cyan-500 disabled:opacity-50">
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="text-xs text-slate-400">New setup? Configure MySQL, run the auth migration and securely bootstrap the owner account. There is no default demo password.</p>
      </form>
    </main>;
  }

  return <div>
    <div className="bg-slate-950 border-b border-slate-800 text-slate-400 text-xs flex items-center justify-end gap-3 px-4 py-2">
      <span>Signed in: {state.user.email} · {state.user.role}</span>
      {state.user.role === 'OWNER' && <button type="button" onClick={() => setShowSecurity(v => !v)}
        className="rounded border border-slate-700 px-3 py-1 text-slate-200 hover:border-cyan-500">Reviewer security</button>}
      <button type="button" onClick={()=>setShowMFA(v=>!v)} className="rounded border border-slate-700 px-3 py-1 text-cyan-300">Authenticator MFA</button>
      <button type="button" onClick={() => {setShowRevoke(v=>!v);setRevokeError('');}} className="rounded border border-amber-700 px-3 py-1 text-amber-200">Sign out all sessions</button>
      <button onClick={logout} className="rounded border border-slate-700 px-3 py-1 text-slate-200 hover:border-cyan-500">Sign out</button>
    </div>
    {showMFA && <div className="p-4"><MFASettings /></div>}
    {showRevoke && <form onSubmit={event => {event.preventDefault();void revokeAll();}}
      className="mx-auto max-w-3xl border border-amber-700 p-4 bg-slate-900 text-slate-100 space-y-2">
      <p className="text-sm">Confirm your password to revoke every active session on all devices.</p>
      <input type="password" autoComplete="current-password" required value={revokePassword}
        onChange={e=>setRevokePassword(e.target.value)} className="bg-slate-950 border border-slate-600 p-2 rounded w-full"
        aria-label="Current password for session revocation"/>
      {revokeError && <p role="alert" className="text-rose-300 text-sm">{revokeError}</p>}
      <button type="submit" className="bg-amber-700 rounded px-4 py-2 text-sm">Verify and revoke all sessions</button>
    </form>}
    {state.user.role === 'OWNER' && showSecurity && <div className="mx-auto max-w-6xl p-4"><SecurityAdminPanel /></div>}
    {state.user.role === 'REVIEWER' ? <ReviewerWorkspace /> : children}
  </div>;
}
