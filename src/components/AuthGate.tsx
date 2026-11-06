import React, { useEffect, useState } from 'react';
import { currentSession, loginOwner, logoutOwner, revokeMySessions, type OwnerUser } from '../services/authClient';
import { SecurityAdminPanel } from './SecurityAdminPanel';
import { ReviewerWorkspace } from './ReviewerWorkspace';

interface AuthGateProps { children: React.ReactNode }
type State = { status: 'checking' } | { status: 'logged_out'; error?: string } | { status: 'authenticated'; user: OwnerUser };

export function AuthGate({ children }: AuthGateProps) {
  const [state, setState] = useState<State>({ status: 'checking' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);

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
      setState({ status: 'authenticated', user: session.user });
    } catch (error) {
      setState({ status: 'logged_out', error: error instanceof Error ? error.message : 'Unable to sign in.' });
    } finally {
      setSubmitting(false);
    }
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
      await revokeMySessions();
      setShowSecurity(false);
      setState({ status: 'logged_out' });
    } catch (error) {
      window.alert(error instanceof Error ? error.message : 'Could not revoke sessions.');
    }
  }

  if (state.status === 'checking') {
    return <div className="min-h-screen bg-slate-950 text-slate-200 grid place-items-center" role="status">Checking secure session…</div>;
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
      <button type="button" onClick={() => void revokeAll()} className="rounded border border-amber-700 px-3 py-1 text-amber-200">Sign out all sessions</button>
      <button onClick={logout} className="rounded border border-slate-700 px-3 py-1 text-slate-200 hover:border-cyan-500">Sign out</button>
    </div>
    {state.user.role === 'OWNER' && showSecurity && <div className="mx-auto max-w-6xl p-4"><SecurityAdminPanel /></div>}
    {state.user.role === 'REVIEWER' ? <ReviewerWorkspace /> : children}
  </div>;
}
