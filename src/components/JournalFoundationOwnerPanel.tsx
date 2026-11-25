import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Eligible={releaseIntentId:string;siteId:string;status:string;postingState:string;
 journalId:string|null;journalStatus:string|null};
type Journal={id:string;releaseIntentId:string;status:string;postingState:string;
 manifestSha256:string;heldState:string|null};
type Authority={externalPoVerified:boolean;supplierAcknowledgmentAuthenticated:boolean;
 officialGrnVerified:boolean;warehouseReleaseAuthorized:boolean;
 serialOwnershipEstablished:boolean;operationalDoubleEntryLedgerEnabled:boolean;
 stockPostingEnabled:boolean;availableToSell:null};
async function json<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Journal API unavailable');
 return v as T;
}
export function JournalFoundationOwnerPanel(){
 const [eligible,setEligible]=useState<Eligible[]>([]),[journals,setJournals]=useState<Journal[]>([]);
 const [authority,setAuthority]=useState<Authority|null>(null),[releaseId,setReleaseId]=useState('');
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   json<{items:Eligible[]}>(await authenticatedFetch('/api/journal-foundation/eligible')),
   json<{items:Journal[]}>(await authenticatedFetch('/api/journal-foundation/journals')),
   json<Authority>(await authenticatedFetch('/api/journal-foundation/authority'))]);
  setEligible(a.items);setJournals(b.items);setAuthority(c);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Owner step-up verified. Configured MFA remains server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function prepare(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
   if(!window.confirm('Create UNPOSTED, balanced double-entry EVIDENCE for independent review? No inventory, transfer, serial ownership or official GRN will be created.'))return;
   const r=await json<{id:string;status:string;legCount:number;postingState:string}>(
    await sensitiveFetch('/api/journal-foundation/journals',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({releaseIntentId:releaseId})}));
   setNotice('UNPOSTED journal '+r.id+' · '+r.legCount+' evidence legs · '+r.status+
    ' · posting '+r.postingState+'. No stock movement.');
   setReleaseId('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Unposted double-entry journal foundation owner"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AH · Double-entry evidence journal (UNPOSTED)</h2>
  <p className="text-xs text-amber-200">Evidence legs are balanced for internal inspection, NOT actual accounting
   or warehouse stock. No issued supplier PO, verified acknowledgment, official goods-receipt note,
   established serial title or authorized stock credit. All 1AG site/SKU quantities remain hard-zero.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 p-3 rounded text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 p-3 rounded text-xs">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-xs text-cyan-300">Refresh evidence and authority blockers</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap gap-2 items-end">
   <label className="text-xs">Owner current password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block rounded bg-slate-950 border border-slate-700 p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="bg-amber-800 rounded px-3 py-2 text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up active':'Step-up required'}</span>
  </form>
  <form onSubmit={prepare} className="border border-slate-700 rounded p-3 space-y-3">
   <h3 className="font-semibold text-sm">Prepare immutable, paired evidence entries for independent review</h3>
   <label className="block text-xs">Previously reviewed HELD 1AG stock-release intention
    <select value={releaseId} required onChange={e=>setReleaseId(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="">Select HELD release (stock posting still DISABLED)</option>
     {eligible.filter(x=>!x.journalId).map(x=><option key={x.releaseIntentId} value={x.releaseIntentId}>
      {x.releaseIntentId.slice(0,16)} · site {x.siteId.slice(0,8)} · {x.postingState}</option>)}
    </select></label>
   <button type="submit" disabled={busy||!verified||!releaseId}
    className="rounded bg-amber-800 px-4 py-2 text-xs disabled:opacity-50">
    Create UNPOSTED debit/credit evidence</button>
  </form>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Owned internal journal evidence</h3>
   {journals.length===0?<p className="text-xs text-slate-400">No proposed journals.</p>:
    journals.map(j=><p key={j.id} className="text-xs border-t border-slate-700 py-2 break-words">
     {j.id.slice(0,12)} · {j.status} · {j.postingState} ·
     {j.heldState??'Awaiting review'} · SHA-256 {j.manifestSha256}</p>)}
  </div>
  <div className="border border-amber-700 rounded p-3 text-xs text-amber-200 space-y-1">
   <h3 className="text-sm font-semibold">Hard-blocked production authority</h3>
   <p>Supplier PO authenticated: {String(authority?.externalPoVerified??false)}
    · Supplier ACK authenticated: {String(authority?.supplierAcknowledgmentAuthenticated??false)}</p>
   <p>Official GRN verified: {String(authority?.officialGrnVerified??false)}
    · Warehouse release authorized: {String(authority?.warehouseReleaseAuthorized??false)}</p>
   <p>Serial ownership established: {String(authority?.serialOwnershipEstablished??false)}
    · Operational journal enabled: {String(authority?.operationalDoubleEntryLedgerEnabled??false)}</p>
   <p>Stock posting enabled: {String(authority?.stockPostingEnabled??false)}
    · Available-to-sell: UNKNOWN / NOT AUTHORIZED.</p>
  </div>
 </section>;
}
