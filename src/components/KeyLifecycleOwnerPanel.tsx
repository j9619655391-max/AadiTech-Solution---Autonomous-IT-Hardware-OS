import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Key={id:string;partyKind:string;fingerprint:string;status:string;retirement:string|null;
 rotationId:string|null;rotationState:string|null;reviewedPossessions:number};
type Receipt={receiptId:string;keyId:string;status:string;reviewState:string|null};
type Rotation={id:string;oldKeyId:string;newKeyId:string;status:string};
type Challenge={challengeId:string;message:{nonceB64:string};canonicalUtf8:string;
 messageSha256:string;expiresAt:string;identityAuthenticated:boolean};
async function decoded<T>(r:Response):Promise<T>{
 const x:unknown=await r.json();
 if(!r.ok)throw Error(x&&typeof x==='object'&&'error' in x?String(x.error):'Key lifecycle service unavailable');
 return x as T;
}
export function KeyLifecycleOwnerPanel(){
 const [keys,setKeys]=useState<Key[]>([]),[receipts,setReceipts]=useState<Receipt[]>([]);
 const [rotations,setRotations]=useState<Rotation[]>([]);
 const [keyId,setKeyId]=useState(''),[oldKeyId,setOldKeyId]=useState(''),
 [newKeyId,setNewKeyId]=useState(''),[sig,setSig]=useState(''),
 [challenge,setChallenge]=useState<Challenge|null>(null);
 const [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   decoded<{items:Key[]}>(await authenticatedFetch('/api/key-lifecycle/keys')),
   decoded<{items:Receipt[]}>(await authenticatedFetch('/api/key-lifecycle/receipts')),
   decoded<{items:Rotation[]}>(await authenticatedFetch('/api/key-lifecycle/rotations'))]);
  setKeys(a.items);setReceipts(b.items);setRotations(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 const step=()=>{if(!verified||!hasRecentVerification())throw Error('Recent password verification required');};
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Current password verified. MFA policy remains server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function issueChallenge(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setChallenge(null);setSig('');
  try{
   step();
   const v=await decoded<Challenge>(await sensitiveFetch('/api/key-lifecycle/challenges',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keyId})}));
   setChallenge(v);setNotice('One-time nonce challenge issued. Expires '+v.expiresAt+
    '. Sign exact UTF-8 message OFFLINE; private keys must NEVER be uploaded.');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function submitSignature(e:React.FormEvent){
  e.preventDefault();if(!challenge)return;
  setBusy(true);setError('');
  try{
   step();
   const v=await decoded<{receiptId:string;status:string}>(
    await sensitiveFetch('/api/key-lifecycle/responses',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({challengeId:challenge.challengeId,
      nonceB64:challenge.message.nonceB64,signatureB64:sig})}));
   setNotice('Offline possession signature matched · '+v.receiptId+
    '. Await separate internal reviewer. External supplier identity NOT verified.');
   setChallenge(null);setSig('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function retire(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   step();
   if(!window.confirm('IMMEDIATELY and irreversibly REVOKE the selected candidate key? New proof claims with it will be denied.'))return;
   const v=await decoded<{status:string}>(
    await sensitiveFetch('/api/key-lifecycle/keys/'+encodeURIComponent(keyId)+'/revoke',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({reason,evidenceRef:evidence})}));
   setNotice(v.status+' · no key reactivation possible. Existing signed claims remain historical internal records only.');
   setKeyId('');setReason('');setEvidence('');setChallenge(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function rotate(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   step();
   if(!window.confirm('Submit dual-possession INTERNAL rotation? Both keys suspended pending independent review; no external trust created.'))return;
   const v=await decoded<{rotationId:string;status:string}>(
    await sensitiveFetch('/api/key-lifecycle/rotations',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({oldKeyId,newKeyId,reason,evidenceRef:evidence})}));
   setNotice('Rotation '+v.rotationId+' · '+v.status+
    '. Both candidates suspended; reviewer can reject or retire old key.');
   setOldKeyId('');setNewKeyId('');setReason('');setEvidence('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const eligible=keys.filter(k=>k.status==='REVIEWED_UNTRUSTED'&&!k.retirement&&
  k.rotationState!=='PENDING_INTERNAL');
 return <section aria-label="Phase 1AJ owner key lifecycle controls"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-lg">Phase 1AJ · Offline key possession / revocation (UNTRUSTED)</h2>
  <p className="text-xs text-amber-200">One-time Ed25519 signature proves control of the PRIVATE KEY only,
   not legal supplier or warehouse identity. Immediate revocation disables future proof checks.
   Rotation requires separate internal inspection of BOTH keys and never enables GRN or stock.</p>
  {error&&<p role="alert" className="text-xs text-rose-200 border border-rose-700 p-2 rounded">{error}</p>}
  {notice&&<p role="status" className="text-xs text-cyan-200 border border-cyan-700 p-2 rounded">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh key states</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex items-end flex-wrap gap-2">
   <label className="block text-xs">Owner current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <button type="submit" className="text-xs bg-amber-800 rounded px-3 py-2" disabled={busy}>Verify</button>
  </form>
  <div className="border border-slate-700 p-3 rounded">
   <h3 className="text-sm font-semibold">Candidate keys and internal possession state</h3>
   {keys.length===0?<p className="text-xs text-slate-400">Register a public-key CANDIDATE in Phase 1AI first.</p>:
    keys.map(k=><p key={k.id} className="border-t border-slate-700 py-2 text-xs break-all">
     {k.id.slice(0,14)} · {k.partyKind} · {k.status} · internally reviewed possessions {k.reviewedPossessions}
     · {k.retirement??k.rotationState??'NOT EXTERNALLY TRUSTED'}</p>)}
  </div>
  <form onSubmit={issueChallenge} className="border border-slate-700 p-3 rounded space-y-2">
   <h3 className="text-sm font-semibold">1. Generate a 10-minute one-time signing challenge</h3>
   <label className="block text-xs">Independent internally reviewed PUBLIC-key candidate
    <select required value={keyId} onChange={e=>setKeyId(e.target.value)}
     className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700">
     <option value="">Choose candidate</option>
     {eligible.map(k=><option key={k.id} value={k.id}>{k.id.slice(0,14)} · {k.partyKind}</option>)}
    </select></label>
   <button type="submit" disabled={busy||!verified||!keyId}
    className="text-xs bg-amber-800 rounded px-3 py-2 disabled:opacity-50">
    Issue nonce message (no private key access)</button>
  </form>
  {challenge&&<form onSubmit={submitSignature} className="border border-amber-700 p-3 rounded space-y-3">
   <h3 className="text-sm font-semibold">2. Sign EXACT text offline and submit detached signature</h3>
   <p className="text-xs text-amber-200">Expiry: {challenge.expiresAt}. This nonce cannot be recovered if this view closes.</p>
   <textarea aria-label="Canonical one-time challenge" readOnly rows={5} value={challenge.canonicalUtf8}
    className="block w-full p-2 rounded bg-slate-950 border border-slate-700 font-mono text-xs"/>
   <label className="text-xs block">Base64 Ed25519 signature only (64 bytes). NEVER enter a private key.
    <textarea required rows={2} value={sig} onChange={e=>setSig(e.target.value)}
     className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button disabled={busy||!verified||!sig} className="text-xs bg-amber-800 rounded px-3 py-2">
    Verify one-time possession only</button>
  </form>}
  <div className="border border-slate-700 p-3 rounded text-xs">
   <h3 className="text-sm font-semibold">Possession receipts — independent review required</h3>
   {receipts.map(r=><p key={r.receiptId} className="border-t border-slate-700 py-2">
    {r.receiptId.slice(0,12)} · key {r.keyId.slice(0,12)} · {r.reviewState??'AWAITING REVIEW'}</p>)}
  </div>
  <form onSubmit={rotate} className="border border-slate-700 p-3 rounded space-y-2">
   <h3 className="text-sm font-semibold">3. Propose independently reviewed rotation (both keys must have reviewed possession)</h3>
   {(['old','new'] as const).map(which=><label key={which} className="text-xs block">
    {which==='old'?'Old candidate (retired after internal approval)':'New candidate (still UNTRUSTED)'}
    <select required value={which==='old'?oldKeyId:newKeyId}
     onChange={e=>which==='old'?setOldKeyId(e.target.value):setNewKeyId(e.target.value)}
     className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700">
     <option value="">Choose reviewed-possession candidate</option>
     {eligible.filter(k=>Number(k.reviewedPossessions)>0).map(k=><option key={k.id} value={k.id}>
      {k.id.slice(0,14)} · {k.partyKind}</option>)}
    </select></label>)}
   <label className="text-xs block">Detailed justification
    <textarea required minLength={12} maxLength={1000} value={reason}
     onChange={e=>setReason(e.target.value)}
     className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <label className="text-xs block">Internal evidence ticket
    <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button disabled={busy||!verified||!oldKeyId||!newKeyId}
    className="text-xs bg-amber-800 rounded px-3 py-2 disabled:opacity-50">Propose suspended rotation</button>
  </form>
  <div className="border border-slate-700 p-3 rounded text-xs">
   <h3 className="text-sm font-semibold">Rotation history</h3>
   {rotations.map(x=><p key={x.id} className="border-t border-slate-700 py-2">
    {x.id.slice(0,12)} · {x.oldKeyId.slice(0,9)} → {x.newKeyId.slice(0,9)} · {x.status}</p>)}
  </div>
  <form onSubmit={retire} className="border border-rose-800 p-3 rounded space-y-2">
   <h3 className="font-semibold text-sm text-rose-200">Emergency irrevocable key retirement</h3>
   <p className="text-xs text-rose-200">Use for loss, exposure or suspected compromise. It blocks future source proof checks immediately, without waiting for review.</p>
   <label className="block text-xs">Candidate to revoke
    <select required value={keyId} onChange={e=>setKeyId(e.target.value)}
     className="block mt-1 w-full rounded p-2 bg-slate-950 border border-slate-700">
     <option value="">Choose key</option>
     {keys.filter(k=>!k.retirement).map(k=><option key={k.id} value={k.id}>{k.id.slice(0,14)} · {k.partyKind}</option>)}
    </select></label>
   <p className="text-xs text-slate-400">Reason and evidence ticket are shared with the rotation form above.</p>
   <button disabled={busy||!verified||!keyId||reason.trim().length<12||!evidence}
    className="text-xs rounded px-3 py-2 bg-rose-800 disabled:opacity-50">EMERGENCY REVOKE key</button>
  </form>
 </section>;
}
