import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';

type Entry={id:string;holdId:string;requestId:string;status:string;recordedBy:string;
 deliveryEvidenceRef:string;physicalCountRef:string};
type Line={productId:string;quantity:number;trackingMode:'SERIAL'|'LOT';
 lotCode:string|null;serialNumbers:string[]};
type Detail={observation:Entry;items:Line[]};
async function json<T>(r:Response):Promise<T>{
 const value:unknown=await r.json();
 if(!r.ok)throw Error(value&&typeof value==='object'&&'error' in value?String(value.error):'Intake witness API unavailable');
 return value as T;
}
export function InboundWitnessPanel(){
 const [queue,setQueue]=useState<Entry[]>([]);
 const [detail,setDetail]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [outcome,setOutcome]=useState<'ACCEPT_QUARANTINE'|'REJECT_INTERNAL'>('REJECT_INTERNAL');
 const [inspected,setInspected]=useState(false);
 const [reason,setReason]=useState(''),[evidence,setEvidence]=useState('');
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const response=await json<{items:Entry[]}>(await authenticatedFetch('/api/intake/review/observations'));
  setQueue(response.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(e instanceof Error?e.message:'Witness queue unavailable'));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password reverified. Production privileged MFA is additionally enforced server-side.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Password verification failed');}
  finally{setBusy(false);}
 }
 async function open(id:string){
  setBusy(true);setError('');setNotice('');
  try{
   const response=await json<Detail>(await authenticatedFetch('/api/intake/review/observations/'+encodeURIComponent(id)));
   setDetail(response);setOutcome('REJECT_INTERNAL');setReason('');setEvidence('');setInspected(false);
  }catch(e){setError(e instanceof Error?e.message:'Unable to inspect observed details');}
  finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();if(!detail||busy)return;
  setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Verify current password before witnessing');
   if(!window.confirm('Record INTERNAL witness decision? Accepted observations remain quarantine evidence, NOT real stock, verified goods receipt, reservation or invoice.'))return;
   const result=await json<{status:string}>(await sensitiveFetch(
    '/api/intake/review/observations/'+encodeURIComponent(detail.observation.id)+'/witness',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({outcome,reason,inspectionEvidenceRef:evidence,physicallyInspected:inspected})
    }));
   setNotice('Independent decision '+result.status+' saved. No availability, supplier dispatch or financial posting.');
   setDetail(null);await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Witness decision failed; refresh before retry');}
  finally{setBusy(false);}
 }
 return <section aria-label="Independent inbound quarantine witness" className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AD · Independent Quarantine Witness</h2>
  <p className="text-xs text-amber-200">Only internally observed, HELD purchase preparations appear.
   Verify the documents and physical units independently. This is not supplier-issued PO matching or
   an externally verified goods receipt. ACCEPT only records quarantine custody evidence;
   it never makes units available, reserved or financially posted.</p>
  {error&&<p role="alert" className="p-3 rounded border border-rose-700 text-sm text-rose-200">{error}</p>}
  {notice&&<p role="status" className="p-3 rounded border border-cyan-700 text-sm text-cyan-200">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-cyan-300 text-sm disabled:opacity-40">Refresh independent observation queue</button>
  <form onSubmit={verify} className="border border-slate-700 p-3 rounded flex flex-wrap items-end gap-3">
   <label className="text-xs">Current reviewer password
    <input type="password" autoComplete="current-password" value={password} required
     onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="bg-amber-800 rounded px-3 py-2 text-xs disabled:opacity-50">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up valid':'Reauthentication required'}</span>
  </form>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">Inbound observations · {queue.length}</h3>
   {queue.length===0?<p className="text-xs text-slate-400">No independent observations recorded.</p>:
    queue.map(o=><div key={o.id} className="border-t border-slate-700 py-2 text-xs flex flex-wrap justify-between gap-2">
     <span>{o.id.slice(0,12)} · {o.status} · Delivery ref {o.deliveryEvidenceRef}</span>
     <button type="button" onClick={()=>void open(o.id)} className="text-cyan-300">Inspect details</button>
    </div>)}
  </div>
  {detail&&<form onSubmit={decide} className="border border-amber-700 rounded p-4 space-y-3">
   <h3 className="font-semibold text-sm">Witness observation {detail.observation.id.slice(0,16)}</h3>
   <p className="text-xs">Operator: {detail.observation.recordedBy} · Delivery ref: {detail.observation.deliveryEvidenceRef}
    · Physical count ref: {detail.observation.physicalCountRef}</p>
   <div className="overflow-auto">
    <table className="w-full text-xs text-left">
     <thead><tr><th className="p-2">Product ID</th><th className="p-2">Exact units</th>
      <th className="p-2">Tracking</th><th className="p-2">Serial/lot evidence</th></tr></thead>
     <tbody>{detail.items.map(line=><tr key={line.productId} className="border-t border-slate-700">
      <td className="p-2 font-mono">{line.productId.slice(0,12)}</td>
      <td className="p-2">{line.quantity}</td><td className="p-2">{line.trackingMode}</td>
      <td className="p-2 break-all">{line.trackingMode==='SERIAL'?line.serialNumbers.join(', '):line.lotCode}</td>
     </tr>)}</tbody>
    </table>
   </div>
   {detail.observation.status==='AWAITING_WITNESS'?<>
    <label className="block text-xs">Decision
     <select value={outcome} onChange={e=>setOutcome(e.target.value as typeof outcome)}
      className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2">
      <option value="REJECT_INTERNAL">Reject disputed observation</option>
      <option value="ACCEPT_QUARANTINE">Internally witness quarantine ONLY</option>
     </select></label>
    <label className="block text-xs">Inspection evidence ticket reference
     <input required maxLength={160} value={evidence} onChange={e=>setEvidence(e.target.value)}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="block text-xs">Detailed reason (12–1000 characters)
     <textarea value={reason} onChange={e=>setReason(e.target.value)} minLength={12} maxLength={1000}
      required rows={3} className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="flex gap-2 items-start text-xs text-amber-200">
     <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
     I independently inspected the physical units, serial/lot identities and the cited delivery/count evidence.
     Required for quarantine attestation.</label>
    <button type="submit" disabled={busy||!verified||(outcome==='ACCEPT_QUARANTINE'&&!inspected)}
     className="rounded bg-amber-800 px-4 py-2 text-xs disabled:opacity-50">Record internal witness decision</button>
   </>:<p className="text-xs text-amber-200">Immutable decision already recorded. No repeat or stock release allowed.</p>}
  </form>}
  <p className="text-xs text-amber-200">Quarantine custody events are not an available-to-sell inventory ledger.
   Reservations, issues, returns, posted GRNs and financial valuation remain blocked.</p>
 </section>;
}
