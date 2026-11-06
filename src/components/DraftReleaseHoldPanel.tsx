import React,{useEffect,useState} from 'react';
import {authenticatedFetch} from '../services/authClient';
type Hold={id:string;revision_number:number;status:string;dispatch_state:string;stale:boolean};
type Result={currentRevision:number;preparations:Hold[]};
export function DraftReleaseHoldPanel({draftId}:{draftId:string}){
 const [data,setData]=useState<Result|null>(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 async function load(){
  const response=await authenticatedFetch('/api/quotes/release-preparations/'+draftId);
  const value=await response.json();
  if(!response.ok)throw Error(value.error||'Unavailable');
  setData(value as Result);
 }
 useEffect(()=>{let active=true;
  authenticatedFetch('/api/quotes/release-preparations/'+draftId).then(async response=>{
   const value=await response.json();if(!response.ok)throw Error(value.error||'Unavailable');
   if(active)setData(value as Result);
  }).catch(e=>{if(active)setError(String(e));});
  return()=>{active=false;};
 },[draftId]);
 async function hold(){
  if(!data||busy||!window.confirm('Prepare a HELD internal snapshot only?'))return;
  setBusy(true);setError('');setNotice('');
  try{
   const response=await authenticatedFetch('/api/quotes/release-preparations/'+draftId,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({expectedRevision:data.currentRevision})
   });
   const value=await response.json();
   if(!response.ok)throw Error(value.error||'Unavailable');
   setNotice(value.replayed?'Existing hold returned':'New internal hold saved');
   await load();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section className="rounded-xl border border-amber-700 bg-slate-900 p-5 space-y-3">
  <h3 className="font-semibold">Release preparation: HELD</h3>
  <p className="text-sm text-amber-300">Dispatch disabled. No customer delivery or inventory action.</p>
  {error&&<p role="alert" className="text-rose-300">{error}</p>}
  {notice&&<p role="status" className="text-emerald-300">{notice}</p>}
  <button type="button" className="text-cyan-300" onClick={()=>void load().catch(e=>setError(String(e)))}>Refresh</button>
  {data&&<><p>Revision {data.currentRevision}</p>
   <button type="button" disabled={busy} onClick={()=>void hold()} className="bg-amber-800 rounded px-4 py-2">Prepare HELD snapshot</button>
   {data.preparations.map(v=><p key={v.id} className="text-xs border border-slate-700 p-2">Revision {v.revision_number} · {v.status} · {v.dispatch_state}{v.stale?' · STALE':''}</p>)}
  </>}
 </section>;
}
