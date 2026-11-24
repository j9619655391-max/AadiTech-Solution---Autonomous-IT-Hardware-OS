import React,{useEffect,useRef,useState} from 'react';
import {authenticatedFetch} from '../services/authClient';
type Plan={id:string;ticketId:string;kind:'WORK_ORDER'|'RMA';note:string;noteRedacted?:boolean;status:'PLANNING_HELD';sourceTicketVersion:number;customerConsentState:'UNVERIFIED';externalDispatchState:'DISABLED'};
const url='/api/field-service/internal-plans';
export function HeldFieldServicePlans({ticketId,version,status,disabled}:{ticketId:string;version:number;status:string;disabled:boolean}){
 const [items,setItems]=useState<Plan[]>([]);
 const [note,setNote]=useState(''),[kind,setKind]=useState<'WORK_ORDER'|'RMA'>('WORK_ORDER');
 const [ack,setAck]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const [ready,setReady]=useState(false);
 const active=useRef(false),pending=useRef(false);
 const read=async()=>{
  const r=await authenticatedFetch(url+'?ticketId='+encodeURIComponent(ticketId));
  const data=await r.json();
  if(!r.ok)throw Error('Internal field plans unavailable');
  if(data.ticketId!==ticketId||data.mode!=='INTERNAL_HELD'||data.externalDispatchEnabled!==false||
     data.technicianAssignmentEnabled!==false||data.replacementApprovalEnabled!==false||
     !Array.isArray(data.items)||data.items.length>2||data.items.some((x:Plan)=>x.ticketId!==ticketId||
      x.status!=='PLANNING_HELD'||x.customerConsentState!=='UNVERIFIED'||x.externalDispatchState!=='DISABLED'))
   throw Error('Unverified held field plan response');
  if(active.current){setItems(data.items);setReady(true);}
 };
 useEffect(()=>{
  active.current=true;
  void read().catch(e=>{if(active.current)setError(e.message);});
  return ()=>{active.current=false;};
 },[ticketId,version]);
 const save=async(e:React.FormEvent)=>{
  e.preventDefault();
  if(!ready||pending.current||disabled||status!=='TRIAGED_INTERNAL'||version<2||version>=1000||!ack||items.some(x=>x.kind===kind))return;
  pending.current=true;setBusy(true);setError('');
  try{
   const r=await authenticatedFetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ticketId,expectedTicketVersion:version,kind,note,acknowledgeUnverifiedAuthority:true})});
   const data=await r.json();
   if(!r.ok||data.mode!=='INTERNAL_HELD'||data.externalDispatchEnabled!==false||
      data.plan?.ticketId!==ticketId||data.plan?.sourceTicketVersion!==version||data.plan?.status!=='PLANNING_HELD')
    throw Error('Internal plan not confirmed; reload ticket before retrying');
   if(active.current){setNote('');setAck(false);await read();}
  }catch(e){if(active.current){setReady(false);setError(e instanceof Error?e.message:'Internal plan unavailable');}}
  finally{pending.current=false;if(active.current)setBusy(false);}
 };
 return <section className="space-y-3 rounded-lg border border-slate-700 p-3" aria-label="M17 internal field service planning">
  <h4 className="font-semibold text-white">M17 — Internal work-order / RMA planning</h4>
  <p className="text-xs text-amber-300">PLANNING HELD. No technician assignment, pickup, customer consent, serial ownership, repair, replacement approval or stock movement verified.</p>
  {error&&<p role="alert" className="text-xs text-rose-300">{error}</p>}
  {items.map(item=><div key={item.id} className="rounded border border-slate-700 p-2 text-xs text-slate-300">
   {item.kind} · PLANNING_HELD · source ticket v{item.sourceTicketVersion}: {item.note}
  </div>)}
  {status==='TRIAGED_INTERNAL'&&version>=2&&version<1000&&<form onSubmit={save} className="space-y-2">
   <label className="block text-xs text-slate-300">Internal plan type
    <select className="ml-2 bg-slate-950 text-white" value={kind} onChange={e=>setKind(e.target.value as 'WORK_ORDER'|'RMA')}>
     <option value="WORK_ORDER">Work-order planning</option><option value="RMA">RMA planning</option>
    </select>
   </label>
   <label className="block text-xs text-slate-300">Planning note (no credentials or private data)
    <input className="block w-full rounded bg-slate-950 p-2 text-white" required maxLength={500} value={note} onChange={e=>setNote(e.target.value)}/>
   </label>
   <label className="flex gap-2 text-xs text-slate-300"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>I acknowledge that service and customer authority are unverified.</label>
   <button type="submit" disabled={!ready||disabled||busy||!ack||!note.trim()||items.some(x=>x.kind===kind)} className="rounded bg-slate-700 p-2 text-xs text-white disabled:opacity-50">Save internal held plan</button>
  </form>}
 </section>;
}
