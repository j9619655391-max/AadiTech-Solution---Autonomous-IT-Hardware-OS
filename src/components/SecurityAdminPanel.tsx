import React,{useEffect,useState} from 'react';
import {authenticatedFetch} from '../services/authClient';

type Reviewer={id:string;email:string;full_name:string;status:'ACTIVE'|'DISABLED';active_sessions:number};
type EventRow={id:string;event_type:string;created_at:string;revoked_session_count:number;target_user_id:string};
async function parse<T>(response:Response):Promise<T>{
 const value:unknown=await response.json();
 if(!response.ok){
  const text=value&&typeof value==='object'&&'error' in value?String(value.error):'Staff operation failed';
  throw Error(text);
 }
 return value as T;
}
export function SecurityAdminPanel(){
 const [reviewers,setReviewers]=useState<Reviewer[]>([]);
 const [events,setEvents]=useState<EventRow[]>([]);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [success,setSuccess]=useState('');
 async function refresh(){
  const [staff,log]=await Promise.all([
   parse<{items:Reviewer[]}>(await authenticatedFetch('/api/security/reviewers')),
   parse<{items:EventRow[]}>(await authenticatedFetch('/api/security/events?limit=20'))
  ]);
  setReviewers(staff.items);setEvents(log.items);
 }
 useEffect(()=>{
  let active=true;
  Promise.all([
   authenticatedFetch('/api/security/reviewers').then(r=>parse<{items:Reviewer[]}>(r)),
   authenticatedFetch('/api/security/events?limit=20').then(r=>parse<{items:EventRow[]}>(r))
  ]).then(([staff,log])=>{if(active){setReviewers(staff.items);setEvents(log.items);}})
   .catch(e=>{if(active)setError(e instanceof Error?e.message:'Could not load staff security records');});
  return()=>{active=false;};
 },[]);
 async function change(item:Reviewer,action:'status'|'revoke'){
  if(busy)return;
  const newStatus=item.status==='ACTIVE'?'DISABLED':'ACTIVE';
  const message=action==='status'
   ?(newStatus==='DISABLED'?'Disable this reviewer and revoke all their sessions?':'Reactivate this reviewer and invalidate any old sessions?')
   :'Revoke all active reviewer sessions immediately?';
  if(!window.confirm(message))return;
  setBusy(true);setError('');setSuccess('');
  try{
   const url='/api/security/reviewers/'+encodeURIComponent(item.id)+
    (action==='status'?'/status':'/revoke-sessions');
   const response=await authenticatedFetch(url,{
    method:action==='status'?'PATCH':'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(action==='status'?{status:newStatus}:{})
   });
   const result=await parse<{revokedSessions:number;eventType:string}>(response);
   setSuccess(result.eventType+' recorded. '+result.revokedSessions+' session(s) revoked.');
   await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Operation failed');}
  finally{setBusy(false);}
 }
 return <section className="border border-slate-700 rounded-xl bg-slate-900 p-5 space-y-5" aria-label="Reviewer account security">
  <div>
   <h2 className="text-lg font-semibold text-white">Reviewer account security</h2>
   <p className="text-sm text-slate-400">Owner-only account status and session revocation controls. No password or token values are displayed.</p>
  </div>
  {error&&<p role="alert" className="text-rose-200 text-sm">{error}</p>}
  {success&&<p role="status" className="text-emerald-200 text-sm">{success}</p>}
  <button type="button" onClick={()=>void refresh().catch(e=>setError(String(e)))} disabled={busy}
   className="text-cyan-300 text-sm disabled:opacity-50">Refresh security data</button>
  <div className="space-y-2">
   {reviewers.length===0&&<p className="text-slate-400 text-sm">No reviewers provisioned. Use the restricted provisioning CLI.</p>}
   {reviewers.map(item=><div key={item.id} className="rounded-lg border border-slate-700 p-3 flex flex-wrap gap-3 items-center justify-between">
    <div><p className="font-medium text-sm">{item.full_name} · {item.email}</p>
     <p className="text-xs text-slate-400">{item.status} · {item.active_sessions} active session(s)</p></div>
    <div className="flex flex-wrap gap-2">
     <button type="button" disabled={busy} className="border border-amber-600 text-amber-200 rounded px-3 py-2 text-xs disabled:opacity-40"
      onClick={()=>void change(item,'status')}>{item.status==='ACTIVE'?'Disable account':'Reactivate account'}</button>
     <button type="button" disabled={busy} className="border border-slate-600 rounded px-3 py-2 text-xs disabled:opacity-40"
      onClick={()=>void change(item,'revoke')}>Revoke sessions</button>
    </div>
   </div>)}
  </div>
  <div className="border-t border-slate-700 pt-3 space-y-2">
   <h3 className="font-medium text-sm">Recent security events</h3>
   {events.length===0&&<p className="text-xs text-slate-500">No events yet.</p>}
   {events.map(item=><p className="text-xs text-slate-400" key={item.id}>
    {item.event_type} · {item.revoked_session_count} sessions · {new Date(item.created_at).toLocaleString()} · user {item.target_user_id}
   </p>)}
  </div>
  <p className="text-amber-300 text-xs">MFA is not enabled. Reauthentication, reviewer recovery and SIEM integration must be added before production release.</p>
 </section>;
}
