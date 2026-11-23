import React,{useCallback,useEffect,useState} from 'react';
import {ClipboardList,RefreshCw,ShieldAlert} from 'lucide-react';
import {authenticatedFetch} from '../services/authClient';
import {crmClient,type CRMRecord} from '../services/crmClient';

type Status='OPEN_INTERNAL'|'TRIAGED_INTERNAL'|'WAITING_INTERNAL'|'RESOLVED_HELD';
type Priority='LOW'|'NORMAL'|'HIGH';
type Ticket={
 id:string;customerId:string;customerName?:string;guideId:string;
 subject:string;description:string;priority:Priority;status:Status;
 version:number;customerConsentState:'UNVERIFIED';externalDispatchState:'DISABLED';
 subjectRedacted?:boolean;descriptionRedacted?:boolean;
};
type History={operation:'CREATE'|'STATUS_CHANGE';fromStatus:Status|null;toStatus:Status;
 note:string;versionAfter:number;createdAt:string;noteRedacted?:boolean};
type Catalog={mode:'GUIDANCE_ONLY';items:{id:string;title:string}[]};
type TicketList={items:Ticket[];limit:100;hasMore:boolean;
 nextBeforeCreatedAt:string|null;nextBeforeId:string|null;
 mode:'INTERNAL_HELD';externalDispatchEnabled:false};
type TicketDetail={ticket:Ticket;history:History[];historyLimit:number;historyHasMore:boolean;
 nextBeforeVersion:number|null;mode:'INTERNAL_HELD';externalDispatchEnabled:false};
type HistoryPage={ticketId:string;history:History[];historyLimit:number;historyHasMore:boolean;
 nextBeforeVersion:number|null;mode:'INTERNAL_HELD';externalDispatchEnabled:false};
type InternalAuditFingerprint={ticketId:string;algorithm:'SHA-256';
 format:'aaditech/internal-ticket-audit/sha256/v1';auditDigestSha256:string;
 eventCount:number;latestVersion:number;scope:'APPLICATION_UNATTESTED';
 signatureVerified:false;externalAnchorVerified:false;customerConsentVerified:false;
 mode:'INTERNAL_HELD';externalDispatchEnabled:false};
const nextStates:Record<Status,{status:Status;label:string}[]>={
 OPEN_INTERNAL:[{status:'TRIAGED_INTERNAL',label:'Triaged (internal)'}],
 TRIAGED_INTERNAL:[
  {status:'WAITING_INTERNAL',label:'Waiting for internal information'},
  {status:'RESOLVED_HELD',label:'Resolved internally — held / unverified'}],
 WAITING_INTERNAL:[{status:'TRIAGED_INTERNAL',label:'Resume internal triage'}],
 RESOLVED_HELD:[]
};
async function responseBody<T>(response:Response):Promise<T>{
 const raw:unknown=await response.json().catch(()=>null);
 if(!response.ok){
  const error=raw&&typeof raw==='object'&&'error' in raw?String(raw.error):'Service request failed';
  throw Error(error);
 }
 return raw as T;
}
export function LiveServiceDeskWorkspace(){
 const [tickets,setTickets]=useState<Ticket[]>([]);
 const [ticketCursor,setTicketCursor]=useState<{createdAt:string;id:string}|null>(null);
 const [ticketsOlderPage,setTicketsOlderPage]=useState(false);
 const [customers,setCustomers]=useState<CRMRecord[]>([]);
 const [guides,setGuides]=useState<{id:string;title:string}[]>([]);
 const [customerId,setCustomerId]=useState('');
 const [guideId,setGuideId]=useState('pc-slow');
 const [subject,setSubject]=useState('');
 const [description,setDescription]=useState('');
 const [priority,setPriority]=useState<Priority>('NORMAL');
 const [acknowledge,setAcknowledge]=useState(false);
 const [selectedId,setSelectedId]=useState('');
 const [detail,setDetail]=useState<TicketDetail|null>(null);
 const [nextStatus,setNextStatus]=useState<Status|' '>(' ');
 const [transitionNote,setTransitionNote]=useState('');
 const [busy,setBusy]=useState(false);
 const [loadingHistory,setLoadingHistory]=useState(false);
 const [fingerprintBusy,setFingerprintBusy]=useState(false);
 const [fingerprint,setFingerprint]=useState<InternalAuditFingerprint|null>(null);
 const [historyIsLatest,setHistoryIsLatest]=useState(true);
 const [loading,setLoading]=useState(true);
 const [loadingOlderTickets,setLoadingOlderTickets]=useState(false);
 const [error,setError]=useState('');
 const [success,setSuccess]=useState('');
 const [customerTruncated,setCustomerTruncated]=useState(false);
 const verifyList=(list:TicketList)=>{
  if(list.mode!=='INTERNAL_HELD'||list.externalDispatchEnabled!==false||
     list.limit!==100||!Array.isArray(list.items)||list.items.length>100||
     typeof list.hasMore!=='boolean'||
     (list.hasMore&&(!list.nextBeforeCreatedAt||!list.nextBeforeId))||
     (!list.hasMore&&(list.nextBeforeCreatedAt!==null||list.nextBeforeId!==null)))
   throw Error('Unverified bounded internal ticket list');
  return list;
 };
 const refresh=useCallback(async()=>{
  setLoading(true);setError('');
  try{
   const [list,crm,catalog]=await Promise.all([
    responseBody<TicketList>(await authenticatedFetch('/api/service-desk/internal-tickets')),
    crmClient.list('customers',1,100),
    responseBody<Catalog>(await authenticatedFetch('/api/help/troubleshooting'))
   ]);
   verifyList(list);
   if(catalog.mode!=='GUIDANCE_ONLY')throw Error('Unverified troubleshooting catalog');
   setTickets(list.items);
   setTicketCursor(list.hasMore?{createdAt:list.nextBeforeCreatedAt!,id:list.nextBeforeId!}:null);
   setTicketsOlderPage(false);
   setCustomers(crm.items);setGuides(catalog.items);
   setCustomerTruncated(crm.total>100);
   setCustomerId(prev=>prev&&crm.items.some(c=>c.id===prev)?prev:crm.items[0]?.id??'');
  }catch(e){setError(e instanceof Error?e.message:'Service desk unavailable');}
  finally{setLoading(false);}
 },[]);
 useEffect(()=>{void refresh();},[refresh]);
 const loadOlderTickets=async()=>{
  if(!ticketCursor||loadingOlderTickets||loading)return;
  const cursor=ticketCursor;
  setLoadingOlderTickets(true);setError('');
  try{
   const page=verifyList(await responseBody<TicketList>(await authenticatedFetch(
    '/api/service-desk/internal-tickets?beforeCreatedAt='+
    encodeURIComponent(cursor.createdAt)+'&beforeId='+encodeURIComponent(cursor.id))));
   if(page.items.length===0||
      (page.hasMore&&(
       page.nextBeforeCreatedAt!>cursor.createdAt||
       page.nextBeforeCreatedAt===cursor.createdAt&&page.nextBeforeId!>=cursor.id)))
    throw Error('Non-decreasing internal ticket list cursor');
   setTickets(page.items);
   setTicketCursor(page.hasMore?{createdAt:page.nextBeforeCreatedAt!,id:page.nextBeforeId!}:null);
   setTicketsOlderPage(true);
  }catch(e){setError(e instanceof Error?e.message:'Older internal tickets unavailable');}
  finally{setLoadingOlderTickets(false);}
 };
 const openTicket=async(id:string)=>{
  setError('');setSuccess('');
  try{
   const data=await responseBody<TicketDetail>(await authenticatedFetch(
    '/api/service-desk/internal-tickets/'+encodeURIComponent(id)));
   if(data.mode!=='INTERNAL_HELD'||data.externalDispatchEnabled!==false)
    throw Error('Unverified internal ticket response');
   setSelectedId(id);setDetail(data);setFingerprint(null);setHistoryIsLatest(true);setNextStatus(' ');setTransitionNote('');
  }catch(e){setError(e instanceof Error?e.message:'Ticket unavailable');}
 };
 const loadOlderHistory=async()=>{
  if(!detail||!detail.historyHasMore||detail.nextBeforeVersion===null||loadingHistory)return;
  const ticketId=detail.ticket.id,cursor=detail.nextBeforeVersion;
  setLoadingHistory(true);setError('');
  try{
   const response=await authenticatedFetch('/api/service-desk/internal-tickets/'+
    encodeURIComponent(ticketId)+'/history?beforeVersion='+cursor);
   const page=await responseBody<HistoryPage>(response);
   if(page.mode!=='INTERNAL_HELD'||page.externalDispatchEnabled!==false||
      page.ticketId!==ticketId||page.historyLimit!==100||!Array.isArray(page.history)||
      page.history.length>100||
      page.history.some(e=>!Number.isSafeInteger(e.versionAfter)||e.versionAfter>=cursor)||
      (page.historyHasMore&&(page.nextBeforeVersion===null||page.nextBeforeVersion>=cursor)))
    throw Error('Invalid bounded history response');
   setDetail(prev=>prev?.ticket.id===ticketId?{...prev,history:page.history,
    historyLimit:page.historyLimit,historyHasMore:page.historyHasMore,
    nextBeforeVersion:page.nextBeforeVersion}:prev);
   setHistoryIsLatest(false);
  }catch(e){setError(e instanceof Error?e.message:'Older audit history unavailable');}
  finally{setLoadingHistory(false);}
 };
 const computeFingerprint=async()=>{
  if(!detail||fingerprintBusy)return;
  const ticketId=detail.ticket.id,version=detail.ticket.version;
  setFingerprintBusy(true);setError('');setFingerprint(null);
  try{
   const data=await responseBody<InternalAuditFingerprint>(await authenticatedFetch(
    '/api/service-desk/internal-tickets/'+encodeURIComponent(ticketId)+'/audit-fingerprint'));
   if(data.ticketId!==ticketId||data.latestVersion!==version||data.mode!=='INTERNAL_HELD'||
      data.externalDispatchEnabled!==false||data.scope!=='APPLICATION_UNATTESTED'||
      data.signatureVerified!==false||data.externalAnchorVerified!==false||
      data.customerConsentVerified!==false||data.algorithm!=='SHA-256'||
      data.format!=='aaditech/internal-ticket-audit/sha256/v1'||
      !/^[a-f0-9]{64}$/.test(data.auditDigestSha256)||
      !Number.isSafeInteger(data.eventCount)||data.eventCount!==version||data.eventCount>1000)
    throw Error('Unsigned internal audit fingerprint response invalid');
   setFingerprint(data);
  }catch(e){setError(e instanceof Error?e.message:'Internal audit fingerprint unavailable');}
  finally{setFingerprintBusy(false);}
 };
 const createTicket=async(event:React.FormEvent)=>{
  event.preventDefault();
  if(!acknowledge){setError('Acknowledge that customer consent is not verified.');return;}
  setBusy(true);setError('');setSuccess('');
  try{
   const response=await authenticatedFetch('/api/service-desk/internal-tickets',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({customerId,guideId,subject,description,priority,
     acknowledgeUnverifiedConsent:true})
   });
   const created=await responseBody<{ticket:Ticket;mode:'INTERNAL_HELD';externalDispatchEnabled:false}>(response);
   if(created.mode!=='INTERNAL_HELD'||created.externalDispatchEnabled!==false)
    throw Error('Unverified ticket creation result');
   setSubject('');setDescription('');setAcknowledge(false);
   setSuccess('Internal ticket saved; no customer message or repair was performed.');
   await refresh();
   await openTicket(created.ticket.id);
  }catch(e){setError(e instanceof Error?e.message:'Ticket creation failed');}
  finally{setBusy(false);}
 };
 const updateStatus=async(event:React.FormEvent)=>{
  event.preventDefault();if(!detail||nextStatus===' ')return;
  setBusy(true);setError('');setSuccess('');
  try{
   const response=await authenticatedFetch(
    '/api/service-desk/internal-tickets/'+encodeURIComponent(detail.ticket.id)+'/status',{
     method:'PATCH',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({expectedVersion:detail.ticket.version,nextStatus,note:transitionNote})
    });
   await responseBody(response);
   await refresh();
   await openTicket(detail.ticket.id);
   setSuccess('Internal status and versioned audit recorded. No external service action.');
  }catch(e){setError(e instanceof Error?e.message:'Unable to update ticket');}
  finally{setBusy(false);}
 };
 return <section className="space-y-5" aria-label="Internal service ticket workspace">
  <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
   <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
    <ClipboardList className="h-5 w-5 text-cyan-400" aria-hidden="true"/>Internal Service Desk — M16
   </h2>
   <p className="mt-2 text-sm text-slate-300">
    Owner-only internal ticket notes for CRM customers. No customer consent, contractual SLA,
    technician assignment, warranty claim or completed repair has been independently verified.
   </p>
   <p className="mt-2 text-xs text-slate-300" role="note">
    Never paste passwords, access tokens, private keys or session cookies into subject, observations
    or audit notes. Recognizable credential strings are rejected by the server, but this check cannot
    guarantee detection of every secret or personal identifier.
   </p>
   <p className="mt-2 flex gap-2 text-sm text-amber-200" role="note">
    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true"/>
    HARD HOLD: customer contact, external dispatch and automatic repair are disabled.
    This is not a live customer-support portal.
   </p>
  </div>
  {error&&<p role="alert" className="rounded-lg border border-rose-700 bg-rose-950/50 p-3 text-sm text-rose-200">{error}</p>}
  {success&&<p role="status" className="rounded-lg border border-slate-700 p-3 text-sm text-cyan-300">{success}</p>}
  <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
   <form onSubmit={createTicket} className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
    <h3 className="font-semibold text-white">Create an internal ticket</h3>
    <label className="block text-xs text-slate-300">Customer (owner-scoped CRM)
     <select required value={customerId} onChange={e=>setCustomerId(e.target.value)}
      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white">
      {!customers.length&&<option value="">No eligible CRM customers</option>}
      {customers.map(c=><option key={c.id} value={c.id}>{String(c.name??c.id)}</option>)}
     </select>
    </label>
    {customerTruncated&&<p className="text-xs text-amber-300">Showing the first 100 CRM customers. Filter your CRM catalog before using a customer beyond this list.</p>}
    <label className="block text-xs text-slate-300">Troubleshooting topic
     <select required value={guideId} onChange={e=>setGuideId(e.target.value)}
      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white">
      {guides.map(g=><option key={g.id} value={g.id}>{g.title}</option>)}
     </select>
    </label>
    <label className="block text-xs text-slate-300">Priority (internal only)
     <select value={priority} onChange={e=>setPriority(e.target.value as Priority)}
      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white">
      <option value="LOW">Low</option><option value="NORMAL">Normal</option><option value="HIGH">High</option>
     </select>
    </label>
    <label className="block text-xs text-slate-300">Subject
     <input required maxLength={180} value={subject} onChange={e=>setSubject(e.target.value)}
      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white"/>
    </label>
    <label className="block text-xs text-slate-300">Observations (avoid sensitive credentials)
     <textarea required maxLength={2000} rows={3} value={description}
      onChange={e=>setDescription(e.target.value)}
      className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white"/>
    </label>
    <label className="flex items-start gap-2 text-xs text-slate-300">
     <input type="checkbox" checked={acknowledge} onChange={e=>setAcknowledge(e.target.checked)}
      className="mt-0.5"/>
     I understand that this ticket is an unverified internal observation; customer consent and SLA are NOT confirmed.
    </label>
    <button type="submit" disabled={busy||loading||!customerId||!acknowledge||!guides.length}
     className="rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
     Save internal ticket
    </button>
   </form>
   <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
    <div className="flex items-center justify-between">
     <h3 className="font-semibold text-white">Owner-scoped internal tickets</h3>
     <button type="button" onClick={()=>void refresh()} aria-label="Refresh internal tickets"
      className="rounded border border-slate-700 p-2 text-slate-200">
      <RefreshCw className="h-4 w-4" aria-hidden="true"/>
     </button>
    </div>
    {loading?<p className="text-sm text-slate-400">Loading internal tickets…</p>:
     tickets.length===0?<p className="text-sm text-slate-400">No internal tickets.</p>:
     <ul className="max-h-[420px] space-y-2 overflow-y-auto">
      {tickets.map(ticket=><li key={ticket.id}>
       <button type="button" onClick={()=>void openTicket(ticket.id)}
        className={'w-full rounded-lg border p-3 text-left '+(selectedId===ticket.id?
         'border-cyan-600 bg-slate-800':'border-slate-700 bg-slate-950 hover:bg-slate-800')}>
        <span className="block text-sm font-semibold text-white">{ticket.subject}</span>
        <span className="mt-1 block text-xs text-slate-400">{ticket.customerName??'Scoped CRM customer'} · {ticket.status.replaceAll('_',' ')} · v{ticket.version}</span>
       </button>
      </li>)}
     </ul>}
    <p className="text-xs text-slate-400">Showing {ticketsOlderPage?'older':'latest'} {tickets.length} internal tickets (100-page cap). External delivery DISABLED.</p>
    <div className="flex flex-wrap gap-2">
     {ticketCursor&&<button type="button" disabled={loading||loadingOlderTickets}
      onClick={()=>void loadOlderTickets()}
      className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-100 disabled:opacity-50">
      {loadingOlderTickets?'Loading…':'Load older 100 tickets'}
     </button>}
     {ticketsOlderPage&&<button type="button" disabled={loading||loadingOlderTickets}
      onClick={()=>void refresh()}
      className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-100 disabled:opacity-50">
      Return to latest tickets
     </button>}
    </div>
   </div>
  </div>
  {detail&&<div className="space-y-4 rounded-xl border border-slate-700 bg-slate-900 p-5">
   <h3 className="font-semibold text-white">{detail.ticket.subject}</h3>
   {(detail.ticket.subjectRedacted||detail.ticket.descriptionRedacted)&&
    <p className="text-xs text-amber-300" role="note">
     Potential legacy credential material masked by this application read. Stored source audit remains unchanged; omit secrets in future records.
    </p>}
   <p className="text-sm text-slate-300">{detail.ticket.description}</p>
   <p className="text-xs text-amber-300">Status: {detail.ticket.status} · Version: {detail.ticket.version} · Consent: UNVERIFIED · Dispatch: DISABLED</p>
   {nextStates[detail.ticket.status].length>0&&
    <form onSubmit={updateStatus} className="grid gap-3 sm:grid-cols-[1fr_2fr_auto] sm:items-end">
     <label className="text-xs text-slate-300">Internal next status
      <select value={nextStatus} onChange={e=>setNextStatus(e.target.value as Status|' ')}
       className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white">
       <option value=" ">Choose status</option>
       {nextStates[detail.ticket.status].map(n=><option key={n.status} value={n.status}>{n.label}</option>)}
      </select>
     </label>
     <label className="text-xs text-slate-300">Audit note (no secrets)
      <input value={transitionNote} onChange={e=>setTransitionNote(e.target.value)}
       maxLength={500} required className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-white"/>
     </label>
     <button type="submit" disabled={busy||nextStatus===' '||!transitionNote.trim()}
      className="rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">Record status</button>
    </form>}
   <div className="space-y-2 rounded-lg border border-slate-700 bg-slate-950 p-3">
    <p className="text-xs text-amber-300">Optional internal database fingerprint only. Not an independent signature, immutable/WORM attestation, or verified customer consent.</p>
    <button type="button" disabled={fingerprintBusy||busy} onClick={()=>void computeFingerprint()}
     className="rounded border border-slate-600 px-3 py-1.5 text-xs text-slate-100 disabled:opacity-50">
     {fingerprintBusy?'Checking bounded ledger…':'Compute unsigned audit fingerprint'}
    </button>
    {fingerprint?.ticketId===detail.ticket.id&&<div className="space-y-1 text-xs text-slate-300">
     <p>Internal events checked: {fingerprint.eventCount} · SHA-256, application-generated · Signature: NOT VERIFIED</p>
     <p className="break-all font-mono" aria-label="Unsigned internal audit SHA-256 fingerprint">{fingerprint.auditDigestSha256}</p>
    </div>}
   </div>
   <h4 className="text-sm font-semibold text-white">Versioned internal audit</h4>
   <p className="text-xs text-slate-400">Showing {historyIsLatest?'latest':'older'} {detail.history.length} internal audit entries (limit {detail.historyLimit}). {detail.historyHasMore?'Earlier entries remain.':'No earlier entries reported by this bounded read.'} This is a single page, not immutable external evidence.</p>
   <div className="flex flex-wrap gap-2">
    {detail.historyHasMore&&<button type="button" disabled={loadingHistory||busy}
     onClick={()=>void loadOlderHistory()}
     className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-100 disabled:opacity-50">
     {loadingHistory?'Loading…':'Load older 100 entries'}
    </button>}
    {!historyIsLatest&&<button type="button" disabled={loadingHistory||busy}
     onClick={()=>void openTicket(detail.ticket.id)}
     className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-100 disabled:opacity-50">Return to latest</button>}
   </div>
   <ol className="space-y-1 text-xs text-slate-300">
    {detail.history.map(e=><li key={e.versionAfter} className="rounded border border-slate-800 p-2">
     v{e.versionAfter} · {e.operation} · {e.toStatus} · {e.note}{e.noteRedacted?' (legacy credential risk masked)':''}
    </li>)}
   </ol>
  </div>}
 </section>;
}
