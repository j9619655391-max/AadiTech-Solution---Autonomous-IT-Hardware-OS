import React,{useEffect,useState} from 'react';
import {BookOpen,Search,ShieldAlert,AlertTriangle,RefreshCw,ChevronDown} from 'lucide-react';
import {authenticatedFetch} from '../services/authClient';
import type {TroubleGuide,TroubleCategory} from '../../server/troubleshooting/guides';

const categories:{id:TroubleCategory|'',label:string}[]=[
 {id:'',label:'All topics'},
 {id:'PERFORMANCE',label:'Performance'},
 {id:'NETWORK',label:'Wi-Fi and network'},
 {id:'SYSTEM',label:'Windows system'},
 {id:'HARDWARE',label:'Devices and hardware'},
 {id:'SECURITY',label:'Security'},
 {id:'APPLICATION',label:'Applications'},
 {id:'PRIVACY',label:'Privacy'}
];
type CatalogResponse={mode:'GUIDANCE_ONLY';deviceInspected:false;actionsExecuted:false;
 total:number;items:TroubleGuide[]};

export function WindowsTroubleshootingWorkspace(){
 const [draftQuery,setDraftQuery]=useState('');
 const [query,setQuery]=useState('');
 const [category,setCategory]=useState<TroubleCategory|''>('');
 const [items,setItems]=useState<TroubleGuide[]>([]);
 const [expanded,setExpanded]=useState<string|null>(null);
 const [loading,setLoading]=useState(true);
 const [error,setError]=useState('');
 const [version,setVersion]=useState(0);
 useEffect(()=>{
  const abort=new AbortController();
  const load=async()=>{
   setLoading(true);setError('');
   try{
    const params=new URLSearchParams();
    if(query)params.set('q',query);
    if(category)params.set('category',category);
    const url='/api/help/troubleshooting'+(params.size?'?'+params.toString():'');
    const response=await authenticatedFetch(url,{signal:abort.signal});
    if(!response.ok)throw new Error(response.status===401?
     'Sign in to view the troubleshooting guides.':'Unable to load the internal guides.');
    const data=await response.json() as CatalogResponse;
    if(data.mode!=='GUIDANCE_ONLY'||data.deviceInspected!==false||
       data.actionsExecuted!==false||!Array.isArray(data.items))
     throw Error('Unverified troubleshooting response');
    if(!abort.signal.aborted){setItems(data.items);setExpanded(null);}
   }catch(e){
    if(!abort.signal.aborted){setError(e instanceof Error?e.message:'Unable to load guides');setItems([]);}
   }finally{if(!abort.signal.aborted)setLoading(false);}
  };
  void load();
  return ()=>abort.abort();
 },[query,category,version]);
 const search=()=>setQuery(draftQuery.trim());
 const clear=()=>{setDraftQuery('');setQuery('');setCategory('');setExpanded(null);};
 return <section className="space-y-5" aria-label="Windows troubleshooting guidance">
  <div className="rounded-xl border border-cyan-800/60 bg-slate-900 p-5">
   <div className="flex items-center gap-2">
    <BookOpen className="h-5 w-5 text-cyan-400" aria-hidden="true"/>
    <h2 className="text-lg font-semibold text-white">Windows Troubleshooting</h2>
   </div>
   <p className="mt-2 text-sm text-slate-300">
    Internal knowledge-base for common Windows 10/11 problems. Choose a topic to see
    first checks, warning signs and when to contact a technician.
   </p>
   <p className="mt-3 flex gap-2 text-xs text-amber-300" role="note">
    <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true"/>
    Guidance only — no device has been inspected, no commands or repairs are executed,
    and no ticket, customer message or diagnostic evidence is created.
   </p>
  </div>
  <form className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4 sm:flex-row sm:items-end"
   onSubmit={e=>{e.preventDefault();search();}}>
   <label className="flex-1 text-sm text-slate-300">Search symptoms
    <input className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
     type="search" maxLength={120} value={draftQuery}
     placeholder="e.g. Wi-Fi no internet, blue screen, printer"
     onChange={e=>setDraftQuery(e.target.value)}/>
   </label>
   <label className="text-sm text-slate-300">Category
    <select className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
     value={category} onChange={e=>setCategory(e.target.value as TroubleCategory|'')}>
     {categories.map(item=><option key={item.id} value={item.id}>{item.label}</option>)}
    </select>
   </label>
   <div className="flex gap-2">
    <button type="submit" className="inline-flex items-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600">
     <Search className="h-4 w-4" aria-hidden="true"/>Search
    </button>
    <button type="button" onClick={clear} className="rounded-lg border border-slate-600 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800">
     Clear
    </button>
    <button type="button" onClick={()=>setVersion(v=>v+1)} aria-label="Refresh troubleshooting guides"
     className="rounded-lg border border-slate-600 p-2 text-slate-200 hover:bg-slate-800">
     <RefreshCw className="h-4 w-4" aria-hidden="true"/>
    </button>
   </div>
  </form>
  {loading&&<p className="text-sm text-slate-400" role="status">Loading troubleshooting guides…</p>}
  {error&&<p className="rounded-lg border border-rose-700 bg-rose-950/40 p-3 text-sm text-rose-200" role="alert">{error}</p>}
  {!loading&&!error&&<>
   <p className="text-sm text-slate-400" role="status">{items.length} matching troubleshooting topic{items.length===1?'':'s'}.</p>
   {items.length===0&&<p className="rounded-lg border border-slate-700 p-4 text-sm text-slate-300">
    No matching guide. Try another symptom, or refer the issue to an authorized technician.
   </p>}
   <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
    {items.map(item=>{
     const isOpen=expanded===item.id;
     return <article key={item.id} className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      <button type="button" aria-expanded={isOpen} aria-controls={'guide-'+item.id}
       onClick={()=>setExpanded(isOpen?null:item.id)}
       className="flex w-full items-start justify-between gap-2 text-left">
       <span>
        <span className="block text-[11px] font-semibold uppercase tracking-wide text-cyan-300">{item.category.replaceAll('_',' ')}</span>
        <span className="mt-1 block font-semibold text-white">{item.title}</span>
        <span className="mt-1 block text-xs leading-relaxed text-slate-400">{item.summary}</span>
       </span>
       <ChevronDown className={'h-5 w-5 shrink-0 text-slate-300 transition-transform '+(isOpen?'rotate-180':'')}
        aria-hidden="true"/>
      </button>
      {isOpen&&<div id={'guide-'+item.id} className="mt-4 space-y-4 border-t border-slate-700 pt-4 text-sm">
       <div>
        <h3 className="font-semibold text-slate-200">Safe first checks</h3>
        <ol className="mt-2 list-decimal space-y-2 pl-5 text-slate-300">{item.firstChecks.map((step,i)=><li key={i}>{step}</li>)}</ol>
       </div>
       <div>
        <h3 className="font-semibold text-slate-200">Escalate to a technician when</h3>
        <ul className="mt-2 list-disc space-y-2 pl-5 text-slate-300">{item.escalateWhen.map((step,i)=><li key={i}>{step}</li>)}</ul>
       </div>
       <p className="flex gap-2 rounded-lg border border-amber-800/60 bg-amber-950/30 p-3 text-xs leading-relaxed text-amber-200">
        <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true"/>{item.caution}
       </p>
      </div>}
     </article>;
    })}
   </div>
  </>}
 </section>;
}
