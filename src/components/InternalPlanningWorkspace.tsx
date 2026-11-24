import React,{useEffect,useState} from 'react';
import {planningCatalog} from '../services/internalPlanningCatalog';
import {internalPlanningClient,type PlanningRecord,type PlanningResult} from '../services/internalPlanningClient';
export function InternalPlanningWorkspace({modules}:{modules:readonly string[]}){
 const choices=planningCatalog.filter(x=>modules.includes(x.id));
 const [module,setModule]=useState(choices[0]?.id??''),[input,setInput]=useState(''),[result,setResult]=useState<PlanningResult|null>(null);
 const [records,setRecords]=useState<PlanningRecord[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[key,setKey]=useState('');
 const [available,setAvailable]=useState<string[]>([]),[persistence,setPersistence]=useState(false);
 useEffect(()=>{let active=true;internalPlanningClient.catalog().then(v=>{if(active){setAvailable(v.modules);setPersistence(v.persistenceEnabled);}}).catch(()=>{if(active)setError('Planning service unavailable.');});return()=>{active=false;};},[]);
 const reset=()=>{setResult(null);setKey('');setNotice('');setError('');};
 async function run(save:boolean){setBusy(true);setError('');setNotice('');setResult(null);
  try{if(input.length>65536)throw Error('Input exceeds planning limit');const payload:unknown=JSON.parse(input);
   if(save){const requestKey=key||crypto.randomUUID();setKey(requestKey);const v=await internalPlanningClient.save(module,payload,requestKey);setResult(v.result);setNotice((v.replayed?'Existing held record: ':'Saved held record: ')+v.id);}
   else{setResult(await internalPlanningClient.evaluate(module,payload));setNotice('Server-side unverified planning result.');}
  }catch(e){setError(e instanceof Error?e.message:'Planning request failed');}finally{setBusy(false);}}
 async function list(){setBusy(true);setError('');setRecords([]);try{setRecords(await internalPlanningClient.list());}catch(e){setError(e instanceof Error?e.message:'List failed');}finally{setBusy(false);}}
 async function open(id:string){setBusy(true);setError('');setResult(null);try{const v=await internalPlanningClient.read(id);setResult(v.result);setNotice('Held record '+v.id+' ('+v.module+')');}catch(e){setError(e instanceof Error?e.message:'Read failed');}finally{setBusy(false);}}
 if(!choices.length)return null;
 return <section className="mb-5 rounded-xl border border-slate-700 bg-slate-900 p-4 text-slate-100 space-y-3" aria-label="Server-side internal planning">
 <h2 className="text-lg font-semibold">Server-side internal planning — HOLD</h2>
 <p className="text-sm text-slate-300">Unverified operator scenarios only. No external action, payment, official invoice or dispatch. Saving is enabled only in disposable CI.</p>
 <label className="block text-sm">Planning module<select className="block mt-1 p-2 bg-slate-800 border border-slate-600 rounded w-full" value={module} disabled={busy} onChange={e=>{setModule(e.target.value);setInput('');reset();}}>{choices.map(x=><option key={x.id} value={x.id}>{x.id} — {x.name}</option>)}</select></label>
 <button type="button" className="text-sm underline" disabled={busy} onClick={()=>{setInput(JSON.stringify(choices.find(x=>x.id===module)?.example??{},null,2));reset();setNotice('Synthetic example loaded. Replace with reviewed scenario inputs.');}}>Load synthetic example</button>
 <label className="block text-sm">Scenario JSON<textarea className="block w-full mt-1 min-h-48 font-mono text-sm bg-slate-950 border border-slate-600 rounded p-2" value={input} disabled={busy} maxLength={65536} onChange={e=>{setInput(e.target.value);reset();}} placeholder="Enter scenario JSON or load a synthetic example"/></label>
 <div className="flex flex-wrap gap-2">
 <button type="button" className="rounded bg-cyan-800 px-3 py-2 disabled:opacity-50" disabled={busy||!available.includes(module)||!input.trim()} onClick={()=>void run(false)}>Evaluate scenario</button>
 <button type="button" className="rounded bg-slate-700 px-3 py-2 disabled:opacity-50" disabled={busy||!persistence||!available.includes(module)||!input.trim()} onClick={()=>void run(true)}>Save held record (CI only)</button>
 <button type="button" className="rounded bg-slate-700 px-3 py-2 disabled:opacity-50" disabled={busy||!persistence} onClick={()=>void list()}>My held records (CI only)</button></div>
 {busy&&<p role="status">Request in progress</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="text-red-300">{error}</p>}{result&&<pre className="overflow-auto whitespace-pre-wrap break-words bg-slate-950 rounded p-3 text-xs">{JSON.stringify(result,null,2)}</pre>}
 {records.filter(v=>modules.includes(v.module)).map(v=><button type="button" className="block underline text-sm" key={v.id} disabled={busy} onClick={()=>void open(v.id)}>{v.module} — {v.id}</button>)}</section>;
}
