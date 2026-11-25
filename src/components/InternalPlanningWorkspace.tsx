import React,{useEffect,useState} from 'react';
import {planningCatalog} from '../services/internalPlanningCatalog';
import {blankForm,encodeForm,exampleForm} from '../services/internalPlanningForms';
import {InternalPlanningFields} from './InternalPlanningFields';
import {InternalPlanningResultView} from './InternalPlanningResultView';
import {internalPlanningClient,type PlanningRecord,type PlanningResult} from '../services/internalPlanningClient';
export function InternalPlanningWorkspace({modules}:{modules:readonly string[]}){
 const choices=planningCatalog.filter(x=>modules.includes(x.id));
 const [module,setModule]=useState(choices[0]?.id??''),[draft,setDraft]=useState(()=>blankForm(choices[0]?.id??'M05')),[result,setResult]=useState<PlanningResult|null>(null);
 const [records,setRecords]=useState<PlanningRecord[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[key,setKey]=useState('');
 const [baseline,setBaseline]=useState<PlanningResult|null>(null);
 const [available,setAvailable]=useState<string[]>([]),[persistence,setPersistence]=useState(false);
 useEffect(()=>{let active=true;internalPlanningClient.catalog().then(v=>{if(active){setAvailable(v.modules);setPersistence(v.persistenceEnabled);}}).catch(()=>{if(active)setError('Planning service unavailable.');});return()=>{active=false;};},[]);
 const reset=()=>{setResult(null);setKey('');setNotice('');setError('');};
 async function run(save:boolean){setBusy(true);setError('');setNotice('');setResult(null);
  try{const payload=encodeForm(module,draft);
   if(save){const requestKey=key||crypto.randomUUID();setKey(requestKey);const v=await internalPlanningClient.save(module,payload,requestKey);setResult(v.result);setNotice((v.replayed?'Existing held record: ':'Saved held record: ')+v.id);}
   else{setResult(await internalPlanningClient.evaluate(module,payload));setNotice('Server-side unverified planning result.');}
  }catch(e){setError(e instanceof Error?e.message:'Planning request failed');}finally{setBusy(false);}}
 async function list(){setBusy(true);setError('');setRecords([]);try{setRecords(await internalPlanningClient.list());}catch(e){setError(e instanceof Error?e.message:'List failed');}finally{setBusy(false);}}
 async function open(id:string){setBusy(true);setError('');setResult(null);try{const v=await internalPlanningClient.read(id);setResult(v.result);setNotice('Held record '+v.id+' ('+v.module+')');}catch(e){setError(e instanceof Error?e.message:'Read failed');}finally{setBusy(false);}}
 if(!choices.length)return null;
 return <section className="mb-5 rounded-xl border border-slate-700 bg-slate-900 p-4 text-slate-100 space-y-3" aria-label="Server-side internal planning">
 <h2 className="text-lg font-semibold">Server-side internal planning — HOLD</h2>
 <p className="text-sm text-slate-300">Unverified operator scenarios only. No external action, payment, official invoice or dispatch. Saving is enabled only in disposable CI.</p>
 <label className="block text-sm">Planning module<select className="block mt-1 p-2 bg-slate-800 border border-slate-600 rounded w-full" value={module} disabled={busy} onChange={e=>{setModule(e.target.value);setDraft(blankForm(e.target.value));setBaseline(null);reset();}}>{choices.map(x=><option key={x.id} value={x.id}>{x.id} — {x.name}</option>)}</select></label>
 <button type="button" className="text-sm underline" disabled={busy} onClick={()=>{setDraft(exampleForm(module,choices.find(x=>x.id===module)?.example??{}));reset();setNotice('Synthetic example loaded. Replace with reviewed scenario inputs.');}}>Load synthetic example</button>
 <InternalPlanningFields module={module} draft={draft} disabled={busy} onChange={v=>{setDraft(v);reset();}}/>
 <button type="button" className="text-sm underline" disabled={busy} onClick={()=>{setDraft(blankForm(module));reset();}}>Clear scenario</button>
 <div className="flex flex-wrap gap-2">
 <button type="button" className="rounded bg-cyan-800 px-3 py-2 disabled:opacity-50" disabled={busy||!available.includes(module)} onClick={()=>void run(false)}>Evaluate scenario</button>
 <button type="button" className="rounded bg-slate-700 px-3 py-2 disabled:opacity-50" disabled={busy||!persistence||!available.includes(module)} onClick={()=>void run(true)}>Save held record (CI only)</button>
 <button type="button" className="rounded bg-slate-700 px-3 py-2 disabled:opacity-50" disabled={busy||!persistence} onClick={()=>void list()}>My held records (CI only)</button></div>
 {busy&&<p role="status">Request in progress</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="text-red-300">{error}</p>}{result&&<InternalPlanningResultView result={result} baseline={baseline} onPin={()=>setBaseline(result)} onClear={()=>setBaseline(null)} />}
 {records.filter(v=>modules.includes(v.module)).map(v=><button type="button" className="block underline text-sm" key={v.id} disabled={busy} onClick={()=>void open(v.id)}>{v.module} — {v.id}</button>)}</section>;
}
