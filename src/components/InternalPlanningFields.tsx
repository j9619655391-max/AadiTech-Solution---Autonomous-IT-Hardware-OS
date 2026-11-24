import React from 'react';
import {formSchemas,blankRow,type Draft,type Scalar} from '../services/internalPlanningForms';
const css='block w-full mt-1 p-2 bg-slate-800 border border-slate-600 rounded text-sm';
function scalar(f:Scalar,v:string,disabled:boolean,change:(v:string)=>void){
 return <label key={f.key} className="block text-sm">{f.label}{f.kind==='select'?<select className={css} value={v} disabled={disabled} onChange={e=>change(e.target.value)}><option value="">Select…</option>{f.options?.map(x=><option key={x} value={x}>{f.boolean?(x==='true'?'Yes':'No'):x}</option>)}</select>:<input className={css} value={v} disabled={disabled} type={f.kind==='date'?'date':f.kind==='month'?'month':'text'} inputMode={f.kind==='integer'?'numeric':f.kind==='decimal'?'decimal':undefined} maxLength={80} onChange={e=>change(e.target.value)}/>}</label>;
}
export function InternalPlanningFields({module,draft,disabled,onChange}:{module:string;draft:Draft;disabled:boolean;onChange:(v:Draft)=>void}){
 const update=(key:string,value:Draft[string])=>onChange({...draft,[key]:value});
 return <div className="space-y-4">{(formSchemas[module]??[]).map(f=>{
  if(f.kind==='rows'){
   const items=draft[f.key] as Record<string,string>[];
   return <fieldset key={f.key} className="border border-slate-700 rounded p-3 space-y-3"><legend>{f.label} ({items.length}/{f.max})</legend>{items.map((row,i)=><div key={i} className="rounded bg-slate-950 p-3"><div className="flex justify-between"><span>Row {i+1}</span><button type="button" disabled={disabled||items.length<=f.min} onClick={()=>update(f.key,items.filter((_,j)=>i!==j))}>Remove row {i+1}</button></div><div className="grid sm:grid-cols-2 gap-2">{f.fields.map(x=>scalar(x,row[x.key],disabled,v=>update(f.key,items.map((a,j)=>j===i?{...a,[x.key]:v}:a))))}</div></div>)}<button type="button" disabled={disabled||items.length>=f.max} onClick={()=>update(f.key,[...items,blankRow(f.fields)])}>Add row</button></fieldset>;
  }
  if(f.kind==='multi'){
   const selected=draft[f.key] as string[];
   return <fieldset key={f.key} className="border border-slate-700 rounded p-3"><legend>{f.label}</legend><div className="grid sm:grid-cols-2 gap-2">{f.options.map(x=><label key={x} className="flex gap-2 text-sm"><input type="checkbox" checked={selected.includes(x)} disabled={disabled} onChange={e=>update(f.key,e.target.checked?[...selected,x]:selected.filter(y=>y!==x))}/>{x}</label>)}</div></fieldset>;
  }
  return scalar(f,draft[f.key] as string,disabled,v=>update(f.key,v));
 })}</div>;
}
