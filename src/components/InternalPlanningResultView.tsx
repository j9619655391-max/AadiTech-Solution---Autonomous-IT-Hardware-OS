import React from 'react';
import {summarizePlanningResult,comparePlanningResults} from '../services/internalPlanningResults';
import type {PlanningResult} from '../services/internalPlanningClient';
export function InternalPlanningResultView({result,baseline,onPin,onClear}:{result:PlanningResult;baseline:PlanningResult|null;onPin:()=>void;onClear:()=>void}){
 try{
  const module=String(result.module),summary=summarizePlanningResult(module,result),comparison=baseline&&baseline.module===module?comparePlanningResults(module,baseline,result):null;
  return <section className="rounded border border-slate-700 p-3 space-y-3" aria-label="Held scenario result">
   <h3 className="font-semibold">{summary.title} — HOLD</h3>
   <p className="text-sm text-slate-300">Unverified operator-supplied scenario. Not an approval, settlement, shipment, or official document.</p>
   <dl className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">{summary.metrics.map(x=><div key={x.key} className="rounded bg-slate-950 p-2"><dt className="text-xs text-slate-400">{x.label}</dt><dd className="break-all">{x.value}</dd></div>)}</dl>
   {summary.table&&<div className="overflow-x-auto"><table className="w-full text-sm text-left"><caption className="text-left font-medium">{summary.table.label}</caption><thead><tr>{summary.table.headers.map(x=><th key={x} scope="col" className="p-2">{x}</th>)}</tr></thead><tbody>{summary.table.rows.map((row,i)=><tr key={i}>{row.map((v,j)=><td key={j} className="border-t border-slate-700 p-2">{v}</td>)}</tr>)}</tbody></table></div>}
   <h4 className="font-medium">Outstanding evidence requirements</h4><ul className="list-disc pl-5 text-sm">{summary.blockers.map(x=><li key={x.code}>{x.description}</li>)}</ul>
   <div className="flex flex-wrap gap-3"><button type="button" className="underline" onClick={onPin}>Use as comparison baseline</button>{baseline&&<button type="button" className="underline" onClick={onClear}>Clear baseline</button>}</div>
   {comparison&&<div className="overflow-x-auto"><table className="w-full text-sm text-left"><caption className="text-left font-medium">Scenario comparison only (not historical verified facts)</caption><thead><tr><th scope="col">Metric</th><th scope="col">Baseline</th><th scope="col">Current</th><th scope="col">Change</th></tr></thead><tbody>{comparison.metrics.map(x=><tr key={x.label} className="border-t border-slate-700"><th scope="row" className="font-normal p-2">{x.label}</th><td className="p-2">{x.baseline}</td><td className="p-2">{x.current}</td><td className="p-2">{x.changed?'Changed':'Same'}</td></tr>)}</tbody></table><p className="text-sm">Detail rows: {comparison.detailChanged?'changed':'same'} · Evidence requirements: {comparison.blockersChanged?'changed':'same'}. Both scenarios remain held.</p></div>}
  </section>;
 }catch{return <p role="alert">Planning result could not be validated. No business action is authorized.</p>;}
}
