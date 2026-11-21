import React, { useRef, useState } from 'react';
import { crmClient, type CRMEntity, type CRMRecord } from '../services/crmClient';
import { parseLegacyBackup, type LegacyCandidate, type LegacyPreview } from '../services/legacyImport';

interface Props { onReview: (candidate: LegacyCandidate) => void; }
async function getCurrentRecords(): Promise<Record<CRMEntity, CRMRecord[]>> {
  const result: Record<CRMEntity, CRMRecord[]> = { leads: [], customers: [], products: [] };
  for (const entity of ['leads', 'customers', 'products'] as const) {
    const first = await crmClient.list(entity, 1, 100);
    if (first.total > 2000) throw Error('Too many '+entity+' for safe browser duplicate scan; ask administrator to reconcile.');
    result[entity].push(...first.items);
    for (let page = 2; page <= Math.ceil(first.total / 100); page++) {
      const next = await crmClient.list(entity, page, 100);
      result[entity].push(...next.items);
    }
    if (result[entity].length !== first.total) throw Error('Database changed during review. Restart preview.');
  }
  return result;
}
export { getCurrentRecords };

export function LegacyImportReview({ onReview }: Props) {
  const picker = useRef<HTMLInputElement | null>(null);
  const [preview, setPreview] = useState<LegacyPreview | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function selectBackup(file: File | undefined) {
    if (!file) return;
    setBusy(true); setError(''); setPreview(null);
    try {
      if (file.size > 2*1024*1024) throw Error('Backup exceeds 2 MB.');
      const raw = await file.text();
      const existing = await getCurrentRecords();
      const output = parseLegacyBackup(raw, existing);
      if (!output.candidates.length) throw Error('No explicit CRM records in backup.');
      setPreview(output);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read backup.');
    } finally {
      if (picker.current) picker.current.value = '';
      setBusy(false);
    }
  }

  return <section className="rounded-xl border border-slate-700 bg-slate-900 p-4 space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 className="text-sm font-semibold">Legacy CRM backup review</h3>
        <p className="text-xs text-slate-400">Local JSON preview only; no automatic writes or deletions.</p>
      </div>
      <input type="file" ref={picker} accept=".json,application/json" aria-label="Choose legacy CRM backup"
        className="hidden" onChange={e => void selectBackup(e.target.files?.[0])} />
      <button disabled={busy} type="button" className="border border-slate-600 rounded-lg p-2 text-sm disabled:opacity-40"
        onClick={() => picker.current?.click()}>{busy ? 'Scanning…' : 'Review exported JSON'}</button>
    </div>
    {error && <p role="alert" className="text-rose-200 text-sm">{error}</p>}
    {preview && <div className="space-y-2">
      <p className="text-sm text-slate-300">
        {preview.candidates.length} records · {preview.invalid} invalid · {preview.warnings} with warnings.
        Only warning-free records may be reviewed for individual creation; the server validates again.
      </p>
      <div className="max-h-72 overflow-y-auto space-y-2">
        {preview.candidates.map(item => <div key={item.entity+':'+item.sourceIndex}
          className="rounded-lg border border-slate-700 p-3 flex flex-wrap gap-2 items-center justify-between">
          <div className="text-sm">
            <p><strong>{item.entity}</strong> · {item.label}</p>
            <p className="text-xs text-slate-400">Legacy ID: {item.sourceId || '(missing)'}</p>
            {item.issues.length > 0 && <p className="text-xs text-amber-300">{item.issues.join(' · ')}</p>}
          </div>
          <button type="button" disabled={item.issues.length > 0}
            className="border border-cyan-600 rounded-lg px-3 py-2 text-xs disabled:opacity-30"
            onClick={() => onReview(item)}>Review one record</button>
        </div>)}
      </div>
    </div>}
  </section>;
}
