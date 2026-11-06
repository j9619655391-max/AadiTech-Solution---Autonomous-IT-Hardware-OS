import React, { useCallback, useEffect, useRef, useState } from 'react';
import { crmClient, CRMRequestError, type CRMEntity, type CRMRecord, type PageResult } from '../services/crmClient';
import { crmFields, prepareCRMFields, CRMRecordToForm } from '../services/crmFields';
import { LegacyImportReview, getCurrentRecords } from './LegacyImportReview';
import type { LegacyCandidate } from '../services/legacyImport';

const names: { key: CRMEntity; label: string }[] = [
  { key: 'leads', label: 'Leads' },
  { key: 'customers', label: 'Customers' },
  { key: 'products', label: 'Product Catalog' }
];
const labels: Record<CRMEntity, string> = {
  leads: 'Lead', customers: 'Customer', products: 'Product'
};
const text = (item: CRMRecord, key: string) => String(item[key] ?? '—');

function exportLegacyBrowserData() {
  const keys = ['aaditech_leads', 'aaditech_customers', 'aaditech_products'] as const;
  const raw: Record<string, unknown> = {};
  for (const key of keys) {
    const value = localStorage.getItem(key);
    if (!value) continue;
    try { raw[key] = JSON.parse(value) as unknown; }
    catch { raw[key] = { unreadable: true, raw: value }; }
  }
  if (!Object.keys(raw).length) throw new Error('No explicitly saved browser CRM records found. Seeded demo data are not exported.');
  const payload = JSON.stringify({ format: 'aaditech-legacy-browser-backup-v1', exportedAt: new Date().toISOString(), data: raw }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
  const link = document.createElement('a');
  try {
    link.href = url;
    link.download = 'aaditech-legacy-crm-' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(link);
    link.click();
  } finally {
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }
}

export function LiveCRMWorkspace() {
  const [entity, setEntity] = useState<CRMEntity>('leads');
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PageResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editing, setEditing] = useState<CRMRecord | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const requestId = useRef(0);
  const [importCandidate, setImportCandidate] = useState<LegacyCandidate | null>(null);
  const [approvedImport, setApprovedImport] = useState(false);

  const load = useCallback(async () => {
    const request = ++requestId.current;
    setLoading(true); setError('');
    try {
      const result = await crmClient.list(entity, page, 25);
      if (request !== requestId.current) return;
      setData(result);
    } catch (err) {
      if (request !== requestId.current) return;
      setData(null);
      setError(err instanceof Error ? err.message : 'Could not load CRM data.');
    } finally {
      if (request === requestId.current) setLoading(false);
    }
  }, [entity, page]);

  useEffect(() => {
    void load();
    return () => { requestId.current++; };
  }, [load]);

  function switchEntity(value: CRMEntity) {
    setEntity(value); setPage(1); setFormOpen(false); setEditing(null);
    setDraft({}); setImportCandidate(null); setApprovedImport(false); setSuccess(''); setError(''); setData(null);
  }

  function openForm(record: CRMRecord | null) {
    setEditing(record); setImportCandidate(null); setApprovedImport(false); setDraft(CRMRecordToForm(entity, record));
    setFormOpen(true); setError(''); setSuccess('');
  }

  function reviewLegacy(item: LegacyCandidate) {
    if (item.issues.length) return;
    setEntity(item.entity); setPage(1); setEditing(null);
    setImportCandidate(item); setApprovedImport(false);
    setDraft({ ...item.fields }); setFormOpen(true); setError(''); setSuccess('');
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(''); setSuccess('');
    try {
      if (importCandidate && !approvedImport) throw Error('Approve this individual legacy record first.');
      const input = prepareCRMFields(entity, draft, editing !== null);
      if (importCandidate) {
        const existing = await getCurrentRecords();
        const key = entity === 'products' ? 'sku' : 'email';
        const candidateId = String(input[key] ?? '').toLowerCase().trim();
        if (!candidateId || existing[entity].some(row => String(row[key] ?? '').toLowerCase().trim() === candidateId))
          throw Error('An existing MySQL record has the same email/SKU. Save cancelled.');
      }
      if (editing) await crmClient.update(entity, editing.id, editing.version, input);
      else await crmClient.create(entity, input);
      setSuccess(labels[entity] + (editing ? ' updated in MySQL.' : ' saved in MySQL.'));
      setFormOpen(false); setEditing(null); setImportCandidate(null); setApprovedImport(false); setDraft({});
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save record.');
    } finally { setBusy(false); }
  }

  async function remove(record: CRMRecord) {
    if (busy || !window.confirm('Archive ' + labels[entity] + ' "' + (record.name ?? record.sku ?? record.id) + '"? This is a soft-delete; audit records remain.')) return;
    setBusy(true); setError(''); setSuccess('');
    try {
      await crmClient.remove(entity, record.id, record.version);
      setSuccess(labels[entity] + ' archived in MySQL.');
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not archive record.'); }
    finally { setBusy(false); }
  }

  const headingKeys = entity === 'customers'
    ? ['name','contactPerson','email','city']
    : entity === 'leads'
      ? ['company','name','status','source']
      : ['sku','brand','model','sellingPrice'];

  return <section className="space-y-5" aria-label="Live MySQL CRM">
    <header className="flex flex-wrap justify-between items-start gap-3">
      <div>
        <h2 className="text-xl font-bold text-white">Live CRM · MySQL</h2>
        <p className="text-slate-400 text-sm mt-1">
          Verified owner-controlled records. Server-generated IDs, validation and audit logging.
        </p>
      </div>
      <div className="flex gap-2 flex-wrap">
        <button type="button" onClick={() => { try { exportLegacyBrowserData(); setSuccess('Legacy browser backup exported. Review for demo records before importing.'); } catch(e) { setError(e instanceof Error ? e.message : 'Export failed.'); } }}
          className="px-3 py-2 text-xs border border-slate-600 rounded-lg text-slate-200 hover:bg-slate-800">
          Export legacy browser CRM
        </button>
        <button type="button" onClick={() => openForm(null)} disabled={busy}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg font-semibold text-white">
          + Add {labels[entity]}
        </button>
      </div>
    </header>
    <div className="bg-amber-950/40 border border-amber-700/60 rounded-lg p-3 text-sm text-amber-200">
      Only this workspace uses the live CRM APIs. Other dashboards, lead-hunter actions,
      quotations and inventory are still prototypes until migrated. Existing browser data is never silently imported.
      No customer balances or stock figures are inferred from incomplete records.
    </div>
    <nav aria-label="CRM dataset" className="flex flex-wrap gap-2">
      {names.map(item => <button key={item.key} type="button"
        onClick={() => switchEntity(item.key)}
        aria-pressed={entity === item.key}
        className={'rounded-lg border px-4 py-2 text-sm ' +
          (entity === item.key ? 'bg-cyan-700 border-cyan-500 text-white' : 'bg-slate-900 border-slate-700 text-slate-300 hover:border-slate-500')}>
        {item.label}
      </button>)}
    </nav>
    {error && <div role="alert" className="rounded-lg border border-rose-700 bg-rose-950/40 text-rose-200 p-3 text-sm">
      {error} {error.includes('changed') ? 'Refresh the record before editing again.' : ''}
    </div>}
    {success && <div role="status" className="rounded-lg border border-emerald-700 bg-emerald-950/30 text-emerald-200 p-3 text-sm">{success}</div>}
    <LegacyImportReview onReview={reviewLegacy} />
    {formOpen && <form onSubmit={save} className="rounded-xl border border-cyan-700/70 bg-slate-900 p-5 space-y-4">
      <h3 className="font-semibold">{editing ? 'Edit' : 'New'} {labels[entity]}</h3>
      <p className="text-xs text-slate-400">Enter verified details only. No invented contacts, inventory, credit or tax compliance claims.</p>
      {importCandidate && <label className="block border border-amber-700 rounded-lg p-3 text-sm text-amber-200">
        <input type="checkbox" checked={approvedImport} onChange={e => setApprovedImport(e.target.checked)} className="mr-2" />
        I independently verified this is genuine business data (not demo) and approve saving this one record.
      </label>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {crmFields[entity].map(field => <label key={field.key} className="text-xs text-slate-300 space-y-1">
          <span className="block font-medium">{field.label}{field.required ? ' *' : ''}</span>
          {field.type === 'select'
            ? <select value={draft[field.key] ?? ''} required={field.required} onChange={e => setDraft(v => ({ ...v, [field.key]: e.target.value }))}
                className="w-full rounded-lg border border-slate-600 bg-slate-950 text-slate-100 p-2.5">
                <option value="">Select</option>
                {field.options?.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            : <input value={draft[field.key] ?? ''} required={field.required}
                type={field.type === 'email' ? 'email' : 'text'}
                inputMode={field.type === 'money' ? 'decimal' : field.type === 'number' ? 'numeric' : undefined}
                autoComplete="off"
                onChange={e => setDraft(v => ({ ...v, [field.key]: e.target.value }))}
                className="w-full rounded-lg border border-slate-600 bg-slate-950 text-slate-100 p-2.5" />}
          {field.help && <span className="block text-slate-500">{field.help}</span>}
        </label>)}
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="submit" disabled={busy || (!!importCandidate && !approvedImport)} className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2 font-semibold">
          {busy ? 'Saving…' : 'Save to MySQL'}
        </button>
        <button type="button" onClick={() => { setFormOpen(false); setEditing(null); setImportCandidate(null); setApprovedImport(false); }} className="rounded-lg border border-slate-600 px-4 py-2">Cancel</button>
      </div>
    </form>}
    <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-x-auto">
      <div className="flex justify-between items-center p-4 border-b border-slate-700">
        <span className="text-slate-300 font-medium">{names.find(x=>x.key===entity)?.label} — {data ? data.total : '—'} records</span>
        <button type="button" onClick={() => void load()} disabled={loading || busy}
          className="text-xs text-cyan-300 disabled:opacity-50 hover:underline">Refresh from server</button>
      </div>
      {loading ? <p role="status" className="p-6 text-slate-300">Loading verified MySQL records…</p>
        : !data ? <p className="p-6 text-rose-200">Database records unavailable. Retry after checking connection and migration.</p>
        : !data.items.length ? <p className="p-6 text-slate-400">No {entity} stored in MySQL. Add a verified record or review the legacy backup separately.</p>
        : <table className="w-full text-sm">
          <thead className="bg-slate-950 text-left text-slate-400"><tr>
            {headingKeys.map(key => <th key={key} className="px-4 py-3 font-medium">{key}</th>)}
            <th className="px-4 py-3">Version</th><th className="px-4 py-3">Actions</th>
          </tr></thead>
          <tbody>{data.items.map(item => <tr key={item.id} className="border-t border-slate-800">
            {headingKeys.map(key => <td key={key} className="px-4 py-3 max-w-64 truncate">{text(item,key)}</td>)}
            <td className="px-4 py-3 text-slate-400">{item.version}</td>
            <td className="px-4 py-3 whitespace-nowrap">
              <button type="button" disabled={busy} onClick={() => openForm(item)} className="text-cyan-300 mr-3 hover:underline">Edit</button>
              <button type="button" disabled={busy} onClick={() => void remove(item)} className="text-rose-300 hover:underline">Archive</button>
            </td>
          </tr>)}</tbody>
        </table>}
      <div className="flex items-center justify-between p-4 border-t border-slate-700 text-sm text-slate-400">
        <span>Page {page}{data ? ' · ' + data.total + ' total' : ''}</span>
        <div className="space-x-2">
          <button type="button" disabled={loading || page === 1} onClick={() => setPage(p => Math.max(1, p-1))} className="disabled:opacity-30 border border-slate-600 rounded px-3 py-1">Previous</button>
          <button type="button" disabled={loading || !data || page*25 >= data.total} onClick={() => setPage(p => p+1)} className="disabled:opacity-30 border border-slate-600 rounded px-3 py-1">Next</button>
        </div>
      </div>
    </div>
    <p className="text-xs text-slate-500">
      Data writes are confirmed by the server before success is shown. An HTTP 409 means another edit or duplicate SKU was detected.
      Legacy import requires manual review of each record; browser backup is never deleted.
    </p>
  </section>;
}
