import type { CRMEntity, CRMRecord } from './crmClient';
import { crmFields, prepareCRMFields } from './crmFields';

/** Deliberately manual migration: no bulk writes, no automatic import, no source deletion. */
export interface LegacyCandidate {
  entity: CRMEntity;
  sourceId: string;
  sourceIndex: number;
  label: string;
  fields: Record<string, string>;
  issues: string[];
  duplicate: boolean;
}
export interface LegacyPreview {
  candidates: LegacyCandidate[];
  totals: Record<CRMEntity, number>;
  invalid: number;
  warnings: number;
}
const names = { aaditech_leads: 'leads', aaditech_customers: 'customers', aaditech_products: 'products' } as const;
const maxBytes = 2 * 1024 * 1024;
const maxRecords = 300;
const demoText = /^(?:demo|sample|test|example|dummy|placeholder)\b/i;
const suspiciousEmail = /(?:example\.(?:com|in|invalid)|company\.in|yourcompany|test@|dummy@|procurement@company\.in)/i;
type ObjectValue = Record<string, unknown>;
function isObject(value: unknown): value is ObjectValue {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
function getString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value == null ? '' : String(value);
}
function toMoney(value: unknown): string {
  if (typeof value !== 'number' && typeof value !== 'string') return '';
  const str = String(value);
  if (!/^(0|[1-9]\d{0,15})(\.\d{1,2})?$/.test(str)) return '';
  return str;
}
function mapped(entity: CRMEntity, entry: ObjectValue): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of crmFields[entity]) {
    const value = entry[item.key];
    if (item.type === 'money') result[item.key] = toMoney(value);
    else result[item.key] = getString(value);
  }
  return result;
}
function identity(entity: CRMEntity, fields: Record<string, string>): string {
  return entity === 'products'
    ? fields.sku?.toLowerCase() ?? ''
    : fields.email?.toLowerCase() ?? '';
}
function legacyName(entity: CRMEntity, fields: Record<string, string>): string {
  return entity === 'products' ? [fields.brand,fields.model,fields.sku].filter(Boolean).join(' · ')
    : entity === 'customers' ? fields.name || ''
    : [fields.company,fields.name].filter(Boolean).join(' · ');
}
export function parseLegacyBackup(contents: string, current: Partial<Record<CRMEntity, CRMRecord[]>> = {}): LegacyPreview {
  if (new TextEncoder().encode(contents).length > maxBytes) throw Error('File exceeds 2 MB. Split and review offline.');
  let parsed: unknown;
  try { parsed = JSON.parse(contents); } catch { throw Error('Invalid JSON backup.'); }
  if (!isObject(parsed) || parsed.format !== 'aaditech-legacy-browser-backup-v1' || !isObject(parsed.data)) {
    throw Error('Unsupported backup format. Use the Export legacy browser CRM button.');
  }
  const blob = parsed.data;
  const results: LegacyCandidate[] = [];
  const seen = new Map<string, number>();
  const totals = { leads: 0, customers: 0, products: 0 };
  for (const [key, entity] of Object.entries(names) as [keyof typeof names, CRMEntity][]) {
    const entries = blob[key];
    if (entries === undefined) continue;
    if (!Array.isArray(entries)) throw Error('Invalid '+key+' collection. Expected an array.');
    totals[entity] = entries.length;
    if (results.length + entries.length > maxRecords) throw Error('Backup has more than 300 records; review smaller exports.');
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      const issues: string[] = [];
      if (!isObject(entry)) {
        results.push({ entity, sourceId: '', sourceIndex:index, label:'Invalid record', fields:{}, issues:['Record must be an object'], duplicate:false });
        continue;
      }
      const fields = mapped(entity, entry);
      const sourceId = getString(entry.id);
      const label = legacyName(entity, fields) || entity+' #'+(index+1);
      const keyValue = identity(entity, fields);
      if (!sourceId) issues.push('Missing original source ID');
      if (!keyValue) issues.push('Email/SKU is required for duplicate review');
      if (keyValue) {
        const composite = entity+'|'+keyValue;
        if (seen.has(composite)) issues.push('Repeated identity within this backup');
        else seen.set(composite, index);
        const existing = current[entity] || [];
        if (existing.some(row => getString(row[entity === 'products' ? 'sku':'email']).toLowerCase() === keyValue))
          issues.push('Matching identity found in loaded MySQL records');
      }
      if (demoText.test(label) || suspiciousEmail.test(fields.email || '') || /^(?:CUST|LD|PROD)-\d+$/.test(sourceId))
        issues.push('Looks like demo/default data — independently verify');
      // Never migrate financial totals, credit limits or inventory fields.
      try {
        const normalized = prepareCRMFields(entity, fields);
        for (const field of crmFields[entity]) {
          if (!(field.key in normalized)) delete fields[field.key];
        }
      } catch (error) {
        issues.push('Validation: '+(error instanceof Error ? error.message:'Invalid fields'));
      }
      // Server validation is final; this preview is advisory and never auto-confirms records.
      results.push({ entity, sourceId, sourceIndex:index, label, fields, issues,
        duplicate: issues.some(v=>v.includes('Repeated') || v.includes('Matching')) });
    }
  }
  return { candidates: results, totals,
    invalid: results.filter(r=>r.issues.some(v=>v.startsWith('Validation:') || v.includes('Missing original') || v.includes('required for duplicate') || v==='Record must be an object')).length,
    warnings: results.filter(r=>r.issues.length>0).length };
}
