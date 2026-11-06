export type CRMEntity = 'customers' | 'leads' | 'products';
export type Input = Record<string, unknown>;
type Kind = 'str' | 'email' | 'money' | 'integer' | 'enum' | 'gstin';
type Field = { kind: Kind; max?: number; values?: readonly string[]; required?: boolean };
const field = (kind: Kind, required = true, max?: number, values?: readonly string[]): Field => ({ kind, required, max, values });
export const definitions: Record<CRMEntity, Record<string, Field>> = {
  customers: {
    name: field('str', true, 200), gstin: field('gstin', false), contactPerson: field('str', true, 150),
    email: field('email'), phone: field('str', true, 30), city: field('str', true, 120), state: field('str', true, 120)
  },
  leads: {
    name: field('str', true, 150), company: field('str', true, 200), email: field('email'),
    phone: field('str', true, 30),
    source: field('enum', true, undefined, ['WEBSITE','WHATSAPP','INDIAMART','JUSTDIAL','EMAIL','TELEGRAM','REFERRAL','GEM_TENDER','OUTBOUND_HUNTER','HARDWARE_REFRESH','PARTNER_PORTAL','OEM_PASS']),
    status: field('enum', false, undefined, ['NEW','CONTACTED','QUALIFIED','BOM_GENERATED','QUOTED','NEGOTIATING','WON','LOST']),
    score: field('enum', false, undefined, ['HOT','WARM','COLD','NURTURE']),
    scoreReason: field('str', false, 500), intentScore: field('integer', false),
    requirement: field('str', true, 10000), estimatedBudget: field('money', false),
    location: field('str', false, 150), gstin: field('gstin', false)
  },
  products: {
    sku: field('str', true, 100), brand: field('str', true, 120), model: field('str', true, 200),
    category: field('enum', true, undefined, ['LAPTOP','DESKTOP','SERVER','NETWORKING','POWER_STORAGE','ACCESSORIES']),
    specs: field('str', true, 10000), unitCost: field('money'),
    freightCost: field('money', false), riskBuffer: field('money', false),
    sellingPrice: field('money'), minPrice: field('money'), gstRate: field('money', false),
    hsn: field('str', true, 16), warrantyMonths: field('integer', false), leadTimeDays: field('integer', false)
  }
};
export class InputError extends Error {}
const maxLimit: Record<string,number> = {intentScore:100,warrantyMonths:1200,leadTimeDays:3650};
export function validate(entity: CRMEntity, value: unknown, partial = false): Input {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new InputError('Object body required');
  const raw = value as Input;
  const def = definitions[entity];
  const keys = Object.keys(raw);
  if (!keys.length || keys.some(k => !Object.prototype.hasOwnProperty.call(def, k))) throw new InputError('Unknown or empty fields');
  if (!partial && Object.entries(def).some(([k,v]) => v.required && !(k in raw))) throw new InputError('Required fields missing');
  const result: Input = {};
  for (const k of keys) {
    const rule = def[k], v = raw[k];
    if (v === null && rule.kind === 'gstin') { result[k] = null; continue; }
    if (rule.kind === 'str' || rule.kind === 'email' || rule.kind === 'gstin' || rule.kind === 'enum') {
      if (typeof v !== 'string') throw new InputError('Invalid '+k);
      const text = v.trim();
      if (rule.kind === 'str' && (text.length > (rule.max ?? 500) || (rule.required && !text))) throw new InputError('Invalid '+k);
      if (rule.kind === 'email' && (text.length > 191 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text))) throw new InputError('Invalid '+k);
      if (rule.kind === 'gstin' && text && !/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(text.toUpperCase())) throw new InputError('Invalid '+k);
      if (rule.kind === 'enum' && !rule.values?.includes(text)) throw new InputError('Invalid '+k);
      result[k] = rule.kind === 'gstin' ? text.toUpperCase() || null : text;
    } else if (rule.kind === 'money') {
      // decimal string preserves two decimal places; never use JS floats for accounting.
      if (typeof v !== 'string' || !/^(0|[1-9]\d{0,15})(\.\d{1,2})?$/.test(v)) throw new InputError('Use a non-negative decimal string for '+k);
      const [a,b=''] = v.split('.');
      result[k] = a+'.'+b.padEnd(2,'0');
      if (k === 'gstRate' && Number(v) > 100) throw new InputError('Invalid gstRate');
    } else {
      if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0 || v > (maxLimit[k] ?? 65535)) throw new InputError('Invalid '+k);
      result[k] = v;
    }
  }
  if (entity === 'products' && result.minPrice !== undefined && result.sellingPrice !== undefined && Number(result.minPrice) > Number(result.sellingPrice)) {
    throw new InputError('minPrice cannot exceed sellingPrice');
  }
  return result;
}
export function parseVersion(value: unknown): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1 || n > 2147483647) throw new InputError('Valid expected version required');
  return n;
}
export function parsePagination(raw: Record<string,unknown>) {
  const page = raw.page === undefined ? 1 : Number(raw.page);
  const limit = raw.limit === undefined ? 25 : Number(raw.limit);
  if (!Number.isSafeInteger(page) || page < 1 || page > 100000 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new InputError('Invalid page or limit');
  return { limit, offset:(page-1)*limit, page };
}
