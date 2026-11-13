import type { CRMEntity, CRMRecord } from './crmClient';

type FieldType = 'text' | 'email' | 'number' | 'money' | 'select';
export interface CRMField {
  key: string;
  label: string;
  type: FieldType;
  required?: boolean;
  options?: readonly string[];
  help?: string;
}
const f = (key: string, label: string, type: FieldType = 'text', required = false,
  options?: readonly string[], help?: string): CRMField =>
  ({ key, label, type, required, options, help });

export const crmFields: Record<CRMEntity, CRMField[]> = {
  customers: [
    f('name', 'Company / Customer name', 'text', true),
    f('contactPerson', 'Contact person', 'text', true),
    f('email', 'Verified business email', 'email', true),
    f('phone', 'Phone number', 'text', true),
    f('city', 'City', 'text', true),
    f('state', 'State', 'text', true),
    f('gstin', 'GSTIN (optional)', 'text', false)
  ],
  leads: [
    f('name', 'Contact name', 'text', true),
    f('company', 'Company', 'text', true),
    f('email', 'Business email', 'email', true),
    f('phone', 'Phone number', 'text', true),
    f('source', 'Source', 'select', true, [
      'WEBSITE','WHATSAPP','INDIAMART','JUSTDIAL','EMAIL','TELEGRAM','REFERRAL',
      'GEM_TENDER','OUTBOUND_HUNTER','HARDWARE_REFRESH','PARTNER_PORTAL','OEM_PASS'
    ]),
    f('status', 'Lead status', 'select', false, ['NEW','CONTACTED','QUALIFIED','BOM_GENERATED','QUOTED','NEGOTIATING','WON','LOST']),
    f('score', 'Priority', 'select', false, ['HOT','WARM','COLD','NURTURE']),
    f('scoreReason', 'Score evidence'),
    f('intentScore', 'Intent score (0–100)', 'number', false),
    f('requirement', 'Customer requirement', 'text', true),
    f('estimatedBudget', 'Estimated budget (INR)', 'money', false, undefined, 'Amount is an estimate, not booked revenue'),
    f('location', 'Location'),
    f('gstin', 'GSTIN (optional)')
  ],
  products: [
    f('sku', 'Unique SKU', 'text', true),
    f('brand', 'Brand', 'text', true),
    f('model', 'Model', 'text', true),
    f('category', 'Category', 'select', true, ['LAPTOP','DESKTOP','SERVER','NETWORKING','POWER_STORAGE','ACCESSORIES']),
    f('specs', 'Verified specifications', 'text', true),
    f('unitCost', 'Unit cost (INR)', 'money', true),
    f('freightCost', 'Freight cost (INR)', 'money'),
    f('riskBuffer', 'Risk buffer (INR)', 'money'),
    f('sellingPrice', 'Selling price (INR)', 'money', true),
    f('minPrice', 'Minimum selling price (INR)', 'money', true),
    f('gstRate', 'GST rate (%)', 'money', false, undefined, 'Draft master rate; verify tax policy before invoicing'),
    f('hsn', 'HSN', 'text', true),
    f('warrantyMonths', 'Warranty (months)', 'number'),
    f('leadTimeDays', 'Lead time (days)', 'number')
  ]
};

export function prepareCRMFields(entity: CRMEntity, values: Record<string, string>, editing = false): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const field of crmFields[entity]) {
    const value = (values[field.key] ?? '').trim();
    if (value === '') {
      if (field.required) throw new Error(field.label + ' is required.');
      if (editing) continue;
      // Allow server defaults for omitted optional fields.
      continue;
    }
    if (field.type === 'number') {
      const num = Number(value);
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(num)) throw new Error(field.label + ' must be a non-negative integer.');
      output[field.key] = num;
    } else if (field.type === 'money') {
      if (!/^(0|[1-9]\d{0,15})(\.\d{1,2})?$/.test(value))
        throw new Error(field.label + ' must be a non-negative number with up to two decimals.');
      output[field.key] = value;
    } else {
      output[field.key] = value;
    }
  }
  if (editing && !Object.keys(output).length) throw new Error('No changes to save.');
  return output;
}

export function CRMRecordToForm(entity: CRMEntity, record: CRMRecord | null): Record<string, string> {
  return Object.fromEntries(crmFields[entity].map(field => {
    const value = record ? record[field.key] : undefined;
    return [field.key, value == null ? '' : String(value)];
  }));
}
