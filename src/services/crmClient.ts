import { authenticatedFetch } from './authClient';

export type CRMEntity = 'customers' | 'leads' | 'products';

export interface CRMRecord {
  id: string;
  version: number;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

export interface PageResult {
  items: CRMRecord[];
  total: number;
  page: number;
  limit: number;
}

export class CRMRequestError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = 'CRMRequestError';
  }
}

async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await authenticatedFetch(url, init);
  if (!response.ok) {
    let message = 'Request failed. Please try again.';
    try {
      const result: unknown = await response.json();
      if (result && typeof result === 'object' && 'error' in result &&
          typeof result.error === 'string') message = result.error;
    } catch { /* Preserve generic message */ }
    throw new CRMRequestError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const crmClient = {
  list: (entity: CRMEntity, page = 1, limit = 25) =>
    request<PageResult>('/api/crm/' + entity + '?page=' + page + '&limit=' + limit),
  create: (entity: CRMEntity, fields: Record<string, unknown>) =>
    request<CRMRecord>('/api/crm/' + entity, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(fields)
    }),
  update: (entity: CRMEntity, id: string, expectedVersion: number, fields: Record<string, unknown>) =>
    request<CRMRecord>('/api/crm/' + entity + '/' + encodeURIComponent(id), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...fields, expectedVersion })
    }),
  remove: (entity: CRMEntity, id: string, expectedVersion: number) =>
    request<void>('/api/crm/' + entity + '/' + encodeURIComponent(id), {
      method: 'DELETE', headers: { 'If-Match': String(expectedVersion) }
    })
};
