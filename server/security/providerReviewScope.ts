import type {PoolConnection} from 'mysql2/promise';
import {activeSensitiveReviewerScope} from './sensitiveReviewScope';

// First-party owner nomination only; NOT legal, CCA/MCA or provider-issued approval.
export type ProviderReviewScope='PROVIDER_BRIDGE'|'PROVIDER_SANDBOX'|'PROVIDER_SELECTION'|'PROVIDER_ONBOARDING';
export type ProviderOwnerColumn='p.provisioned_by'|'p.submitted_by'|'c.opened_by'|
 'p.imported_by'|'n.opened_by'|'p.prepared_by'|'d.prepared_by'|
 'a.imported_by'|'m.prepared_by';
export class ProviderReviewScopeDenied extends Error{
 constructor(){super('Evidence unavailable to reviewer');}
}
export function providerScopeSql(ownerColumn:ProviderOwnerColumn,scope:ProviderReviewScope):string{
 // Caller supplies compile-time column and scope literals, never untrusted HTTP input.
 return `EXISTS (SELECT 1 FROM app_reviewer_scope_grants g
  JOIN auth_users o ON o.id=g.owner_user_id
  JOIN auth_users v ON v.id=g.reviewer_user_id
  WHERE g.owner_user_id=${ownerColumn} AND g.reviewer_user_id=?
   AND g.workflow_scope='${scope}' AND g.state='ACTIVE'
   AND o.role='OWNER' AND o.status='ACTIVE'
   AND v.role='REVIEWER' AND v.status='ACTIVE')`;
}
export async function requireProviderReviewerScope(c:PoolConnection,
 ownerId:string,reviewerId:string,scope:ProviderReviewScope,lock=false):Promise<void>{
 if(!await activeSensitiveReviewerScope(c,ownerId,reviewerId,scope,lock))
  throw new ProviderReviewScopeDenied();
}
