import type {CRMRecord,PageResult} from './crmClient';

// Phase 1FW: M16 customer intake uses existing OWNER-scoped CRM pagination.
// This validates navigation shape only; CRM creator provenance and active
// OWNER authorization are always enforced by the server again on ticket POST.
export const SERVICE_DESK_CUSTOMER_PAGE_SIZE=100;
const customerIdPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function verifyServiceDeskCustomerPage(value:PageResult,requestedPage:number){
 if(!Number.isSafeInteger(requestedPage)||requestedPage<1||requestedPage>100000||
    !value||typeof value!=='object'||Array.isArray(value)||
    !Number.isSafeInteger(value.page)||value.page!==requestedPage||
    value.limit!==SERVICE_DESK_CUSTOMER_PAGE_SIZE||
    !Number.isSafeInteger(value.total)||value.total<0||value.total>10000000||
    !Array.isArray(value.items)||value.items.length>SERVICE_DESK_CUSTOMER_PAGE_SIZE)
  throw Error('Unverified owner-scoped CRM customer page');
 const seen=new Set<string>();
 for(const row of value.items){
  if(!row||typeof row!=='object'||Array.isArray(row)||
     !customerIdPattern.test(row.id)||seen.has(row.id)||
     typeof row.name!=='string'||!row.name.trim()||row.name.length>255)
   throw Error('Invalid CRM customer selection row');
  seen.add(row.id);
 }
 // A changing CRM can make offset pages shorter; never trust an arbitrary
 // count for a page request or retain an unbounded customer catalog.
 return {
  items:value.items,
  page:requestedPage,
  total:value.total,
  totalPages:Math.max(1,Math.ceil(value.total/SERVICE_DESK_CUSTOMER_PAGE_SIZE)),
  hasPrevious:requestedPage>1,
  hasNext:requestedPage*SERVICE_DESK_CUSTOMER_PAGE_SIZE<value.total
 };
}
export function customerSelectionForPage(previousId:string,items:readonly CRMRecord[]){
 if(items.some(item=>item.id===previousId))return previousId;
 return items[0]?.id??'';
}
