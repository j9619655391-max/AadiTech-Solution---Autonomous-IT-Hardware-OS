import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import commercialIntegrityRouter from '../server/commercialIntegrity/ownerRouter';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/procurement/ownerRouter';
import reviewRouter from '../server/procurement/reviewRouter';
import reviewerScopeRouter from '../server/security/reviewerScopeRouter';
import securityAdminRouter from '../server/security/adminRouter';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Procurement integration only permitted on disposable aaditech_ci');
const db=getPool();
if(!db)throw Error('Disposable MySQL unavailable');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),
 reviewerToken=newSecret(),csrf=newSecret();
const ownerPass='CI-procurement-owner-strong-2026',reviewerPass='CI-procurement-reviewer-strong-2026';
let base='',ownerStep='',reviewerStep='',siteId='',productId='',supplierId='',requestId='';
let close:undefined|(()=>Promise<void>);
after(async()=>{if(close)await close();await db.end();});

async function call(path:string,method='GET',body?:unknown,as:'owner'|'reviewer'|'anonymous'='owner',
 options:{csrf?:boolean;stepUp?:boolean;idempotencyKey?:string}={}){
 const headers:Record<string,string>={};
 if(as!=='anonymous')headers.cookie='aaditech_session='+(as==='owner'?ownerToken:reviewerToken);
 if(body!==undefined)headers['content-type']='application/json';
 if(options.csrf!==false&&method!=='GET')headers['x-csrf-token']=csrf;
 if(options.stepUp!==false){
  const token=as==='owner'?ownerStep:reviewerStep;
  if(token)headers['x-step-up-token']=token;
 }
 if(options.idempotencyKey)headers['idempotency-key']=options.idempotencyKey;
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();
 let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Invalid non-JSON response'};}}
 return {status:response.status,data};
}
test('establish disposable real MySQL identities and supplier/catalog/site fixtures',async()=>{
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [owner,'proc-owner-'+owner+'@example.invalid','CI Procurement Owner',await hashPassword(ownerPass),'OWNER']);
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [reviewer,'proc-review-'+reviewer+'@example.invalid','Independent CI Reviewer',
   await hashPassword(reviewerPass),'REVIEWER']);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(ownerToken),owner,csrf]);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(reviewerToken),reviewer,csrf]);
 productId=randomUUID();siteId=randomUUID();
 await db.execute(`INSERT INTO crm_products(id,sku,brand,model,category,specs,
  unitCost,sellingPrice,minPrice,hsn) VALUES(?,?,?,?,?,?,?,?,?,?)`,
  [productId,'PROC-'+productId,'CI','Server','SERVER','Synthetic procurement product',
   '100.00','120.00','100.00','8471']);
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [siteId,'P'+owner.replace(/-/g,'').slice(0,15).toUpperCase(),'Isolated stock site',owner]);
 const app=express();app.use(express.json({limit:'32kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/reviewer-scopes',reviewerScopeRouter);
 app.use('/api/security',securityAdminRouter);
 app.use('/api/procurement/review',reviewRouter);
 app.use('/api/procurement',ownerRouter);app.use('/api/commercial-integrity',commercialIntegrityRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('authentication, role separation and CSRF/step-up gates protect supplier and reviewer operations',async()=>{
 assert.equal((await call('/api/procurement/suppliers','GET',undefined,'anonymous')).status,401);
 assert.equal((await call('/api/procurement/suppliers','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/procurement/review/suppliers','GET',undefined,'owner')).status,403);
 const input={code:'SUP_'+owner.replace(/-/g,'').slice(0,10).toUpperCase(),
  legalName:'Synthetic Vendor',taxId:null};
 assert.equal((await call('/api/procurement/suppliers','POST',input)).status,403);
 assert.equal((await call('/api/procurement/suppliers','POST',input,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/procurement/suppliers','POST',input,'reviewer')).status,403);
 const [o,r]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass},'owner'),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')
 ]);
 assert.equal(o.status,200);assert.equal(r.status,200);
 ownerStep=String(o.data.stepUpToken);reviewerStep=String(r.data.stepUpToken);
 assert.match(ownerStep,/^[A-Za-z0-9_-]{43}$/);
 assert.match(reviewerStep,/^[A-Za-z0-9_-]{43}$/);
 const created=await call('/api/procurement/suppliers','POST',input);
 assert.equal(created.status,201);supplierId=created.data.id;
 assert.equal(created.data.status,'UNVERIFIED');
 assert.equal(created.data.externalVerification,false);
 assert.equal((await call('/api/procurement/suppliers','POST',input)).status,409);
 // An unrelated REVIEWER role alone grants no visibility. Explicitly scope the
 // credential by current-password step-up and existing owner CSRF protection.
 const unscoped=await call('/api/procurement/review/suppliers','GET',undefined,'reviewer');
 assert.equal(unscoped.status,200);
 assert.equal(unscoped.data.items.some((s:any)=>s.id===supplierId),false);
 const grant={reviewerId:reviewer,scope:'PROCUREMENT',decision:'GRANT',
  reason:'Owner explicitly nominated CI procurement reviewer only'};
 assert.equal((await call('/api/reviewer-scopes','POST',grant,'owner',{stepUp:false})).status,403);
 assert.equal((await call('/api/reviewer-scopes','POST',grant,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/reviewer-scopes','POST',
   {...grant,externalAuthorityVerified:true},'owner')).status,400);
 assert.equal((await call('/api/reviewer-scopes','POST',grant,'reviewer')).status,403);
 const approved=await call('/api/reviewer-scopes','POST',grant,'owner');
 assert.equal(approved.status,201);
 assert.equal(approved.data.state,'ACTIVE');
 assert.equal(approved.data.productionReleaseAuthorized,false);
 assert.equal(approved.data.independentAuthorityAuthenticated,false);
 assert.equal((await call('/api/reviewer-scopes','POST',grant,'owner')).status,409);
 const scoped=await call('/api/procurement/review/suppliers','GET',undefined,'reviewer');
 assert.equal(scoped.status,200);
 assert.equal(scoped.data.items.some((s:any)=>s.id===supplierId),true);
 const active=await call('/api/reviewer-scopes');
 assert.equal(active.status,200);
 assert.equal(active.data.items.some((row:any)=>row.reviewerId===reviewer&&
  row.scope==='PROCUREMENT'&&row.state==='ACTIVE'),true);
});
test('independent reviewer attests supplier evidence; owner cannot self attest',async()=>{
 const query=await call('/api/procurement/review/suppliers','GET',undefined,'reviewer');
 assert.equal(query.status,200);
 assert.ok(query.data.items.some((x:any)=>x.id===supplierId));
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'owner')).status,403);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer',{stepUp:false})).status,403);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:false},'reviewer')).status,400);
 const reviewed=await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer');
 assert.equal(reviewed.status,201);
 assert.equal(reviewed.data.status,'REVIEWED_INTERNAL');
 assert.equal(reviewed.data.externalVerification,false);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer')).status,409);
});
test('owner persists bounded quote-evidence purchase request exactly once, no PO or stock',async()=>{
 const invalid={supplierId,siteId,quoteEvidenceRef:'SUP-QUOTE-2026-001',
  items:[{productId,quantity:2,quotedUnitCost:'199.20'}]};
 assert.equal((await call('/api/procurement/requests','POST',invalid)).status,400);
 assert.equal((await call('/api/procurement/requests','POST',invalid,'owner',{stepUp:false,idempotencyKey:randomUUID()})).status,403);
 assert.equal((await call('/api/procurement/requests','POST',{...invalid,items:[
  {productId:randomUUID(),quantity:1,quotedUnitCost:'100.00'}]},
  'owner',{idempotencyKey:randomUUID()})).status,400);
 const key=randomUUID();
 const created=await call('/api/procurement/requests','POST',invalid,'owner',{idempotencyKey:key});
 assert.equal(created.status,201);
 assert.equal(created.data.status,'PENDING');
 assert.equal(created.data.subtotal,'398.40');
 assert.equal(created.data.dispatchEnabled,false);
 requestId=created.data.id;
 const replay=await call('/api/procurement/requests','POST',invalid,'owner',{idempotencyKey:key});
 assert.equal(replay.status,200);assert.equal(replay.data.replayed,true);
 assert.equal(replay.data.id,requestId);
 assert.equal((await call('/api/procurement/requests','POST',{...invalid,
  quoteEvidenceRef:'SUP-QUOTE-2026-002'},'owner',{idempotencyKey:key})).status,409);
 const owned=await call('/api/procurement/requests/'+requestId);
 assert.equal(owned.status,200);
 assert.equal(owned.data.items.length,1);
 assert.equal(owned.data.items[0].quotedUnitCost,'199.20');
 assert.equal(owned.data.externalPurchaseOrderIssued,false);
 const holds=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(holds.status,409);
});
test('independent review attests quote, rejects repeat and creates no external order',async()=>{
 const queue=await call('/api/procurement/review/requests','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.ok(queue.data.items.some((x:any)=>x.id===requestId));
 const detail=await call('/api/procurement/review/requests/'+requestId,'GET',undefined,'reviewer');
 assert.equal(detail.status,200);assert.equal(detail.data.items[0].lineSubtotal,'398.40');
 const body={decision:'APPROVED_INTERNAL',reason:'Supplier quote evidence inspected and internally accepted',
  evidenceAttested:true};
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'owner')).status,403);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',
  {...body,evidenceAttested:false},'reviewer')).status,400);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',
  body,'reviewer',{csrf:false})).status,403);
 const decided=await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'reviewer');
 assert.equal(decided.status,201);assert.equal(decided.data.decision,'APPROVED_INTERNAL');
 assert.equal(decided.data.externalPurchaseOrderIssued,false);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'reviewer')).status,409);
});
test('internal PO hold is immutable, idempotent, hash-backed and dispatch DISABLED',async()=>{
 const missing=await call('/api/procurement/requests/'+requestId+'/hold','POST',
  {recipient:'outside@example.invalid'});
 assert.equal(missing.status,400);
 const held=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(held.status,201);
 assert.equal(held.data.status,'HELD');assert.equal(held.data.dispatchState,'DISABLED');
 assert.equal(held.data.stockPosted,false);
 assert.equal(held.data.externalPurchaseOrderIssued,false);
 assert.match(held.data.sha256,/^[0-9a-f]{64}$/);
 const repeated=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(repeated.status,200);
 assert.equal(repeated.data.replayed,true);
 assert.equal(repeated.data.sha256,held.data.sha256);
 const [rows]=await db.query<any[]>('SELECT status,dispatch_state,snapshot_sha256,snapshot_json FROM proc_po_holds WHERE request_id=?',[requestId]);
 assert.equal(rows.length,1);assert.equal(rows[0].status,'HELD');
 assert.equal(rows[0].dispatch_state,'DISABLED');
 assert.equal(rows[0].snapshot_sha256,held.data.sha256);
 assert.equal(rows[0].snapshot_json.lines[0].quotedUnitCost,'199.20');
 const [opening]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inventory_opening_counts WHERE product_id=?',[productId]);
 assert.equal(Number(opening[0].n),0);
 const unsupported=await call('/api/procurement/receipts','POST',
  {requestId,siteId,quantity:2,serials:['TEST-SERIAL']});
 assert.equal(unsupported.status,404);
});
test('rejection fails closed; does not permit PO hold or stock movement',async()=>{
 const body={supplierId,siteId,quoteEvidenceRef:'SUP-QUOTE-2026-REJ',
  items:[{productId,quantity:1,quotedUnitCost:'10.00'}]};
 const request=await call('/api/procurement/requests','POST',body,'owner',
  {idempotencyKey:randomUUID()});
 assert.equal(request.status,201);
 const rejection=await call('/api/procurement/review/requests/'+request.data.id+'/decide',
  'POST',{decision:'REJECTED_INTERNAL',reason:'Supplier conditions and payment terms do not satisfy review',
   evidenceAttested:false},'reviewer');
 assert.equal(rejection.status,201);
 assert.equal((await call('/api/procurement/requests/'+request.data.id+'/hold','POST',{})).status,409);
 const [audit]=await db.query<any[]>('SELECT entity_type,action FROM proc_audit_events WHERE entity_id=?',
  [request.data.id]);
 assert.ok(audit.some((x:any)=>x.action==='SUBMITTED_FOR_INDEPENDENT_REVIEW'));
});


test('Phase 1BI owner-only source readback catches supplier line-cost tamper and forbids PO dispatch',async()=>{
 const route='/api/commercial-integrity/procurement/'+requestId;
 assert.equal((await call(route,'GET',undefined,'anonymous')).status,401);
 assert.equal((await call(route,'GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/commercial-integrity/procurement/'+randomUUID())).status,404);
 const initial=await call(route);
 assert.equal(initial.status,200);
 assert.equal(initial.data.localScopeConsistent,true,initial.data.anomalyCodes?.join(','));
 assert.equal(initial.data.hasDisabledHeldPurchaseOrder,true);
 assert.equal(initial.data.supplierCorporateIdentityIndependentlyVerified,false);
 assert.equal(initial.data.actualSupplierPurchaseOrderIssued,false);
 assert.equal(initial.data.stockPosted,false);
 assert.equal(initial.data.productionReleaseAuthorized,false);
 assert.equal(initial.data.releaseDecision,'HOLD');
 const [rows]=await db.query<any[]>('SELECT id,line_subtotal FROM proc_request_items WHERE request_id=? ORDER BY position LIMIT 1',[requestId]);
 assert.equal(rows.length,1);
 try{
  await db.execute('UPDATE proc_request_items SET line_subtotal=? WHERE id=?',['1.00',rows[0].id]);
  const changed=await call(route);
  assert.equal(changed.status,200);
  assert.equal(changed.data.localScopeConsistent,false);
  assert.ok(changed.data.anomalyCodes.includes('PROCUREMENT_QUOTED_COST_SNAPSHOT_CHANGED'));
  assert.equal(changed.data.productionReleaseAuthorized,false);
 }finally{
  await db.execute('UPDATE proc_request_items SET line_subtotal=? WHERE id=?',[rows[0].line_subtotal,rows[0].id]);
 }
 assert.equal((await call(route)).data.localScopeConsistent,true);
});



/* Phase 1EK: supplier/site provenance is actor scope, not legal tenancy. */
test('1EK two OWNER sessions cannot list each other suppliers or request details',async()=>{
 const foreignUser=randomUUID(),foreignToken='z'.repeat(43);
 const otherCookie='aaditech_session='+foreignToken;
 const foreignSupplier=randomUUID(),foreignSite=randomUUID();
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [foreignUser,'ek-proc-'+foreignUser+'@example.invalid',
   'Isolated procurement owner','test-only','OWNER']);
 await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
  VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
  [hashToken(foreignToken),foreignUser,csrf]);
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,status,created_by) VALUES (?,?,?,'REVIEWED_INTERNAL',?)`,
  [foreignSupplier,'EK'+foreignUser.replace(/-/g,'').slice(0,14).toUpperCase(),
   'Another owner internal synthetic supplier',foreignUser]);
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [foreignSite,'EKS'+foreignUser.replace(/-/g,'').slice(0,14).toUpperCase(),
   'Another owner private warehouse',foreignUser]);
 const ownSuppliers=await call('/api/procurement/suppliers');
 assert.equal(ownSuppliers.status,200);
 assert.equal(ownSuppliers.data.items.some((x:any)=>x.id===supplierId),true);
 assert.equal(ownSuppliers.data.items.some((x:any)=>x.id===foreignSupplier),false);
 // A second OWNER with a valid server-side session also cannot read A's supplier records.
 const headers={cookie:otherCookie};
 const response=await fetch(base+'/api/procurement/suppliers',{headers});
 assert.equal(response.status,200);
 const items=await response.json() as {items:{id:string}[]};
 assert.equal(items.items.some(x=>x.id===supplierId),false);
 assert.equal(items.items.some(x=>x.id===foreignSupplier),true);
 const otherRequest=await fetch(base+'/api/procurement/requests/'+requestId,{headers});
 assert.equal(otherRequest.status,404);
 const ownRequest=await call('/api/procurement/requests/'+requestId);
 assert.equal(ownRequest.status,200);
 const ownList=await call('/api/procurement/requests');
 assert.equal(ownList.status,200);
 assert.equal(ownList.data.items.some((x:any)=>x.id===requestId),true);
});
test('1EK known foreign supplier or warehouse UUIDs fail transactional procurement checks',async()=>{
 const [others]=await db.execute<any[]>(`SELECT s.id AS supplierId,i.id AS siteId
  FROM proc_suppliers s JOIN inventory_sites i ON i.created_by=s.created_by
  WHERE s.legal_name='Another owner internal synthetic supplier'`);
 assert.equal(others.length,1);
 const foreignSupplier=String(others[0].supplierId),
  foreignSite=String(others[0].siteId);
 const baseBody={supplierId,siteId,quoteEvidenceRef:'EK-CI-OWNER-SCOPE-QUOTE',
  items:[{productId,quantity:1,quotedUnitCost:'88.00'}]};
 for(const body of [
  {...baseBody,supplierId:foreignSupplier},
  {...baseBody,siteId:foreignSite}
 ]){
  const key=randomUUID();
  const denied=await call('/api/procurement/requests','POST',body,'owner',
   {idempotencyKey:key});
  assert.equal(denied.status,400);
  const [reservations]=await db.execute<any[]>(
   'SELECT COUNT(*) AS n FROM proc_request_keys WHERE actor_id=? AND request_key=?',
   [owner,key]);
  assert.equal(Number(reservations[0].n),0);
 }
 const [notPosted]=await db.execute<any[]>(
  'SELECT COUNT(*) AS n FROM proc_requests WHERE site_id=? AND created_by=?',
  [foreignSite,owner]);
 assert.equal(Number(notPosted[0].n),0);
 const [holds]=await db.execute<any[]>(
  'SELECT COUNT(*) AS n FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id WHERE r.site_id=?',
  [foreignSite]);
 assert.equal(Number(holds[0].n),0);
});


test('1EL unrelated owners remain invisible to appointed procurement reviewer',async()=>{
 const [owners]=await db.execute<any[]>(`SELECT created_by AS otherOwner
  FROM proc_suppliers WHERE legal_name='Another owner internal synthetic supplier'`);
 assert.equal(owners.length,1);
 const otherOwner=String(owners[0].otherOwner),foreignSupplier=randomUUID();
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,created_by) VALUES (?,?,?,?)`,
  [foreignSupplier,'EL'+randomUUID().replace(/-/g,'').slice(0,15).toUpperCase(),
   'Out-of-scope private supplier',otherOwner]);
 const queue=await call('/api/procurement/review/suppliers','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.equal(queue.data.items.some((s:any)=>s.id===foreignSupplier),false);
 const attempt=await call('/api/procurement/review/suppliers/'+foreignSupplier+'/attest',
  'POST',{evidenceRef:'EL-SPOOF-REVIEW-2026',attestIdentified:true},'reviewer');
 assert.equal(attempt.status,404);
 const [records]=await db.execute<any[]>(
  'SELECT status,reviewed_by FROM proc_suppliers WHERE id=?',[foreignSupplier]);
 assert.equal(records[0].status,'UNVERIFIED');
 assert.equal(records[0].reviewed_by,null);
});
test('1EL owner can revoke/regrant review access with transactional audit and no retroactive access',async()=>{
 const revoke={reviewerId:reviewer,scope:'PROCUREMENT',decision:'REVOKE',
  reason:'Owner withdraws internal CI reviewer assignment'};
 const revoked=await call('/api/reviewer-scopes','POST',revoke);
 assert.equal(revoked.status,201);
 assert.equal(revoked.data.state,'REVOKED');
 assert.equal((await call('/api/reviewer-scopes','POST',revoke)).status,409);
 const queue=await call('/api/procurement/review/requests','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.equal(queue.data.items.some((row:any)=>row.id===requestId),false);
 const hidden=await call('/api/procurement/review/requests/'+requestId,'GET',
  undefined,'reviewer');
 assert.equal(hidden.status,404);
 const restored=await call('/api/reviewer-scopes','POST',{
  ...revoke,decision:'GRANT',
  reason:'Owner reassigns same reviewer after isolated revocation test'});
 assert.equal(restored.status,201);
 assert.equal(restored.data.state,'ACTIVE');
 const visible=await call('/api/procurement/review/requests/'+requestId,
  'GET',undefined,'reviewer');
 assert.equal(visible.status,200);
 const [history]=await db.execute<any[]>(`SELECT decision FROM app_reviewer_scope_events
  WHERE owner_user_id=? AND reviewer_user_id=? AND workflow_scope='PROCUREMENT'
  ORDER BY recorded_at,id`,[owner,reviewer]);
 assert.equal(history.length,3);
 assert.deepEqual(history.map((x:any)=>x.decision).sort(),['GRANT','GRANT','REVOKE']);
 const [orgRows]=await db.execute<any[]>(
  'SELECT COUNT(*) AS n FROM app_organization_candidates');
 assert.equal(Number(orgRows[0].n),0);
});

test('1ER disabled or demoted OWNER cannot expose or authorize old PROCUREMENT nominations',async()=>{
 const queue='/api/procurement/review/requests';
 const detail=queue+'/'+requestId;
 const decision=detail+'/decide';
 const body={decision:'APPROVED_INTERNAL',
  reason:'Inactive original owner must make this known request inaccessible',
  evidenceAttested:true};
 assert.equal((await call(detail,'GET',undefined,'reviewer')).status,200);
 for(const [column,invalid,restore] of [
  ['status','DISABLED','ACTIVE'],['role','REVIEWER','OWNER']
 ] as const){
  await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[invalid,owner]);
  try{
   const hidden=await call(queue,'GET',undefined,'reviewer');
   assert.equal(hidden.status,200);
   assert.equal(hidden.data.items.some((row:any)=>row.id===requestId),false,
    column+' source owner must be filtered from queue');
   assert.equal((await call(detail,'GET',undefined,'reviewer')).status,404,
    column+' known ID read should deny');
   assert.equal((await call(decision,'POST',body,'reviewer')).status,404,
    column+' known ID write should deny before duplicate-decision check');
  }finally{
   await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[restore,owner]);
  }
  assert.equal((await call(detail,'GET',undefined,'reviewer')).status,200,
   'Restored source author state permits prior scoped read, not a new grant');
 }
});

test('1ES suspended or demoted nominating OWNER cannot create reviewer scopes',async()=>{
 const grant={reviewerId:reviewer,scope:'QUOTES',decision:'GRANT',
  reason:'Owner account status and role must block stale nominations'};
 const count=async(table:'app_reviewer_scope_grants'|'app_reviewer_scope_events')=>{
  const [rows]=await db.query<any[]>(
   'SELECT COUNT(*) AS n FROM '+table+
   " WHERE owner_user_id=? AND reviewer_user_id=? AND workflow_scope='QUOTES'",
   [owner,reviewer]);
  return Number(rows[0].n);
 };
 assert.equal(await count('app_reviewer_scope_grants'),0);
 assert.equal(await count('app_reviewer_scope_events'),0);
 for(const [column,invalid,restore,expectedStatus] of [
  ['status','DISABLED','ACTIVE',401],['role','REVIEWER','OWNER',403]
 ] as const){
  await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[invalid,owner]);
  try{
   const denied=await call('/api/reviewer-scopes','POST',grant);
   assert.equal(denied.status,expectedStatus,column+' ineligible owner must not nominate');
   assert.equal(await count('app_reviewer_scope_grants'),0,
    column+' denial cannot create a reviewer grant');
   assert.equal(await count('app_reviewer_scope_events'),0,
    column+' denial cannot create an audit event');
  }finally{
   await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[restore,owner]);
  }
 }
 const granted=await call('/api/reviewer-scopes','POST',grant);
 assert.equal(granted.status,201);
 assert.equal(granted.data.productionReleaseAuthorized,false);
 const revoked=await call('/api/reviewer-scopes','POST',{
  ...grant,decision:'REVOKE',reason:'Close isolated CI nomination after successful control test'});
 assert.equal(revoked.status,201);
 assert.equal(revoked.data.state,'REVOKED');
 assert.equal(await count('app_reviewer_scope_events'),2);
});

test('1ET reviewer disable withdraws every scope; enable never resurrects them; demoted identities remain revocable',async()=>{
 // All mutations remain first-party, synthetic, and isolated to aaditech_ci.
 const step=await call('/api/auth/step-up','POST',{currentPassword:ownerPass});
 assert.equal(step.status,200);
 ownerStep=String(step.data.stepUpToken);
 const target='/api/security/reviewers/'+reviewer+'/status';
 const rows=async()=>{
  const [grants]=await db.query<any[]>(
   'SELECT workflow_scope,state FROM app_reviewer_scope_grants WHERE reviewer_user_id=? AND owner_user_id=?',
   [reviewer,owner]);
  return grants as {workflow_scope:string;state:string}[];
 };
 assert.equal((await rows()).some(x=>x.workflow_scope==='PROCUREMENT'&&x.state==='ACTIVE'),true);
 // Stale owner authority must be denied even when the target is an active reviewer.
 for(const [column,invalid,restore,expected] of [
  ['status','DISABLED','ACTIVE',401],['role','REVIEWER','OWNER',403]
 ] as const){
  await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[invalid,owner]);
  try{
   const denied=await call(target,'PATCH',{status:'DISABLED'});
   assert.equal(denied.status,expected);
   assert.equal((await rows()).some(x=>x.workflow_scope==='PROCUREMENT'&&x.state==='ACTIVE'),true);
  }finally{
   await db.execute('UPDATE auth_users SET '+column+'=? WHERE id=?',[restore,owner]);
  }
 }
 const disabled=await call(target,'PATCH',{status:'DISABLED'});
 assert.equal(disabled.status,200);
 assert.equal(disabled.data.revokedWorkflowNominations,1);
 assert.equal(disabled.data.productionReleaseAuthorized,false);
 assert.equal(disabled.data.releaseDecision,'HOLD');
 assert.equal((await rows()).some(x=>x.state==='ACTIVE'),false);
 assert.equal((await call('/api/procurement/review/requests','GET',undefined,'reviewer')).status,401);
 const enabled=await call(target,'PATCH',{status:'ACTIVE'});
 assert.equal(enabled.status,200);
 assert.equal(enabled.data.revokedWorkflowNominations,0);
 // A newly authenticated reviewer still has no inherited procurement rights.
 await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
  VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
  [hashToken(reviewerToken),reviewer,csrf]);
 const queue=await call('/api/procurement/review/requests','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.equal(queue.data.items.some((x:any)=>x.id===requestId),false);
 const grant={reviewerId:reviewer,scope:'PROCUREMENT',decision:'GRANT',
  reason:'Fresh nomination after explicit disable and reenable lifecycle'};
 assert.equal((await call('/api/reviewer-scopes','POST',grant)).status,201);
 assert.equal((await call('/api/procurement/review/requests','GET',undefined,'reviewer'))
  .data.items.some((x:any)=>x.id===requestId),true);
 // A demoted identity can be manually revoked, but never granted anew.
 await db.execute("UPDATE auth_users SET role='OWNER' WHERE id=?",[reviewer]);
 try{
  assert.equal((await call('/api/reviewer-scopes','POST',{
   ...grant,decision:'REVOKE',reason:'Remove obsolete reviewer authority after account demotion'})).status,201);
  assert.equal((await call('/api/reviewer-scopes','POST',grant)).status,400);
 }finally{
  await db.execute("UPDATE auth_users SET role='REVIEWER' WHERE id=?",[reviewer]);
 }
 assert.equal((await rows()).some(x=>x.state==='ACTIVE'),false);
 assert.equal((await call('/api/procurement/review/requests','GET',undefined,'reviewer'))
  .data.items.some((x:any)=>x.id===requestId),false);
 const [events]=await db.query<any[]>(
  "SELECT event_type FROM auth_security_events WHERE actor_user_id=? AND target_user_id=? AND event_type IN ('REVIEWER_DISABLED','REVIEWER_ENABLED')",
  [owner,reviewer]);
 assert.equal(events.some((x:any)=>x.event_type==='REVIEWER_DISABLED'),true);
 assert.equal(events.some((x:any)=>x.event_type==='REVIEWER_ENABLED'),true);
});
