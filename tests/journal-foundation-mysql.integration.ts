import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/journalFoundation/ownerRouter';
import reviewRouter from '../server/journalFoundation/reviewRouter';
import {readHeldGrnSource} from '../server/stockFoundation/integrity';
import {releaseSnapshot,releaseHoldSnapshot} from '../server/stockFoundation/validation';
import {claimDigest,heldGrnSnapshot} from '../server/evidenceChain/validation';
import {checkHeldSource,checkClaim,checkQuarantine,makePack} from '../server/evidenceChain/integrity';
import {dispatchManifest,sha} from '../server/dispatch/validation';
import {validateInbound,canonicalIntakeHash} from '../server/intake/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Journal foundation integration allowed only on disposable CI MySQL');
const db=getPool();if(!db)throw Error('Disposable CI database required');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),
 reviewerToken=newSecret(),csrf=newSecret(),ownerPass='CI-evidence-owner-2026-pass',
 reviewerPass='CI-evidence-reviewer-2026-pass';
let ownerStep='',reviewerStep='',base='';
let close:(()=>Promise<void>)|undefined;
after(async()=>{if(close)await close();await db.end();});
type Fixture={preparationId:string;outboxId:string;holdId:string;observationId:string;
 supplierId:string;productId:string;lotProductId:string;claimId?:string};
let a:Fixture,b:Fixture,c:Fixture;
async function call(path:string,method='GET',body?:unknown,as:'owner'|'reviewer'|'anon'='owner',
 opts:{csrf?:boolean;stepUp?:boolean}={}){
 const headers:Record<string,string>={};
 if(as!=='anon')headers.cookie='aaditech_session='+(as==='owner'?ownerToken:reviewerToken);
 if(body!==undefined)headers['content-type']='application/json';
 if(method!=='GET'&&opts.csrf!==false)headers['x-csrf-token']=csrf;
 if(opts.stepUp!==false){
  const token=as==='owner'?ownerStep:reviewerStep;
  if(token)headers['x-step-up-token']=token;
 }
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON response'};}}
 return {status:response.status,data};
}
async function fixture(label:string):Promise<Fixture>{
 const supplierId=randomUUID(),productId=randomUUID(),lotProductId=randomUUID();
 const siteId=randomUUID(),requestId=randomUUID(),reviewId=randomUUID(),
  holdId=randomUUID(),destinationId=randomUUID(),preparationId=randomUUID(),
  dispatchReviewId=randomUUID(),outboxId=randomUUID(),observationId=randomUUID(),
  inspectionId=randomUUID();
 const code='EC'+randomUUID().replace(/-/g,'').slice(0,12).toUpperCase();
 const email='ec-'+randomUUID().replace(/-/g,'').slice(0,10)+'@example.invalid';
 await db.execute(`INSERT INTO inventory_sites(id,code,name,created_by)
  VALUES(?,?,?,?)`,[siteId,code,'Isolated CI '+label,owner]);
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,status,evidence_ref,created_by,reviewed_by)
  VALUES(?,?,?,'REVIEWED_INTERNAL',?,?,?)`,
  [supplierId,code,'CI internal only '+label,'SUPPLIER-ID-REF-2026',owner,reviewer]);
 const skus=[{productId,sku:'EC-SER-'+productId,name:'CI serial server',quantity:2,
  quotedUnitCost:'100.00',lineSubtotal:'200.00'},
 {productId:lotProductId,sku:'EC-LOT-'+lotProductId,name:'CI lot component',quantity:3,
  quotedUnitCost:'20.00',lineSubtotal:'60.00'}];
 for(const l of skus){
  await db.execute(`INSERT INTO crm_products
   (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,hsn)
   VALUES(?,?,?,?,'SERVER',?,'20.00','120.00','20.00','8471')`,
   [l.productId,l.sku,'CI',l.name,'No real stock']);
 }
 await db.execute(`INSERT INTO proc_requests
  (id,supplier_id,site_id,created_by,quote_evidence_ref,subtotal,status)
  VALUES(?,?,?,?,?,'260.00','APPROVED_INTERNAL')`,
  [requestId,supplierId,siteId,owner,'SYNTH-QUOTE-EVID-2026']);
 for(let i=0;i<skus.length;i++){
  const l=skus[i];
  await db.execute(`INSERT INTO proc_request_items
   (id,request_id,position,product_id,sku_snapshot,name_snapshot,quantity,
    quoted_unit_cost,line_subtotal) VALUES (?,?,?,?,?,?,?,?,?)`,
   [randomUUID(),requestId,i+1,l.productId,l.sku,l.name,l.quantity,
    l.quotedUnitCost,l.lineSubtotal]);
 }
 await db.execute(`INSERT INTO proc_review_decisions
  (id,request_id,reviewer_id,decision,reason,evidence_attested)
  VALUES(?,?,?,'APPROVED_INTERNAL',?,1)`,
  [reviewId,requestId,reviewer,'CI internal synthetic purchase review']);
 const hold={format:'aaditech-internal-po-hold-v1',requestId,supplierId,
  supplierCode:code,supplierName:'CI internal only '+label,siteId,
  supplierQuoteEvidenceRef:'SYNTH-QUOTE-EVID-2026',subtotal:'260.00',
  reviewId,lines:skus};
 const holdSha=sha(JSON.stringify(hold));
 await db.execute(`INSERT INTO proc_po_holds
  (id,request_id,decision_id,prepared_by,snapshot_sha256,snapshot_json)
  VALUES(?,?,?,?,?,?)`,
  [holdId,requestId,reviewId,owner,holdSha,JSON.stringify(hold)]);
 await db.execute(`INSERT INTO proc_delivery_destinations
  (id,supplier_id,email,evidence_ref,status,created_by,reviewed_by,review_evidence_ref,review_reason)
  VALUES(?,?,?,?,'REVIEWED_INTERNAL',?,?,?,?)`,
  [destinationId,supplierId,email,'SYNTH-CONTACT-REF-2026',owner,reviewer,
   'REVIEWED-CONTACT-REF-2026','Internally reviewed but unverified email address']);
 const manifest=dispatchManifest({holdId,holdSha256:holdSha,destinationId,
  supplierId,email,authorizationEvidenceRef:'SYNTH-DISP-AUTH-2026'});
 const manifestSha=sha(JSON.stringify(manifest));
 await db.execute(`INSERT INTO proc_dispatch_preparations
  (id,hold_id,destination_id,prepared_by,authorization_evidence_ref,
   hold_sha256,manifest_sha256,manifest_json,status)
  VALUES(?,?,?,?,?,?,?,?,'APPROVED_INTERNAL')`,
  [preparationId,holdId,destinationId,owner,'SYNTH-DISP-AUTH-2026',
   holdSha,manifestSha,JSON.stringify(manifest)]);
 await db.execute(`INSERT INTO proc_dispatch_review_decisions
  (id,preparation_id,reviewer_id,decision,reason,evidence_ref,destination_attested)
  VALUES (?,?,?,'APPROVED_INTERNAL',?,?,1)`,
  [dispatchReviewId,preparationId,reviewer,'Synthetic internal dispatch review',
   'SYNTH-DISPATCH-REVIEW-2026']);
 const outbox={format:'aaditech-supplier-PO-outbox-HELD-v1',preparationId,
  manifestSha256:manifestSha,decisionId:dispatchReviewId,
  dispatchState:'DISABLED',externalPoIssued:false};
 await db.execute(`INSERT INTO proc_dispatch_outbox_holds
  (id,preparation_id,decision_id,snapshot_sha256,snapshot_json)
  VALUES(?,?,?,?,?)`,
  [outboxId,preparationId,dispatchReviewId,sha(JSON.stringify(outbox)),JSON.stringify(outbox)]);
 const items=[{productId,quantity:2,trackingMode:'SERIAL',lotCode:null,
   serialNumbers:[('EC-'+label+'-'+randomUUID().replace(/-/g,'').slice(0,12)).toUpperCase(),
    ('EC-'+label+'-'+randomUUID().replace(/-/g,'').slice(0,12)).toUpperCase()]},
  {productId:lotProductId,quantity:3,trackingMode:'LOT',lotCode:'LOT-'+label.toUpperCase()+'-2026',serialNumbers:[]}];
 const intake=validateInbound({holdId,deliveryEvidenceRef:'SYNTH-DELIVERY-REF-2026',
  physicalCountRef:'SYNTH-COUNT-REF-2026',items});
 const obsHash=canonicalIntakeHash({...intake,
  items:[...intake.items].sort((x,y)=>x.productId.localeCompare(y.productId))});
 await db.execute(`INSERT INTO inv_inbound_observations
  (id,hold_id,request_id,site_id,recorded_by,delivery_evidence_ref,physical_count_ref,
   payload_sha256,status) VALUES(?,?,?,?,?,?,?,?,'QUARANTINED_INTERNAL')`,
  [observationId,holdId,requestId,siteId,owner,intake.deliveryEvidenceRef,
   intake.physicalCountRef,obsHash]);
 await db.execute(`INSERT INTO inv_inbound_decisions
  (id,observation_id,reviewer_id,outcome,inspection_evidence_ref,reason)
  VALUES(?,?,?,'ACCEPT_QUARANTINE',?,?)`,
  [inspectionId,observationId,reviewer,'SYNTH-INSPECTION-2026',
   'CI internally inspected synthetic quarantine units']);
 for(const l of items){
  const lineId=randomUUID();
  await db.execute(`INSERT INTO inv_inbound_lines
   (id,observation_id,product_id,quantity,tracking_mode,lot_code,serials_json)
   VALUES(?,?,?,?,?,?,?)`,
   [lineId,observationId,l.productId,l.quantity,l.trackingMode,l.lotCode,
    JSON.stringify(l.serialNumbers)]);
  await db.execute(`INSERT INTO inv_quarantine_custody_events
   (id,observation_id,line_id,site_id,product_id,quantity,recorded_by)
   VALUES(?,?,?,?,?,?,?)`,
   [randomUUID(),observationId,lineId,siteId,l.productId,l.quantity,reviewer]);
  for(const serial of l.serialNumbers){
   await db.execute(`INSERT INTO inv_quarantine_serials
    (id,observation_id,product_id,site_id,serial_number) VALUES(?,?,?,?,?)`,
    [randomUUID(),observationId,l.productId,siteId,serial]);
  }
 }
 return {preparationId,outboxId,holdId,observationId,supplierId,productId,lotProductId};
}
function claimBody(f:Fixture){
 return {preparationId:f.preparationId,supplierAckRef:'CLAIM-ONLY-2026-'+f.preparationId.slice(0,8).toUpperCase(),
  evidenceRef:'CLAIM-DOC-REF-2026',documentSha256:sha('Synthetic offline claimant evidence '+f.preparationId)};
}
const attest={decision:'ATTESTED_INTERNAL',reason:'Inspected the operator supplied claim document and recorded discrepancies',
 reviewEvidenceRef:'REVIEW-DOCUMENT-2026',documentInspected:true};
const holdDecision={decision:'HELD_INTERNAL',reason:'Inspected internal quarantined serial and lot custody; GRN remains held',
 reviewEvidenceRef:'INTERNAL-GRN-WITNESS-2026',custodyInspected:true};


type HeldFixture=Fixture&{heldGrnId:string;claimId:string;packId:string};
let main:HeldFixture,second:HeldFixture;
async function withHeldSource(f:Fixture):Promise<HeldFixture>{
 const conn=await db.getConnection();await conn.beginTransaction();
 try{
  const src=await checkHeldSource(conn,f.preparationId);
  const claimId=randomUUID(),claimData={
   preparationId:f.preparationId,supplierAckRef:'SYNTH-ACK-'+randomUUID().slice(0,8).toUpperCase(),
   evidenceRef:'SYNTH-CLAIM-REF-2026',
   documentSha256:sha('UNVERIFIED-SYNTH-DOC-'+f.preparationId)};
  const claimSha=claimDigest(claimData,src.outboxSha256);
  await conn.execute(`INSERT INTO proc_ack_claims
   (id,preparation_id,outbox_id,recorded_by,supplier_ack_ref,evidence_ref,
    document_sha256,outbox_sha256,claim_sha256,status)
   VALUES (?,?,?,?,?,?,?,?,?,'ATTESTED_INTERNAL')`,
   [claimId,f.preparationId,src.outboxId,owner,claimData.supplierAckRef,
    claimData.evidenceRef,claimData.documentSha256,src.outboxSha256,claimSha]);
  await conn.execute(`INSERT INTO proc_ack_claim_decisions
   (id,claim_id,reviewer_id,decision,reason,review_evidence_ref,document_inspected)
   VALUES (?,?,?,'ATTESTED_INTERNAL',?,?,1)`,
   [randomUUID(),claimId,reviewer,'Synthetic internal supplier document checked',
    'SYNTH-ACK-REVIEW-2026']);
  const claimed=await checkClaim(conn,claimId,src);
  const observation=await checkQuarantine(conn,f.observationId,src);
  const pack=makePack(src,claimed,observation),packId=randomUUID(),
   decisionId=randomUUID(),packSha=sha(JSON.stringify(pack));
  await conn.execute(`INSERT INTO inv_grn_reconciliation_packs
   (id,claim_id,observation_id,prepared_by,pack_sha256,pack_json,status)
   VALUES (?,?,?,?,?,?,'HELD_INTERNAL')`,
   [packId,claimId,f.observationId,owner,packSha,JSON.stringify(pack)]);
  await conn.execute(`INSERT INTO inv_grn_reconciliation_decisions
   (id,pack_id,reviewer_id,decision,reason,review_evidence_ref,custody_inspected)
   VALUES (?,?,?,'HELD_INTERNAL',?,?,1)`,
   [decisionId,packId,reviewer,'Synthetic internal GRN evidence checked',
    'SYNTH-GRN-WITNESS-2026']);
  const heldGrnId=randomUUID(),held=heldGrnSnapshot(packId,packSha,decisionId);
  await conn.execute(`INSERT INTO inv_grn_held_records
   (id,pack_id,decision_id,snapshot_sha256,snapshot_json)
   VALUES (?,?,?,?,?)`,
   [heldGrnId,packId,decisionId,sha(JSON.stringify(held)),JSON.stringify(held)]);
  await conn.commit();return {...f,heldGrnId,claimId,packId};
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}

async function stockRelease(f:HeldFixture):Promise<string>{
 const conn=await db.getConnection();await conn.beginTransaction();
 try{
  const source=await readHeldGrnSource(conn,f.heldGrnId);
  const snapshot=releaseSnapshot(source),digest=sha(JSON.stringify(snapshot));
  const id=randomUUID(),reviewId=randomUUID();
  for(const l of source.lines)await conn.execute(`INSERT IGNORE INTO inv_stock_position_gates
    (site_id,product_id) VALUES(?,?)`,[source.siteId,l.productId]);
  await conn.execute(`INSERT INTO inv_stock_release_intents
   (id,held_grn_id,observation_id,site_id,prepared_by,source_sha256,
    intent_sha256,intent_json,status)
   VALUES(?,?,?,?,?,?,?,?,'REVIEWED_HELD')`,
   [id,source.heldGrnId,source.observationId,source.siteId,owner,
    source.heldGrnSha256,digest,JSON.stringify(snapshot)]);
  for(const l of source.lines)await conn.execute(`INSERT INTO inv_stock_release_intent_lines
   (id,release_intent_id,product_id,site_id,observed_quantity,tracking_mode,
    lot_code,serials_json) VALUES(?,?,?,?,?,?,?,?)`,
   [randomUUID(),id,l.productId,source.siteId,l.quantity,l.trackingMode,
    l.lotCode,JSON.stringify([...l.serialNumbers].sort())]);
  await conn.execute(`INSERT INTO inv_stock_release_decisions
   (id,release_intent_id,reviewer_id,decision,reason,evidence_ref,source_inspected)
   VALUES(?,?,?,'REVIEWED_HELD',?,?,1)`,
   [reviewId,id,reviewer,'Independent CI synthetic evidence held only',
    'EVIDENCE-REVIEW-CI-2026']);
  const hold=releaseHoldSnapshot(id,digest,reviewId);
  await conn.execute(`INSERT INTO inv_stock_release_holds
   (id,release_intent_id,decision_id,snapshot_sha256,snapshot_json)
   VALUES(?,?,?,?,?)`,[randomUUID(),id,reviewId,sha(JSON.stringify(hold)),JSON.stringify(hold)]);
  await conn.commit();return id;
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
let releaseA='',releaseB='',journalA='',journalB='';
test('CI: establish complete synthetic HELD-only 1AC–1AG provenance, no supplier or sellable inventory',async()=>{
 for(const [id,token,role,password] of [[owner,ownerToken,'OWNER',ownerPass],
  [reviewer,reviewerToken,'REVIEWER',reviewerPass]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
   [id,'journal-'+id+'@example.invalid','Journal Evidence CI',
    await hashPassword(password),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 main=await withHeldSource(await fixture('JOURNAL_A'));
 second=await withHeldSource(await fixture('JOURNAL_B'));
 releaseA=await stockRelease(main);releaseB=await stockRelease(second);
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/journal-foundation/review',reviewRouter);
 app.use('/api/journal-foundation',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('roles, step-up, CSRF and exact data shape reject unauthorized journal creation',async()=>{
 const body={releaseIntentId:releaseA};
 assert.equal((await call('/api/journal-foundation/eligible','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/journal-foundation/eligible','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/journal-foundation/review/journals','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/journal-foundation/journals','POST',body)).status,403);
 assert.equal((await call('/api/journal-foundation/journals','POST',body,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/journal-foundation/journals','POST',body,'reviewer')).status,403);
 const [u,v]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass}),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(u.status,200);assert.equal(v.status,200);
 ownerStep=String(u.data.stepUpToken);reviewerStep=String(v.data.stepUpToken);
 assert.equal((await call('/api/journal-foundation/journals','POST',
  {...body,postNow:true})).status,400);
 const eligible=await call('/api/journal-foundation/eligible');
 assert.equal(eligible.status,200);assert.equal(eligible.data.actualLedgerEnabled,false);
 assert.ok(eligible.data.items.some((x:any)=>x.releaseIntentId===releaseA));
});
test('upstream held release tamper refuses journal; concurrent exact create yields one paired manifest',async()=>{
 const [before]=await db.query<any[]>(`SELECT snapshot_sha256 FROM inv_stock_release_holds
  WHERE release_intent_id=?`,[releaseA]);
 await db.execute(`UPDATE inv_stock_release_holds SET snapshot_sha256=?
  WHERE release_intent_id=?`,['a'.repeat(64),releaseA]);
 assert.equal((await call('/api/journal-foundation/journals','POST',
  {releaseIntentId:releaseA})).status,409);
 await db.execute(`UPDATE inv_stock_release_holds SET snapshot_sha256=?
  WHERE release_intent_id=?`,[before[0].snapshot_sha256,releaseA]);
 const pair=await Promise.all([
  call('/api/journal-foundation/journals','POST',{releaseIntentId:releaseA}),
  call('/api/journal-foundation/journals','POST',{releaseIntentId:releaseA})]);
 assert.deepEqual(pair.map(x=>x.status).sort(),[200,201]);
 assert.equal(pair[0].data.id,pair[1].data.id);journalA=pair[0].data.id;
 const [legs]=await db.query<any[]>(`SELECT product_id,account_code,entry_side,
  quantity,posting_state FROM inv_unposted_journal_legs WHERE journal_id=?
  ORDER BY product_id,account_code`,[journalA]);
 assert.equal(legs.length,4);
 for(let i=0;i<legs.length;i+=2){
  assert.equal(legs[i].product_id,legs[i+1].product_id);
  assert.equal(Number(legs[i].quantity),Number(legs[i+1].quantity));
  assert.equal(legs[i].posting_state,'DISABLED');
  assert.equal(legs[i+1].posting_state,'DISABLED');
 }
 const [serial]=await db.query<any[]>(`SELECT provenance_state,ownership_state
  FROM inv_unposted_serial_candidates WHERE journal_id=?`,[journalA]);
 assert.equal(serial.length,2);
 assert.ok(serial.every(r=>r.provenance_state==='UNVERIFIED'&&r.ownership_state==='NOT_ESTABLISHED'));
 const secondCreated=await call('/api/journal-foundation/journals','POST',
  {releaseIntentId:releaseB});
 assert.equal(secondCreated.status,201);journalB=secondCreated.data.id;
 const [blockers]=await db.query<any[]>(`SELECT * FROM inv_unposted_source_blockers WHERE journal_id=?`,
  [journalA]);
 assert.equal(blockers.length,1);
 assert.equal(blockers[0].external_po_verified,'NO');
 assert.equal(blockers[0].official_grn_verified,'NO');
 assert.equal(blockers[0].stock_credit_state,'DISABLED');
});
test('MySQL enums and uniqueness refuse fake externally verified supplier, serial title and duplicate claim',async()=>{
 await assert.rejects(db.execute(`UPDATE inv_unposted_source_blockers
  SET official_grn_verified='YES' WHERE journal_id=?`,[journalA]));
 await assert.rejects(db.execute(`UPDATE inv_unposted_serial_candidates
  SET ownership_state='ESTABLISHED' WHERE journal_id=?`,[journalA]));
 await assert.rejects(db.execute(`UPDATE inv_unposted_journal_headers
  SET posting_state='ENABLED' WHERE id=?`,[journalA]));
 const [serials]=await db.query<any[]>(`SELECT product_id,site_id,serial_number
  FROM inv_unposted_serial_candidates WHERE journal_id=? LIMIT 1`,[journalA]);
 await assert.rejects(db.execute(`INSERT INTO inv_unposted_serial_candidates
  (id,journal_id,product_id,site_id,serial_number) VALUES (?,?,?,?,?)`,
  [randomUUID(),journalB,serials[0].product_id,serials[0].site_id,serials[0].serial_number]));
 const [positions]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,
  picked_quantity,posted_quantity FROM inv_stock_position_gates`);
 assert.ok(positions.length>=4);
 assert.ok(positions.every(r=>Object.values(r).every(x=>Number(x)===0)));
});
test('independent reviewer rejects altered/unbalanced legs and serial substitutions',async()=>{
 const url='/api/journal-foundation/review/journals/'+journalA+'/decide';
 const body={decision:'REVIEWED_HELD',
  reason:'Independently reviewed balanced quarantine and candidate evidence pairs',
  evidenceRef:'CI-UNPOSTED-JOURNAL-REVIEW-2026',balancingInspected:true};
 assert.equal((await call(url,'POST',body,'owner')).status,403);
 assert.equal((await call(url,'POST',{...body,balancingInspected:false},'reviewer')).status,400);
 assert.equal((await call(url,'POST',body,'reviewer',{csrf:false})).status,403);
 assert.equal((await call(url,'POST',body,'reviewer',{stepUp:false})).status,403);
 const [leg]=await db.query<any[]>(`SELECT id,quantity FROM inv_unposted_journal_legs
  WHERE journal_id=? LIMIT 1`,[journalA]);
 await db.execute('UPDATE inv_unposted_journal_legs SET quantity=quantity+1 WHERE id=?',[leg[0].id]);
 assert.equal((await call(url,'POST',body,'reviewer')).status,409);
 await db.execute('UPDATE inv_unposted_journal_legs SET quantity=? WHERE id=?',
  [leg[0].quantity,leg[0].id]);
 const [serial]=await db.query<any[]>(`SELECT id,serial_number FROM inv_unposted_serial_candidates
  WHERE journal_id=? LIMIT 1`,[journalA]);
 await db.execute('UPDATE inv_unposted_serial_candidates SET serial_number=? WHERE id=?',
  ['FORGED-JOURNAL-2026',serial[0].id]);
 assert.equal((await call(url,'POST',body,'reviewer')).status,409);
 await db.execute('UPDATE inv_unposted_serial_candidates SET serial_number=? WHERE id=?',
  [serial[0].serial_number,serial[0].id]);
 const decision=await call(url,'POST',body,'reviewer');
 assert.equal(decision.status,201);assert.equal(decision.data.status,'REVIEWED_HELD');
 assert.equal(decision.data.stockPosted,0);assert.equal(decision.data.postingState,'DISABLED');
 assert.equal((await call(url,'POST',body,'reviewer')).status,409);
 const [held]=await db.query<any[]>(`SELECT state,posting_state,snapshot_json
  FROM inv_unposted_journal_holds WHERE journal_id=?`,[journalA]);
 assert.equal(held.length,1);assert.equal(held[0].state,'HELD');
 assert.equal(held[0].posting_state,'DISABLED');
 assert.equal(held[0].snapshot_json.stockPosted,false);
 assert.equal((await call('/api/journal-foundation/review/journals/'+journalB+'/decide',
  'POST',{...body,decision:'REJECTED_INTERNAL',balancingInspected:false},'reviewer')).status,201);
 const [rejected]=await db.query<any[]>(`SELECT COUNT(*) AS n
  FROM inv_unposted_journal_holds WHERE journal_id=?`,[journalB]);
 assert.equal(Number(rejected[0].n),0);
});
test('all operational stock debit, warehouse movement, and supplier authority remain blocked',async()=>{
 assert.equal((await call('/api/journal-foundation/debit-attempt','POST',
  {journalId:journalA,productId:main.productId,quantity:1})).status,409);
 assert.equal((await call('/api/journal-foundation/debit-attempt','POST',
  {journalId:journalA,productId:main.productId,quantity:-1})).status,400);
 assert.equal((await call('/api/journal-foundation/post','POST',{})).status,404);
 assert.equal((await call('/api/journal-foundation/warehouse-transfer','POST',{})).status,404);
 const auth=await call('/api/journal-foundation/authority');
 assert.equal(auth.status,200);
 assert.equal(auth.data.operationalDoubleEntryLedgerEnabled,false);
 assert.equal(auth.data.serialOwnershipEstablished,false);
 assert.equal(auth.data.supplierAcknowledgmentAuthenticated,false);
 assert.equal(auth.data.officialGrnVerified,false);
 assert.equal(auth.data.availableToSell,null);
});
