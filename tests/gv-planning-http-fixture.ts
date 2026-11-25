import type {TestContext} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {Pool,RowDataPacket} from 'mysql2/promise';
import {hashToken} from '../server/auth/crypto';
import {GV_TABLE} from '../server/internalPlanning/records';
const fixtures=[
  {
    "module": "M05",
    "input": {
      "lines": [
        {
          "sku": "S1",
          "quantity": 2,
          "unitPrice": "100.00",
          "gstRate": "18.00"
        }
      ],
      "discount": "10.00"
    },
    "changed": {
      "lines": [
        {
          "sku": "S1",
          "quantity": 2,
          "unitPrice": "100.00",
          "gstRate": "18.00"
        }
      ],
      "discount": "0"
    }
  },
  {
    "module": "M13",
    "input": {
      "orderReference": "SO-DRAFT",
      "items": [
        {
          "sku": "S1",
          "ordered": 4,
          "packed": 2
        }
      ],
      "packages": 1,
      "destinationPostalCode": "400001"
    },
    "changed": {
      "orderReference": "SO-DRAFT",
      "items": [
        {
          "sku": "S1",
          "ordered": 4,
          "packed": 4
        }
      ],
      "packages": 1,
      "destinationPostalCode": "400001"
    }
  },
  {
    "module": "M14",
    "input": {
      "invoiceReference": "INV-DRAFT",
      "receiptReference": "BANK-DRAFT",
      "invoiceAmount": "100.00",
      "receivedAmount": "100.00",
      "currency": "INR"
    },
    "changed": {
      "invoiceReference": "INV-DRAFT",
      "receiptReference": "BANK-DRAFT",
      "invoiceAmount": "100.00",
      "receivedAmount": "98.99",
      "currency": "INR"
    }
  },
  {
    "module": "M15",
    "input": {
      "serialReference": "SERIAL-01",
      "declaredStart": "2026-01-01",
      "declaredEnd": "2026-12-31",
      "claimDate": "2026-06-01",
      "purchaseEvidencePresent": true
    },
    "changed": {
      "serialReference": "SERIAL-01",
      "declaredStart": "2026-01-01",
      "declaredEnd": "2026-12-31",
      "claimDate": "2025-12-31",
      "purchaseEvidencePresent": true
    }
  },
  {
    "module": "M18",
    "input": {
      "tenantReference": "TENANT-DRAFT",
      "recordKind": "QUOTE",
      "requestedFields": [
        "displayReference",
        "totalEstimate"
      ],
      "consentRecorded": true
    },
    "changed": {
      "tenantReference": "TENANT-DRAFT",
      "recordKind": "ORDER",
      "requestedFields": [
        "quantity"
      ],
      "consentRecorded": true
    }
  },
  {
    "module": "M19",
    "input": {
      "partnerReference": "P1",
      "sku": "SKU1",
      "requestedPrice": "120",
      "minimumPrice": "100",
      "startsOn": "2026-01-01",
      "endsOn": "2026-01-31"
    },
    "changed": {
      "partnerReference": "P1",
      "sku": "SKU1",
      "requestedPrice": "100",
      "minimumPrice": "100",
      "startsOn": "2026-01-01",
      "endsOn": "2026-01-31"
    }
  },
  {
    "module": "M20",
    "input": {
      "partnerReference": "P1",
      "collected": "1000",
      "refunds": "100",
      "rate": "10",
      "cap": "100"
    },
    "changed": {
      "partnerReference": "P1",
      "collected": "1000",
      "refunds": "100",
      "rate": "10",
      "cap": "50"
    }
  },
  {
    "module": "M21",
    "input": {
      "channel": "EMAIL",
      "asOf": "2026-06-01",
      "recipients": [
        {
          "contactReference": "C1",
          "consentChannel": "EMAIL",
          "consentedOn": "2026-01-01",
          "expiresOn": "2026-12-31",
          "optedOut": false
        }
      ]
    },
    "changed": {
      "channel": "EMAIL",
      "asOf": "2026-06-01",
      "recipients": [
        {
          "contactReference": "C1",
          "consentChannel": "EMAIL",
          "consentedOn": "2026-01-01",
          "expiresOn": "2026-12-31",
          "optedOut": true
        }
      ]
    }
  },
  {
    "module": "M22",
    "input": {
      "action": "DRAFT",
      "targetReference": "T1",
      "humanReviewRequested": true
    },
    "changed": {
      "action": "READ_SUMMARY",
      "targetReference": "T1",
      "humanReviewRequested": true
    }
  },
  {
    "module": "M23",
    "input": {
      "observations": [
        {
          "month": "2026-01",
          "units": 1
        },
        {
          "month": "2026-02",
          "units": 2
        },
        {
          "month": "2026-03",
          "units": 4
        }
      ],
      "horizon": 2
    },
    "changed": {
      "observations": [
        {
          "month": "2026-01",
          "units": 1
        },
        {
          "month": "2026-02",
          "units": 2
        },
        {
          "month": "2026-03",
          "units": 4
        }
      ],
      "horizon": 3
    }
  },
  {
    "module": "M24",
    "input": {
      "jobReference": "JOB1",
      "attempt": 2,
      "maxAttempts": 5,
      "lastResult": "TRANSIENT_FAILURE",
      "idempotencyReference": "KEY1",
      "baseDelaySeconds": 30
    },
    "changed": {
      "jobReference": "JOB1",
      "attempt": 5,
      "maxAttempts": 5,
      "lastResult": "TRANSIENT_FAILURE",
      "idempotencyReference": "KEY1",
      "baseDelaySeconds": 30
    }
  },
  {
    "module": "M25",
    "input": {
      "documentReference": "DOC1",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rights": "DECLARED_OWNED",
      "scope": "INTERNAL",
      "requestedScope": "INTERNAL",
      "containsPersonalData": false
    },
    "changed": {
      "documentReference": "DOC1",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rights": "DECLARED_OWNED",
      "scope": "INTERNAL",
      "requestedScope": "RESTRICTED",
      "containsPersonalData": false
    }
  }
];
type Requester=(path:string,options?:RequestInit)=>Promise<{response:Response;data:any}>;
export async function gvExercisePlanningHttp(t:TestContext,db:Pool,request:Requester,ownerCookie:string,ownerCsrf:string,ownerId:string){
 const root='/api/internal-planning',prior=process.env.GV_PLANNING_FIXTURE,priorSsl=process.env.DB_SSL;
 const ids:string[]=[];let created=false;
 const seed=async(role:'OWNER'|'REVIEWER',mfa=true)=>{
  const id=randomUUID(),token=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
  await db.execute("INSERT INTO auth_users(id,email,full_name,password_hash,role,status) VALUES (?,?,?,'CI-INVALID-HASH',?,'ACTIVE')",[id,'gv-'+id+'@example.invalid','GV synthetic '+role,role]);ids.push(id);
  await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at,mfa_verified_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR),'+(mfa?'UTC_TIMESTAMP(3)':'NULL')+')',[hashToken(token),id,csrf]);return {cookie:'aaditech_session='+token,csrf,id,token};
 };
 const owner={cookie:ownerCookie,csrf:ownerCsrf},post=(path:string,payload:unknown,auth?:{cookie:string;csrf:string},key?:string)=>request(root+path,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{cookie:auth.cookie,'x-csrf-token':auth.csrf}:{}),...(key?{'Idempotency-Key':key}:{})},body:JSON.stringify(payload)});
 const get=(path:string,auth:{cookie:string})=>request(root+path,{headers:{cookie:auth.cookie}});
 try{
  process.env.GV_PLANNING_FIXTURE='NO';
  await t.test('1GV persistence disabled without explicit CI opt-in',async()=>{assert.equal((await post('/records/M05',fixtures[0].input,owner,randomUUID())).response.status,503);});
  // The enclosing smoke already verifies disposable CI; do not override TLS=true.
  if(process.env.DB_SSL===undefined)process.env.DB_SSL='false';
  process.env.GV_PLANNING_FIXTURE='YES';
  const [existing]=await db.query<RowDataPacket[]>('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?',[GV_TABLE]);assert.equal(existing.length,0);
  const ddl=readFileSync('database/authority/phase1gv_internal_planning_records_candidate.sql','utf8').split(/^-- statement-break$/m);assert.equal(ddl.length,3);await db.query(ddl[0]);created=true;for(const statement of ddl.slice(1))await db.query(statement);
  const other=await seed('OWNER'),reviewer=await seed('REVIEWER'),nonMfa=await seed('OWNER',false),ownIds:string[]=[];
  for(const f of fixtures){
   const prefix='1GV '+f.module+'-',key=randomUUID();let id='';
   await t.test(prefix+'01 authenticated preview',async()=>{const x=await post('/'+f.module,f.input,owner);assert.equal(x.response.status,200);assert.equal(x.response.headers.get('cache-control'),'no-store');assert.equal(x.data.module,f.module);assert.equal(x.data.externalExecutionEnabled,false);assert.equal(x.data.productionReleaseAuthorized,false);});
   await t.test(prefix+'02 invalid payload',async()=>{assert.equal((await post('/'+f.module,{...f.input,approved:true},owner)).response.status,400);});
   await t.test(prefix+'03 missing CSRF',async()=>{const x=await request(root+'/'+f.module,{method:'POST',headers:{cookie:ownerCookie,'Content-Type':'application/json'},body:JSON.stringify(f.input)});assert.equal(x.response.status,403);});
   await t.test(prefix+'04 unauthenticated preview',async()=>{assert.equal((await post('/'+f.module,f.input)).response.status,401);});
   await t.test(prefix+'05 reviewer denied',async()=>{assert.equal((await post('/'+f.module,f.input,reviewer)).response.status,403);});
   await t.test(prefix+'06 durable creation',async()=>{const x=await post('/records/'+f.module,f.input,owner,key);assert.equal(x.response.status,201);assert.equal(x.data.replayed,false);assert.equal(x.data.result.releaseDecision,'HOLD');id=x.data.id;ownIds.push(id);});
   await t.test(prefix+'07 canonical replay',async()=>{const x=await post('/records/'+f.module,Object.fromEntries(Object.entries(f.input).reverse()),owner,key);assert.equal(x.response.status,200);assert.equal(x.data.replayed,true);assert.equal(x.data.id,id);});
   await t.test(prefix+'08 conflicting key',async()=>{assert.equal((await post('/records/'+f.module,f.changed,owner,key)).response.status,409);});
   await t.test(prefix+'09 cross-owner read denied',async()=>{assert.equal((await get('/records/'+id,other)).response.status,404);});
   await t.test(prefix+'10 owner read',async()=>{const x=await get('/records/'+id,owner);assert.equal(x.response.status,200);assert.equal(x.data.id,id);assert.equal(x.data.result.module,f.module);assert.equal(x.data.result.evidenceStatus,'OPERATOR_SUPPLIED_UNVERIFIED');});
  }
  await t.test('1GV actor-scoped list and exact twelve stored rows',async()=>{const x=await get('/records',owner),foreign=await get('/records',other);assert.equal(x.response.status,200);assert.deepEqual(new Set(x.data.items.map((v:any)=>v.id)),new Set(ownIds));assert.deepEqual(foreign.data.items,[]);});
  await t.test('1GV non-MFA owner cannot persist',async()=>{assert.equal((await post('/records/M05',fixtures[0].input,nonMfa,randomUUID())).response.status,403);});
  await t.test('1GV concurrent same-key creation yields one row',async()=>{const key=randomUUID(),a=await Promise.all([post('/records/M05',fixtures[0].input,owner,key),post('/records/M05',fixtures[0].input,owner,key)]);assert.deepEqual(a.map(x=>x.response.status).sort(),[200,201]);assert.equal(a[0].data.id,a[1].data.id);const [rows]=await db.execute<RowDataPacket[]>('SELECT COUNT(*) AS n FROM '+GV_TABLE+' WHERE actor_id=? AND request_key=?',[ownerId,key]);assert.equal(Number(rows[0].n),1);});
  await t.test('1GV immutable stored records reject raw mutation and deletion',async()=>{for(const sql of ['UPDATE '+GV_TABLE+' SET result_sha256=result_sha256 WHERE id=?','DELETE FROM '+GV_TABLE+' WHERE id=?'])await assert.rejects(db.execute(sql,[ownIds[0]]),(e:any)=>e?.code==='ER_SIGNAL_EXCEPTION'&&e?.sqlMessage==='GV_RECORD_IMMUTABLE');});
  await t.test('1GV invalid ID and missing idempotency key',async()=>{assert.equal((await get('/records/not-an-id',owner)).response.status,400);assert.equal((await post('/records/M05',fixtures[0].input,owner)).response.status,400);});
  await t.test('1GV revoked secondary session cannot read records',async()=>{await db.execute('DELETE FROM auth_sessions WHERE token_hash=?',[hashToken(other.token)]);assert.equal((await get('/records',other)).response.status,401);});
 }finally{
  if(prior===undefined)delete process.env.GV_PLANNING_FIXTURE;else process.env.GV_PLANNING_FIXTURE=prior;
  if(priorSsl===undefined)delete process.env.DB_SSL;else process.env.DB_SSL=priorSsl;
  if(created)await db.query('DROP TABLE '+GV_TABLE);
  for(const id of ids){await db.execute('DELETE FROM auth_sessions WHERE user_id=?',[id]);await db.execute('DELETE FROM auth_users WHERE id=?',[id]);}
 }
}
