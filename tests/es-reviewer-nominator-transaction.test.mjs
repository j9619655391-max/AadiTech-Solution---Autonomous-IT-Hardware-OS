import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Phase 1ES is a code-level transaction contract. Hosted disposable MySQL
// tests exercise endpoint suspension, not a proof of all possible races.
test('1ES nomination transaction must lock active nominating OWNER first',()=>{
 const source=readFileSync('server/security/reviewerScopeRouter.ts','utf8');
 const begin=source.indexOf('await conn.beginTransaction()');
 const owner=source.indexOf("'SELECT id,role,status FROM auth_users WHERE id=? FOR UPDATE',[owner]");
 const reviewer=source.indexOf("'SELECT id,role,status FROM auth_users WHERE id=? FOR UPDATE',[reviewerId]");
 const audit=source.indexOf('INSERT INTO app_reviewer_scope_events');
 const commit=source.indexOf('await conn.commit()');
 assert.ok(begin>=0&&begin<owner&&owner<reviewer&&reviewer<audit&&audit<commit,
  'owner and reviewer locks must precede any grant or audit commit');
 const guard=source.slice(owner,reviewer);
 assert.match(guard,/sourceOwners\.length!==1/);
 assert.match(guard,/sourceOwners\[0\]\.role!=='OWNER'/);
 assert.match(guard,/sourceOwners\[0\]\.status!=='ACTIVE'/);
 assert.match(guard,/await conn\.rollback\(\);res\.status\(403\)/);
 assert.ok(source.includes('router.use(requireOwner)'),'keep request-level owner authentication');
 assert.ok(source.includes("productionReleaseAuthorized:false,releaseDecision:'HOLD'"));
});
