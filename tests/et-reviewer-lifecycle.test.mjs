import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// The source contract complements real disposable-MySQL/HTTP lifecycle coverage.
test('1ET security-admin transaction locks the active acting OWNER before target reviewer',()=>{
 const src=readFileSync('server/security/adminRouter.ts','utf8');
 const begin=src.indexOf('await conn.beginTransaction()');
 const actor=src.indexOf("'SELECT id,role,status FROM auth_users WHERE id=? FOR UPDATE',[actorId]");
 const target=src.indexOf("'SELECT id,role,status,email FROM auth_users WHERE id=? FOR UPDATE',[req.params.id]");
 assert.ok(begin>=0&&begin<actor&&actor<target);
 const guard=src.slice(actor,target);
 for(const condition of ["actors.length!==1","actors[0].role!=='OWNER'","actors[0].status!=='ACTIVE'"])
  assert.ok(guard.includes(condition),condition);
 assert.match(guard,/await conn.rollback\(\);res.status\(403\)/);
 assert.ok(src.includes('router.use(requireOwner)'));
});
test('1ET disabling reviewer withdraws ACTIVE nominations before commit; reenable cannot restore them',()=>{
 const src=readFileSync('server/security/adminRouter.ts','utf8');
 const disable=src.indexOf("if(input.status==='DISABLED')");
 const revoke=src.indexOf("UPDATE app_reviewer_scope_grants SET state='REVOKED' WHERE reviewer_user_id=? AND state='ACTIVE'");
 const commit=src.indexOf('await conn.commit()');
 assert.ok(disable>=0&&disable<revoke&&revoke<commit);
 assert.ok(src.includes('revokedWorkflowNominations=grants.affectedRows'));
 assert.ok(!src.includes("SET state='ACTIVE'"));
 assert.ok(src.includes("productionReleaseAuthorized:false,releaseDecision:'HOLD'"));
});
test('1ET demotion cannot block owner revocation of an existing app-local scope',()=>{
 const src=readFileSync('server/security/reviewerScopeRouter.ts','utf8');
 assert.match(src,/if\(!users.length\|\|\(decision==='GRANT'&&/);
 assert.match(src,/users\[0\].role!=='REVIEWER'\|\|users\[0\].status!=='ACTIVE'/);
 assert.match(src,/decision==='REVOKE'&&prior!=='ACTIVE'/);
 assert.ok(src.includes('INSERT INTO app_reviewer_scope_events'));
});
