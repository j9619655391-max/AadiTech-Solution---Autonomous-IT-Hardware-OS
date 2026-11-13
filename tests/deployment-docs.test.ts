import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

test('hosting documentation explicitly withdraws destructive legacy import instructions',()=>{
 const doc=readFileSync('HOSTINGER_DEPLOYMENT_GUIDE.md','utf8');
 assert.match(doc,/Do \*\*not\*\* import or execute/);
 assert.match(doc,/DB_SSL=true/);
 assert.match(doc,/APP_TRUSTED_PROXY_CIDRS/);
 assert.match(doc,/NOT PRODUCTION READY/);
 assert.doesNotMatch(doc,/Choose File.*upload\s+\/database\/schema\.sql/i);
});
test('example environment is not production and documents secure production contract',()=>{
 const env=readFileSync('.env.example','utf8');
 assert.match(env,/^NODE_ENV=development$/m);
 assert.match(env,/^# APP_REQUIRE_HTTPS=true$/m);
 assert.match(env,/^# MFA_REQUIRE_PRIVILEGED=true$/m);
 assert.match(env,/^# APP_TRUSTED_PROXY_CIDRS=/m);
 assert.match(env,/^# DB_SSL_CA_BASE64=/m);
});
