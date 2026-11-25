import test from 'node:test';
import assert from 'node:assert/strict';
import {privilegedMfaRequired} from '../server/auth/mfaPolicy';
import {getDatabaseConfig} from '../server/db';

test('privileged MFA policy is explicit and rejects malformed settings',()=>{
 const saved=process.env.MFA_REQUIRE_PRIVILEGED;
 try{
  delete process.env.MFA_REQUIRE_PRIVILEGED;
  assert.equal(privilegedMfaRequired(),false);
  process.env.MFA_REQUIRE_PRIVILEGED='true';
  assert.equal(privilegedMfaRequired(),true);
  process.env.MFA_REQUIRE_PRIVILEGED='false';
  assert.equal(privilegedMfaRequired(),false);
  process.env.MFA_REQUIRE_PRIVILEGED='yes';
  assert.throws(()=>privilegedMfaRequired(),/true or false/);
 }finally{
  if(saved===undefined)delete process.env.MFA_REQUIRE_PRIVILEGED;
  else process.env.MFA_REQUIRE_PRIVILEGED=saved;
 }
});
test('MySQL TLS rejects invalid settings and verifies certificates',()=>{
 const oldSsl=process.env.DB_SSL,oldCa=process.env.DB_SSL_CA_BASE64;
 try{
  process.env.DB_SSL='true';delete process.env.DB_SSL_CA_BASE64;
  assert.deepEqual(getDatabaseConfig().ssl,{rejectUnauthorized:true});
  const pem='-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----';
  process.env.DB_SSL_CA_BASE64=Buffer.from(pem).toString('base64');
  assert.deepEqual(getDatabaseConfig().ssl,{rejectUnauthorized:true,ca:pem});
  process.env.DB_SSL='false';
  assert.throws(()=>getDatabaseConfig(),/requires DB_SSL=true/);
  delete process.env.DB_SSL_CA_BASE64;
  process.env.DB_SSL='banana';
  assert.throws(()=>getDatabaseConfig(),/DB_SSL must/);
 }finally{
  if(oldSsl===undefined)delete process.env.DB_SSL;else process.env.DB_SSL=oldSsl;
  if(oldCa===undefined)delete process.env.DB_SSL_CA_BASE64;else process.env.DB_SSL_CA_BASE64=oldCa;
 }
});
