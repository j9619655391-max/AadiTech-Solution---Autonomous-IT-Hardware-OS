import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, newSecret, hashToken } from '../server/auth/crypto';

test('password hashing uses randomized salt and verifies correct password', async () => {
  const password = 'example long owner password 123';
  const first = await hashPassword(password);
  const second = await hashPassword(password);
  assert.notEqual(first, second);
  assert.equal(await verifyPassword(password, first), true);
  assert.equal(await verifyPassword('wrong password', first), false);
});

test('malformed password hashes rejected, weak passwords not accepted', async () => {
  await assert.rejects(hashPassword('weak'), /14 characters/);
  assert.equal(await verifyPassword('something long enough', 'bad:hash'), false);
});

test('session token generation is random and stored token hash is deterministic', () => {
  const first = newSecret();
  const second = newSecret();
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first, second);
  assert.equal(hashToken(first), hashToken(first));
  assert.notEqual(hashToken(first), first);
});
