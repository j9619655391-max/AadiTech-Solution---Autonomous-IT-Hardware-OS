import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { requireOwner } from '../server/auth/router';

test('anonymous sensitive routes fail closed without MySQL/session', async () => {
  const app = express();
  app.use('/api/ai', requireOwner);
  app.use('/api/db', requireOwner);
  app.use('/api/hostinger', requireOwner);
  app.post('/api/ai/command', (_req,res) => res.json({ secret: true }));
  app.get('/api/db/status', (_req,res) => res.json({ secret: true }));
  app.get('/api/hostinger/readiness', (_req,res) => res.json({ secret: true }));
  const listener = app.listen(0, '127.0.0.1');
  try {
    const address = listener.address();
    assert.ok(address && typeof address !== 'string');
    for (const [method, route] of [['POST','/api/ai/command'],['GET','/api/db/status'],['GET','/api/hostinger/readiness']]) {
      const response = await fetch('http://127.0.0.1:' + address.port + route, { method });
      assert.equal(response.status, 401);
      assert.equal((await response.json()).error, 'Authentication required');
    }
  } finally {
    await new Promise<void>((resolve,reject) => listener.close(e => e ? reject(e) : resolve()));
  }
});
