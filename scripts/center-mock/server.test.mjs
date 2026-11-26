import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { createPreviewServer } from './server.mjs';

async function start(t, scenario) {
  const server = createPreviewServer(scenario).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const request = (path, init) => fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    signal: AbortSignal.timeout(3000), ...init,
  });
  const api = async (path, method = 'GET', data, status = 200) => {
    const res = await request(`/admin/api/${path}`, {
      method, ...(data === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
    });
    assert.equal(res.status, status, `${method} ${path}`);
    return res.json();
  };
  return { request, api };
}

test('serves the real frontend shell and independent Mock data', async (t) => {
  const { request, api } = await start(t);
  const html = await request('/admin/');
  assert.equal(html.headers.get('Cache-Control'), 'no-store');
  assert.match(await html.text(), /MOCK · 演示数据/);
  assert.match((await request('/admin/assets/app.js')).headers.get('Content-Type'), /javascript/);
  assert.match((await request('/admin/assets/acl_values.js')).headers.get('Content-Type'), /javascript/);
  assert.equal((await request('/api/v1/admin/nodes')).status, 404);
  assert.equal((await request('/admin/api/overview', { headers: { Origin: 'https://example.invalid' } })).status, 403);

  assert.equal((await api('session')).authenticated, true);
  const overview = await api('overview');
  assert.equal(overview.authorization.version, 7);
  assert.equal(overview.counts.members, 6);
  assert.ok(overview.topology.links.length > 0);
  const queue = await api('requests?page=2&size=15');
  assert.equal(queue.total, 18);
  assert.equal(queue.items.length, 3);
  const sh = await api('nodes?q=sh-gateway&status=member');
  const detail = await api(`nodes/${encodeURIComponent(sh.items[0].nodeKey)}`);
  assert.ok(detail.signed && detail.reported && detail.inventory);
  assert.notEqual(detail.inventory.transports.find((t) => t.proto === 'quic').port, detail.reported.transportPorts.quic);
  assert.equal((await api('drafts')).filter((d) => d.valid).length, 1);
  assert.equal((await api('audit?size=15&page=2')).items.length, 4);
});

test('draft, inventory and application code actions are in-memory only', async (t) => {
  const { api } = await start(t);
  const current = await api('policy/active');
  const { draft } = await api('drafts', 'POST', { fromActive: true }, 201);
  assert.equal(draft.policy.acl.acls.length, 3);
  const [request] = (await api('requests')).items;
  const updated = await api(`drafts/${draft.id}/members`, 'POST', { nodeKey: request.nodeKey });
  assert.equal(updated.draft.policy.members.length, current.snapshot.members.length + 1);
  assert.equal((await api(`drafts/${draft.id}/export`)).members.length, updated.draft.policy.members.length);
  assert.deepEqual((await api('policy/active')).snapshot, current.snapshot);

  const key = encodeURIComponent(request.nodeKey);
  await api(`nodes/${key}/inventory`, 'PUT', { note: 'Mock inventory update' });
  assert.equal((await api(`nodes/${key}`)).inventory.note, 'Mock inventory update');
  await api(`nodes/${key}/inventory`, 'DELETE');
  assert.equal((await api(`nodes/${key}`)).inventory, null);

  const created = await api('keys', 'POST', { label: '临时演示', ttlHours: 24 }, 201);
  assert.match(created.key, /^demo-only-/);
  await api(`keys/${created.row.id}/revoke`, 'POST');
  assert.equal((await api('keys')).find((k) => k.id === created.row.id).state, 'revoked');
  const separate = await start(t);
  assert.equal((await separate.api('drafts')).length, 2);
  assert.ok(!(await separate.api('keys')).some((k) => k.id === created.row.id));
});

test('Mock ACL editing keeps destination addresses and ports distinct without publishing', async (t) => {
  const { api } = await start(t);
  const active = await api('policy/active');
  const [draft] = await api('drafts');
  const { draft: before } = await api(`drafts/${draft.id}`);
  const acl = { ...before.policy.acl, acls: [
    { action: 'accept', proto: 'tcp', src: ['node:1'], dst: ['[2001:db8::/64]:443, 8000-8010', 'node:2'] },
  ] };
  const saved = await api(`drafts/${draft.id}/acl`, 'POST', acl);
  assert.deepEqual(saved.draft.policy, { ...before.policy, acl });
  assert.deepEqual(saved.analysis.rules.slice(0, 3).map(({ ports }) => ports), ['443', '8000-8010', '*']);
  assert.deepEqual(saved.analysis.rules[0].dst, ['2001:db8::/64']);
  assert.match(saved.analysis.rules[2].dst[0], /hk-edge/);
  assert.deepEqual(await api('policy/active'), active);
});

test('only the bundled demo envelope can be previewed and published', async (t) => {
  const { request, api } = await start(t);
  const sample = await (await request('/mock/authorization.json')).json();
  const result = await api('authorization/preview', 'POST', { ...sample, signature: 'other' });
  assert.equal(result.valid, false);
  await api('authorization', 'POST', { ...sample, payload: 'other' }, 400);
  const preview = await api('authorization/preview', 'POST', sample);
  assert.equal(preview.valid, true);
  assert.equal(preview.diff.added[0].name, 'sh-ci-runner');
  const published = await api('authorization', 'POST', sample);
  assert.equal(published.version, 8);
  assert.equal((await api('authorization', 'POST', sample)).idempotent, true);
  assert.equal((await api('authorization/history/8')).active, true);
  assert.equal((await api('overview')).counts.requests, 17);
});

test('supports empty, expired, setup and login states without real credentials', async (t) => {
  const empty = await start(t, 'empty');
  assert.equal((await empty.api('overview')).authorization, null);
  assert.deepEqual(await empty.api('drafts'), []);
  const expired = await start(t, 'expired');
  assert.equal((await expired.api('overview')).authorization.expired, true);

  const setup = await start(t, 'setup');
  assert.equal((await setup.api('session')).setupPending, true);
  const trust = await (await setup.request('/mock/trust.json')).json();
  assert.match(trust.publicKey, /^0{64}$/);
  const preview = await setup.api('setup/preview', 'POST', trust);
  assert.equal(preview.networkId.length, 64);
  await setup.api('setup', 'POST', { trust, confirm: true });
  assert.equal((await setup.api('session')).setupPending, false);

  const login = await start(t, 'login');
  assert.equal((await login.api('session')).authenticated, false);
  await login.api('login', 'POST', { password: 'wrong' }, 401);
  assert.equal((await login.api('login', 'POST', { password: 'mock-preview' })).authenticated, true);
  assert.equal((await login.api('logout', 'POST')).authenticated, false);
});
