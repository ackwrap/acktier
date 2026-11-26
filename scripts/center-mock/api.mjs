import { buildFixtures, emptyPolicy, hour, mockController, mockTrust, networkId } from './fixtures.mjs';
import { policyAnalysis, publicationView } from './policy.mjs';

export const mockPassword = 'mock-preview';
export const scenarios = ['demo', 'empty', 'expired', 'setup', 'login'];

const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const stringList = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string');
const now = () => new Date().toISOString();
const ok = (body, status = 200, headers) => ({ status, body, headers });
const done = () => ok({ ok: true });
const error = (status, code, message) => ok({ error: { code, message } }, status);
const missing = () => error(404, 'not_found', '没有这条 Mock 记录或接口。');

function filteredPage(items, params, fields) {
  const q = (params.get('q') ?? '').trim().toLowerCase();
  const filtered = q ? items.filter((item) => fields(item).some((v) => String(v ?? '').toLowerCase().includes(q))) : items;
  const positive = (key, fallback) => {
    const n = Number(params.get(key));
    return Number.isSafeInteger(n) && n > 0 ? n : fallback;
  };
  const size = Math.min(200, positive('size', 25));
  const page = positive('page', 1);
  const start = Math.min(filtered.length, (page - 1) * size);
  return { items: filtered.slice(start, start + size), total: filtered.length, page, size };
}

function acceptablePolicy(p) {
  return object(p) && Array.isArray(p.members) && p.members.every((m) => object(m) &&
    typeof m.name === 'string' && typeof m.ipv4 === 'string' && typeof m.nodeKey === 'string' &&
    (m.tags == null || stringList(m.tags)) && (m.routes == null || stringList(m.routes))) &&
    (p.acl == null || (object(p.acl) && (p.acl.acls == null || Array.isArray(p.acl.acls))));
}

export function createMockAPI(scenario) {
  const s = buildFixtures(scenario);
  const demoEnvelope = {
    payload: Buffer.from(JSON.stringify({ mock: true, ...publicationView(s.nextPublication).snapshot })).toString('base64'),
    signature: Buffer.alloc(64, 1).toString('base64'),
  };
  const files = new Map([
    ['trust.json', mockTrust], ['authorization.json', demoEnvelope], ['controller-trust.json', mockController],
  ]);
  const active = () => s.history[0];
  const members = () => active()?.policy.members ?? [];
  const authorization = () => active() ? publicationView(active()).authorization : null;
  const audit = (action, target = '', detail = '') => {
    s.audit.unshift({ at: now(), actor: 'web@mock', action, target, result: 'success', detail });
  };
  const session = () => ({
    authenticated: s.authenticated, setupPending: s.setupPending, passwordConfigured: true,
    ...(s.authenticated ? { csrf: 'mock-csrf', expiresAt: new Date(Date.now() + 8 * hour).toISOString() } : {}),
  });

  function rows() {
    const signed = new Map(members().map((m) => [m.nodeKey, m]));
    return [...new Set([...signed.keys(), ...s.reports.keys()])].map((key) => {
      const m = signed.get(key);
      const r = s.reports.get(key);
      return {
        nodeKey: key, status: m ? 'member' : r?.keyRevoked ? 'revoked' : 'request',
        name: m?.name, memberId: m?.id, ipv4: m?.ipv4, tags: m?.tags,
        hostname: r?.hostname, os: r?.os, online: r?.online ?? false, reported: Boolean(r), lastSeen: r?.lastSeen,
        transportPorts: r?.transportPorts, transports: r?.transports ?? [], endpoints: r?.endpoints.length ?? 0,
        advertisedRoutes: r?.advertisedRoutes ?? [], inventory: s.inventories.has(key),
      };
    });
  }

  function overview() {
    const nodes = members().map((m) => {
      const r = s.reports.get(m.nodeKey);
      return { key: m.nodeKey, name: m.name, ip: m.ipv4, online: r?.online ?? false, canRelay: r?.canRelay ?? false };
    });
    return {
      networkId, minimumVersion: mockTrust.minimumVersion, authorization: authorization(),
      counts: {
        requests: rows().filter((r) => r.status === 'request').length, members: nodes.length,
        membersOnline: nodes.filter((n) => n.online).length, records: s.reports.size,
        drafts: s.drafts.length, keysActive: s.keys.filter((k) => k.state === 'active').length,
      },
      relay: s.relay, revision: s.revision, topology: { nodes, links: s.links },
      recentAudit: s.audit.slice(0, 6), serverTime: now(),
    };
  }

  function nodeDetail(key) {
    const signed = members().find((m) => m.nodeKey === key) ?? null;
    const reported = s.reports.get(key) ?? null;
    const signedRoutes = signed?.routes ?? [];
    const reportedRoutes = reported?.advertisedRoutes ?? [];
    const auth = authorization();
    return {
      nodeKey: key, signed, reported, inventory: s.inventories.get(key) ?? null, authorization: auth,
      flags: {
        missingReport: !reported, offline: Boolean(reported && !reported.online), revoked: reported?.keyRevoked ?? false,
        notMember: !signed, authorizationExpired: auth?.expired ?? false,
        unapprovedRoutes: signed && reported ? reportedRoutes.filter((r) => !signedRoutes.includes(r)) : [],
        unadvertisedRoutes: signed && reported ? signedRoutes.filter((r) => !reportedRoutes.includes(r)) : [],
      },
    };
  }

  function drafts(method, id, action, key, body) {
    const analysis = (d) => policyAnalysis(d.policy, d.baseVersion, active());
    if (method === 'GET' && !id) {
      const summaries = s.drafts.toSorted((a, b) => b.updatedAt.localeCompare(a.updatedAt)).map(({ policy, ...d }) => {
        const result = analysis({ ...d, policy });
        return { ...d, baseStale: result.baseStale, valid: result.valid, members: policy.members.length, aclRules: policy.acl?.acls?.length ?? 0 };
      });
      return ok(summaries);
    }
    const storeDraft = (d, type, status = 200) => {
      const at = s.drafts.findIndex((v) => v.id === d.id);
      const updated = { ...d, updatedAt: now() };
      if (at === -1) s.drafts.unshift(updated);
      else s.drafts[at] = updated;
      audit(type, d.id, d.name);
      return ok({ draft: updated, analysis: analysis(updated) }, status);
    };
    if (method === 'POST' && !id) {
      if (s.drafts.length >= 32) return error(409, 'too_many_drafts', 'Mock 草稿已达上限。');
      if (!body.policy && active() && !body.fromActive) {
        return error(409, 'policy_source_required', '请导入完整的策略 JSON，或基于当前快照新建草稿。');
      }
      const policy = body.policy ?? active()?.policy ?? emptyPolicy();
      if (!acceptablePolicy(policy)) return error(400, 'invalid_policy', '需要包含 members 数组的策略 JSON。');
      return storeDraft({
        id: `draft_mock_new_${s.nextId++}`, name: typeof body.name === 'string' ? body.name : '新建 Mock 策略草稿',
        note: typeof body.note === 'string' ? body.note : '', baseVersion: active()?.version ?? 0,
        policy: structuredClone(policy), createdAt: now(),
      }, 'draft.create', 201);
    }
    const current = s.drafts.find((d) => d.id === id);
    if (!current) return missing();
    if (method === 'GET' && !action) return ok({ draft: current, analysis: analysis(current) });
    if (method === 'GET' && action === 'export') {
      if (!analysis(current).valid) return error(409, 'invalid_draft', '这个 Mock 草稿有校验错误，请修正后再导出。');
      return ok(current.policy, 200, { 'Content-Disposition': `attachment; filename="${id}-policy.json"` });
    }
    if (method === 'DELETE' && !action) {
      s.drafts = s.drafts.filter((d) => d.id !== id);
      audit('draft.delete', id);
      return done();
    }
    if (method === 'PUT' && !action) {
      const policy = body.policy ?? current.policy;
      if (!acceptablePolicy(policy)) return error(400, 'invalid_policy', '策略格式不正确。');
      return storeDraft({
        ...current, policy, name: typeof body.name === 'string' && body.name ? body.name : current.name,
        note: typeof body.note === 'string' ? body.note : current.note,
        baseVersion: body.rebase ? active()?.version ?? 0 : current.baseVersion,
      }, 'draft.update');
    }
    if (method === 'POST' && action === 'acl') {
      const policy = { ...current.policy, acl: body };
      if (!acceptablePolicy(policy) || !analysis({ ...current, policy }).valid) {
        return error(400, 'invalid_acl', 'Mock ACL 格式、动作或业务协议不正确。');
      }
      return storeDraft({ ...current, policy }, 'draft.acl');
    }
    if (action === 'members') {
      const currentMembers = current.policy.members;
      if (method === 'DELETE' && key) {
        return storeDraft({ ...current, policy: { ...current.policy, members: currentMembers.filter((m) => m.nodeKey !== key) } }, 'draft.remove_member');
      }
      if (method === 'POST' && !key) {
        const row = rows().find((r) => r.nodeKey === body.nodeKey && r.status !== 'revoked');
        if (!row) return missing();
        if (currentMembers.some((m) => m.nodeKey === row.nodeKey)) return error(409, 'member_conflict', '此节点已在当前草稿中。');
        const id = 1 + Math.max(0, ...currentMembers.map((m) => Number(m.id) || 0));
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        const ipv4 = typeof body.ipv4 === 'string' ? body.ipv4.trim() : '';
        const added = {
          id, nodeKey: row.nodeKey, name: (name || row.name || row.hostname).toLowerCase(),
          ipv4: ipv4 || row.ipv4 || `100.64.8.${id}`,
          tags: stringList(body.tags) ? body.tags : [], routes: stringList(body.routes) ? body.routes : [],
        };
        return storeDraft({ ...current, policy: { ...current.policy, members: [...currentMembers, added] } }, 'draft.add_member');
      }
    }
    return missing();
  }

  function publish(method, id, key, body) {
    if (method === 'GET' && id === 'history') {
      const entries = s.history.map((r) => ({ ...publicationView(r).authorization, active: r === active() }));
      if (!key) return ok(entries);
      const record = s.history.find((r) => String(r.version) === key);
      if (!record) return missing();
      const view = publicationView(record);
      return ok({ ...view.authorization, active: record === active(), snapshot: view.snapshot, rules: view.rules });
    }
    if (method !== 'POST' || (id && id !== 'preview')) return missing();
    if (body.payload !== demoEnvelope.payload || body.signature !== demoEnvelope.signature) {
      const reason = 'Mock 仅接受本预览提供的 /mock/authorization.json，不执行真实验签。';
      return id === 'preview' ? ok({ valid: false, reason }) : error(400, 'mock_envelope_only', reason);
    }
    const next = s.nextPublication;
    const idempotent = active() === next;
    const view = publicationView(next);
    if (id === 'preview') {
      return ok({ valid: true, idempotent, ...view, diff: policyAnalysis(next.policy, active()?.version ?? 0, active()).diff });
    }
    if (!idempotent) {
      next.publishedAt = now();
      s.history.unshift(next);
      s.revision++;
      audit('authorization.publish', `v${next.version}`, '模拟发布');
    }
    return ok({ version: next.version, idempotent, authorization: authorization() });
  }

  function dispatch(method, [resource, id, action, key], params, body) {
    if (method === 'GET' && resource === 'session') return ok(session());
    if (method === 'POST' && resource === 'login') {
      if (body.password !== mockPassword) return error(401, 'bad_password', '请使用 Mock 演示密码 mock-preview，不要输入真实凭据。');
      s.authenticated = true;
      return ok(session());
    }
    if (!s.authenticated) return error(401, 'unauthenticated', '请先登录 Mock 管理台。');
    if (method === 'POST' && resource === 'logout') {
      s.authenticated = false;
      return ok(session());
    }
    if (method === 'POST' && resource === 'setup' && s.setupPending) {
      const trust = id === 'preview' ? body : body.trust;
      if (trust?.publicKey !== mockTrust.publicKey || trust?.minimumVersion !== mockTrust.minimumVersion) {
        return error(400, 'mock_trust_only', '请使用此预览提供的 /mock/trust.json。');
      }
      if (id === 'preview') return ok({ ...mockTrust, networkId });
      if (body.confirm !== true) return error(400, 'unconfirmed', '请先确认 Mock 组网指纹。');
      s.setupPending = false;
      audit('owner.bind', networkId, 'Mock 绑定');
      return done();
    }
    if (s.setupPending) return error(409, 'setup_pending', '请先完成 Mock 初始化。');
    if (method === 'GET' && resource === 'overview') return ok(overview());
    if (method === 'GET' && (resource === 'requests' || (resource === 'nodes' && !id))) {
      const status = resource === 'requests' ? 'request' : params.get('status');
      const items = rows().filter((r) => !status || r.status === status);
      return ok(filteredPage(items, params, (r) => [r.name, r.hostname, r.os, r.nodeKey, r.ipv4]));
    }
    if (resource === 'nodes' && id) {
      const key = id.startsWith('nodekey:') ? id : `nodekey:${id}`;
      const detail = nodeDetail(key);
      if (!detail.signed && !detail.reported) return missing();
      if (method === 'GET' && !action) return ok(detail);
      if (method === 'PUT' && action === 'inventory') {
        const { transports = [], endpoints = [], routes = [], note = '' } = body;
        if (!Array.isArray(transports) || !transports.every((t) => typeof t?.proto === 'string' && Number.isInteger(t.port)) ||
          !Array.isArray(endpoints) || !endpoints.every((e) => typeof e?.proto === 'string' && typeof e.addr === 'string') ||
          !stringList(routes) || typeof note !== 'string') {
          return error(400, 'invalid_inventory', '能力清单的传输、地址、网段或备注格式不正确。');
        }
        const inv = {
          nodeKey: key, importedAt: now(), routes, note,
          transports: transports.map(({ proto, port }) => ({ proto, port })),
          endpoints: endpoints.map(({ proto, addr }) => ({ proto, addr })),
        };
        s.inventories.set(key, inv);
        audit('inventory.import', key);
        return ok(inv);
      }
      if (method === 'DELETE' && action === 'inventory') {
        if (!s.inventories.delete(key)) return missing();
        audit('inventory.delete', key);
        return done();
      }
    }
    if (method === 'GET' && resource === 'policy' && id === 'active') {
      return ok(active() ? { hasActive: true, ...publicationView(active()) } : { hasActive: false, authorization: null, snapshot: null, rules: [] });
    }
    if (method === 'POST' && resource === 'policy' && id === 'validate') {
      if (!acceptablePolicy(body.policy)) return error(400, 'invalid_policy', '策略格式不正确。');
      return ok(policyAnalysis(body.policy, body.baseVersion ?? active()?.version ?? 0, active()));
    }
    if (resource === 'drafts') return drafts(method, id, action, key, body);
    if (resource === 'authorization') return publish(method, id, action, body);
    if (method === 'GET' && resource === 'audit') {
      return ok(filteredPage(s.audit, params, (a) => [a.action, a.actor, a.target, a.detail, a.result]));
    }
    if (method === 'GET' && resource === 'keys') return ok(s.keys);
    if (method === 'POST' && resource === 'keys' && !id) {
      const ttl = Number(body.ttlHours);
      if (typeof body.label !== 'string' || !body.label.trim() || !Number.isInteger(ttl) || ttl < 1 || ttl > 720) {
        return error(400, 'invalid_key', '请填写备注与 1–720 小时有效期。');
      }
      const seq = s.nextId++;
      const row = {
        id: `key_mock_new_${seq}`, label: body.label, state: 'active', reusable: !!body.reusable,
        usedCount: 0, createdAt: now(), expiresAt: new Date(Date.now() + ttl * hour).toISOString(),
      };
      s.keys.unshift(row);
      audit('key.create', row.id);
      return ok({ key: `demo-only-request-${seq}`, row }, 201);
    }
    if (method === 'POST' && resource === 'keys' && action === 'revoke') {
      const row = s.keys.find((k) => k.id === id);
      if (!row) return missing();
      row.state = 'revoked';
      audit('key.revoke', id);
      return done();
    }
    if (resource === 'delegation') {
      if (method === 'GET') return ok(s.delegation);
      if (method === 'DELETE') {
        s.delegation = { enabled: false, updatedAt: now() };
        audit('delegation.disable');
        return done();
      }
      if (method === 'PUT') {
        if (body.publicKey !== mockController.publicKey || body.networkId !== networkId || body.proof !== mockController.proof) {
          return error(400, 'mock_controller_only', '请使用此预览提供的 /mock/controller-trust.json。');
        }
        s.delegation = { enabled: true, publicKey: mockController.publicKey, label: mockController.label, updatedAt: now() };
        audit('delegation.enable', mockController.label);
        return ok(s.delegation);
      }
    }
    if (method === 'POST' && resource === 'password') {
      return error(501, 'mock_only', 'Mock 不保存或修改管理员密码；请勿输入真实凭据。');
    }
    return missing();
  }

  return { dispatch, files };
}
