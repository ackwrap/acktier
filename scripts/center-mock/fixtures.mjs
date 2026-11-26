import { createHash } from 'node:crypto';

export const hour = 3_600_000;
export const hash = (label) => createHash('sha256').update(`acktier-ui-fixture:${label}`).digest('hex');
export const nodeKey = (name) => `nodekey:${hash(name)}`;
// An all-zero key has the right shape for the UI, but real owner setup rejects it.
export const mockTrust = { publicKey: '0'.repeat(64), minimumVersion: 1 };
export const networkId = createHash('sha256').update(Buffer.from(mockTrust.publicKey, 'hex')).digest('hex');
export const mockController = {
  networkId, publicKey: hash('controller-public'), label: '演示运维工作站',
  proof: Buffer.alloc(64, 2).toString('base64url'),
};

export const emptyPolicy = () => ({
  members: [], acl: { acls: [] }, dns: { enableMagicDNS: true, magicDNSSuffix: 'ack.internal' },
});

const devices = [
  ['sh-gateway', 'Linux', 11, ['tag:relay', 'tag:infra'], { udp: 51820, quic: 41000, tcp: 443 }],
  ['hk-edge', 'Linux', 12, ['tag:relay'], { quic: 41001, wss: 443 }],
  ['office-nas', 'Linux', 13, ['tag:storage'], { tcp: 41002 }],
  ['dev-laptop', 'Windows', 21, ['tag:dev'], { udp: 41641, tcp: 41003 }],
  ['design-mac', 'macOS', 22, ['tag:design'], { udp: 41641, wss: 8443 }],
  ['backup-node', '', 31, ['tag:storage'], {}],
];

const requestNames = [
  'sh-ci-runner', 'macbook-demo', 'hangzhou-nas', 'beijing-branch', 'field-laptop', 'dev-container',
  'build-windows', 'test-station-a', 'lab-raspberry', 'guest-laptop', 'iPad-demo', 'hk-spare',
  'su-devbox', 'kvm-host', 'render-worker', 'ci-arm64', 'test-station-b', 'warehouse-gateway',
];

const auditEvents = [
  ['authorization.publish', 'v7', 'success', '模拟首发 · 6 个已签成员'],
  ['node.register', 'sh-ci-runner', 'success', '已收到模拟申请'],
  ['draft.update', '上海 CI 接入', 'success', '添加构建机，仅草稿'],
  ['inventory.import', 'sh-gateway', 'success', '上海机房台账'],
  ['authorization.publish', 'v6', 'failure', '演示：拒绝旧版本'],
  ['key.create', 'key_mock_sh', 'success', '单次 · 24h'],
  ['key.revoke', 'key_mock_old', 'success', '演示：已吊销'],
  ['delegation.enable', '演示运维工作站', 'success', 'Mock 控制端'],
  ['owner.bind', '演示组网', 'success', '仅模拟'],
];

export function buildFixtures(scenario, now = Date.now()) {
  const iso = (hours) => new Date(now + hours * hour).toISOString();
  const populated = scenario !== 'empty' && scenario !== 'setup';
  const reports = new Map();
  const inventories = new Map();

  function report(name, os, octet, transportPorts, options = {}) {
    const transports = Object.keys(transportPorts).toSorted();
    reports.set(nodeKey(name), {
      hostname: options.hostname ?? name, os, transportPorts, transports,
      online: options.online ?? true, canRelay: options.canRelay ?? false, keyRevoked: options.revoked ?? false,
      lastSeen: iso(options.lastSeen ?? -1 / 120), createdAt: iso(-188), links: [],
      endpoints: transports.map((proto) => ({ proto, addr: `203.0.113.${octet}:${transportPorts[proto]}` })),
      advertisedRoutes: options.routes ?? [],
    });
  }

  const members = devices.map(([name, os, octet, tags, ports], i) => {
    const routes = i === 0 ? ['192.168.20.0/24', '192.168.21.0/24'] : [];
    if (populated && os) {
      report(name, os, octet, ports, {
        canRelay: i < 2, online: i !== 2, lastSeen: i === 2 ? -11 : -(i + 1) / 120,
        hostname: i === 3 ? 'WIN-DEV-42' : name, routes: i === 0 ? ['192.168.20.0/24', '10.42.0.0/16'] : [],
      });
    }
    return { id: i + 1, nodeKey: nodeKey(name), name, ipv4: `100.64.0.${octet}`, ipv6: `fd7a:115c:a1e0::${octet}`, tags, routes };
  });
  for (const [i, name] of (populated ? requestNames : []).entries()) {
    report(name, ['Linux', 'Windows', 'Linux', 'macOS', 'iOS'][i % 5], i + 50,
      i % 4 === 3 ? {} : { udp: 42000 + i, [i % 2 ? 'quic' : 'tcp']: 43000 + i },
      { online: i % 4 !== 3, lastSeen: -(i + 1) / 10, routes: i % 5 === 0 ? [`192.168.${40 + i}.0/24`] : [] });
  }

  const links = [
    [0, 1, 27.3, 0.002, 'quic'], [0, 3, 8.4, 0, 'udp'],
    [1, 3, 39.7, 0.01, 'tcp'], [1, 4, 47.2, 0.026, 'wss'],
  ].map(([i, j, rttMs, loss, proto]) => ({
    a: members[i].nodeKey, b: members[j].nodeKey, rttMs, loss, proto, costMs: rttMs * (1 + loss),
  }));
  if (populated) {
    report('legacy-field', 'Linux', 80, { udp: 41641 }, { online: false, revoked: true, lastSeen: -44 });
    for (const { a, b, rttMs, loss, proto } of links) {
      reports.get(a).links.push({ target: b, targetName: members.find((m) => m.nodeKey === b).name, rttMs, jitterMs: 2.3, loss, proto });
    }
    inventories.set(members[0].nodeKey, {
      nodeKey: members[0].nodeKey, importedAt: iso(-9), note: '上海机房台账：计划下次变更时切换 QUIC 端口。',
      transports: [{ proto: 'udp', port: 51820 }, { proto: 'quic', port: 41010 }],
      endpoints: [{ proto: 'udp', addr: '198.51.100.11:51820' }], routes: ['192.168.20.0/24', '192.168.21.0/24'],
    });
  }

  const policy = populated ? {
    ...emptyPolicy(), members,
    acl: {
      groups: { 'group:office': ['tag:dev', 'tag:design'] }, hosts: { 'office-lan': '192.168.20.0/24' },
      acls: [
        { action: 'accept', proto: 'tcp', src: ['group:office'], dst: ['tag:storage:443,8443'] },
        { action: 'accept', proto: 'udp', src: ['tag:dev'], dst: ['192.168.20.0/24:53'] },
        { action: 'drop', proto: 'tcp', src: ['*'], dst: ['office-lan:22'] },
      ],
    },
    stunAddr: '198.51.100.10:3478', stunAltAddr: '198.51.100.10:3479',
  } : emptyPolicy();
  const proposed = structuredClone(policy);
  if (populated) {
    proposed.members.push({
      id: 7, nodeKey: nodeKey('sh-ci-runner'), name: 'sh-ci-runner', ipv4: '100.64.0.51', tags: ['tag:ci'],
    });
    proposed.acl.acls.push({ action: 'accept', proto: 'tcp', src: ['tag:ci'], dst: ['tag:storage:5000-5010'] });
  }
  const invalid = structuredClone(policy);
  invalid.acl.acls.push({ action: 'accept', proto: 'wss', src: ['tag:dev'], dst: ['tag:infra:8443'] });
  const drafts = populated ? [
    { id: 'draft_mock_ci', name: '上海 CI 接入', note: '新增构建与制品缓存流量', baseVersion: 7, policy: proposed, createdAt: iso(-18), updatedAt: iso(-2) },
    { id: 'draft_mock_review', name: '备份网段隔离', note: '演示校验错误与过时基准', baseVersion: 6, policy: invalid, createdAt: iso(-42), updatedAt: iso(-16) },
  ] : [];
  const keys = populated ? [
    { id: 'key_mock_sh', label: '上海临时接入', state: 'active', reusable: false, usedCount: 0, createdAt: iso(-2), expiresAt: iso(22) },
    { id: 'key_mock_build', label: '构建机批量申请', state: 'active', reusable: true, usedCount: 4, createdAt: iso(-8), expiresAt: iso(160) },
    { id: 'key_mock_nas', label: 'NAS 替换', state: 'used', reusable: false, usedCount: 1, createdAt: iso(-32), expiresAt: iso(4) },
    { id: 'key_mock_test', label: '前端验收', state: 'expired', reusable: true, usedCount: 2, createdAt: iso(-70), expiresAt: iso(-46) },
    { id: 'key_mock_old', label: '旧现场设备', state: 'revoked', reusable: false, usedCount: 0, createdAt: iso(-94), expiresAt: iso(74) },
  ] : [];
  const audit = populated ? Array.from({ length: 19 }, (_, i) => {
    const [action, target, result, detail] = auditEvents[i % auditEvents.length];
    return { action, target, result, detail, at: iso(-i * 3 - 1), actor: i % 2 === 0 ? 'web@mock' : 'controller:mock' };
  }) : [];
  const history = populated ? [
    { version: 7, policy, expiresAt: iso(scenario === 'expired' ? -2 : 62), publishedAt: iso(-20) },
    { version: 6, policy: { ...policy, members: members.slice(0, 5) }, expiresAt: iso(-21), publishedAt: iso(-96) },
    { version: 5, policy: { ...policy, members: members.slice(0, 4) }, expiresAt: iso(-97), publishedAt: iso(-160) },
  ] : [];

  return {
    authenticated: scenario !== 'login', setupPending: scenario === 'setup',
    reports, inventories, links: populated ? links : [], drafts, keys, audit, history,
    nextPublication: { version: history.length ? 8 : 1, policy: proposed, expiresAt: iso(168), publishedAt: iso(0) },
    delegation: populated ? { enabled: true, publicKey: mockController.publicKey, label: mockController.label, updatedAt: iso(-38) } : { enabled: false },
    relay: populated ? { clients: 3, frames: 19842, bytes: 18_734_861 } : { clients: 0, frames: 0, bytes: 0 },
    revision: populated ? 138 : 1, nextId: 1,
  };
}
