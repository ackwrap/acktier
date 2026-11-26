import { hash, networkId } from './fixtures.mjs';
import { aclAction, aclProtocol, splitACLTarget, validBusinessPorts } from '../../internal/server/control/web/assets/acl_values.js';

const all = ['0.0.0.0/0（全部）', '::/0（全部）'];
const aclEntries = (policy) => (policy.acl?.acls ?? []).map((entry, i) => ({
  index: i + 1, action: aclAction(entry?.action), proto: aclProtocol(entry?.proto),
  src: entry?.src, dst: entry?.dst,
}));

// Display-only rows. Production's Go compiler is the authority on ACL semantics.
function ruleRows(policy) {
  const labels = (selector, expand = true) => {
    if (selector === '*') return all;
    if (Object.hasOwn(policy.acl?.hosts ?? {}, selector)) return [policy.acl.hosts[selector]];
    if (expand && Object.hasOwn(policy.acl?.groups ?? {}, selector)) {
      const group = policy.acl.groups[selector];
      if (Array.isArray(group)) return [...new Set(group.flatMap((s) => labels(s, false)))];
    }
    if (typeof selector === 'string' && /^(node|id|tag|nodekey):/.test(selector)) {
      return policy.members.filter((m) => m.nodeKey === selector || `node:${m.id}` === selector ||
        `id:${m.id}` === selector || m.tags?.includes(selector)).map((m) => `${m.name} · ${m.ipv4}/32`);
    }
    return [selector];
  };
  return [
    ...aclEntries(policy).flatMap(({ action, proto, src, dst }) => dst.flatMap((raw) => {
      const target = splitACLTarget(raw);
      return (proto === 'icmp' ? ['icmp', 'icmpv6'] : [proto]).flatMap((p) =>
        target.ports.split(',').map((ports) => ({
          action, proto: p, src: src.flatMap((s) => labels(s.trim())), dst: labels(target.selector), ports: ports.trim(),
        })));
    })),
    { action: 'drop', proto: 'any', src: all, dst: all, ports: '*' },
  ];
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const stringList = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string');

export function policyAnalysis(policy, baseVersion, active) {
  const acl = aclEntries(policy);
  const issues = [];
  if (active && baseVersion !== active.version) issues.push({
    level: 'warning', message: `草稿基于 v${baseVersion}，当前生效的是 v${active.version}。`,
  });
  for (const entry of acl) {
    if (!entry.action || !entry.proto || !stringList(entry.src) || !entry.src.length ||
      !stringList(entry.dst) || !entry.dst.length || !entry.dst.every((d) => validBusinessPorts(splitACLTarget(d).ports))) {
      issues.push({ level: 'error', message: `规则 #${entry.index} 的动作、协议或选择器无效，QUIC/WSS 不是 ACL 业务协议。` });
    }
  }
  if (acl.length === 0) issues.push({ level: 'warning', message: 'ACL 为空：签发后默认拒绝成员间的业务流量。' });

  const valid = issues.every((i) => i.level !== 'error');
  const rules = valid ? ruleRows(policy) : [];
  const before = active?.policy.members ?? [];
  const old = new Map(before.map((m) => [m.nodeKey, m]));
  const nextKeys = new Set(policy.members.map((m) => m.nodeKey));
  const oldRules = active ? ruleRows(active.policy) : [];
  return {
    valid, issues, rules, aclEntries: acl,
    baseStale: Boolean(active && baseVersion !== active.version),
    diff: {
      added: policy.members.filter((m) => !old.has(m.nodeKey)),
      removed: before.filter((m) => !nextKeys.has(m.nodeKey)),
      changed: policy.members.filter((m) => old.has(m.nodeKey) && !same(old.get(m.nodeKey), m))
        .map((member) => ({ member, fields: ['身份属性'] })),
      rulesBefore: oldRules.length, rulesAfter: rules.length, rulesSame: same(oldRules, rules),
      dnsChanged: Boolean(active && !same(active.policy.dns, policy.dns)),
      stunChanged: Boolean(active && (active.policy.stunAddr !== policy.stunAddr || active.policy.stunAltAddr !== policy.stunAltAddr)),
      hasActive: Boolean(active),
    },
  };
}

export function publicationView(record) {
  const { version, policy, expiresAt, publishedAt } = record;
  const { members, dns, stunAddr, stunAltAddr } = policy;
  const rules = ruleRows(policy);
  const prefixes = (labels) => labels.map((label) => label.split(' · ').at(-1).split('（')[0]);
  const packetFilter = rules.map(({ action, proto, src, dst, ports }) => {
    const [start, end = start] = ports === '*' ? [0, 65535] : ports.split('-').map(Number);
    const ipProto = { any: 0, tcp: 6, udp: 17, icmp: 1, icmpv6: 58 }[proto] ?? Number(proto);
    return { action, ipProto, srcPrefixes: prefixes(src), dstPrefixes: prefixes(dst), dstPortStart: start, dstPortEnd: end };
  });
  return {
    authorization: {
      version, expiresAt, publishedAt, expired: Date.parse(expiresAt) <= Date.now(),
      digest: hash(`${version}:${expiresAt}`), members: members.length, rules: rules.length,
    },
    snapshot: { networkId, version, expiresAt, members, packetFilter, dns, stunAddr, stunAltAddr },
    rules,
  };
}
