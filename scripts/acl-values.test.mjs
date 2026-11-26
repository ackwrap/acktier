import assert from 'node:assert/strict';
import test from 'node:test';
import { aclProtocol, usesBusinessPorts, splitACLTarget, formatACLTarget, validBusinessPorts } from '../internal/server/control/web/assets/acl_values.js';
import { parseACLSource } from '../internal/server/control/web/assets/artifacts.js';

test('bare destinations and IPv6 literals are not misread as port specifications', () => {
  for (const raw of ['*', 'node:19', 'ID:19', 'tag:storage', 'group:office', 'autogroup:internet', 'office-lan',
    '2001:db8::443', '2001:db8::/64', '::ffff:192.0.2.1', 'fe80::1%scope:123']) {
    assert.deepEqual(splitACLTarget(raw), { selector: raw, ports: '*' }, raw);
  }
  assert.deepEqual(splitACLTarget('*:*'), { selector: '*', ports: '*' });
  assert.deepEqual(splitACLTarget('node:19:443, 5000-5010'), { selector: 'node:19', ports: '443, 5000-5010' });
});

test('adding ports keeps IPv6 addresses and prefixes unambiguous', () => {
  for (const selector of ['2001:db8::1', '2001:db8::/64']) {
    const raw = formatACLTarget(selector, '443');
    assert.equal(raw, `[${selector}]:443`);
    assert.deepEqual(splitACLTarget(raw), { selector, ports: '443' });
  }
  assert.equal(formatACLTarget('node:42', '*'), 'node:42:*');
  assert.equal(formatACLTarget('192.168.20.0/24', '53'), '192.168.20.0/24:53');
  assert.equal(formatACLTarget('node', '53'), '[node]:53', 'reserved name used as a host alias');
});

test('the visual form only treats TCP and UDP packets as having business ports', () => {
  for (const proto of ['', '*', ' Any ', ' TCP ', 'udp', '0', '006', '17']) {
    assert.equal(usesBusinessPorts(aclProtocol(proto)), true, proto);
  }
  for (const proto of ['icmp', '1', '58', '255']) {
    assert.notEqual(aclProtocol(proto), '');
    assert.equal(usesBusinessPorts(aclProtocol(proto)), false, proto);
  }
  for (const proto of ['QUIC', 'wss', '256', ' -1', '17.0']) assert.equal(aclProtocol(proto), '', proto);
  for (const value of ['*', '443', '1-65535', '443, 5000-5010']) assert.ok(validBusinessPorts(value), value);
  for (const value of ['0', '65536', '8000-1', '443,', '*,443']) assert.equal(validBusinessPorts(value), false, value);
});

test('ACL JSON rejects shapes that cannot be loaded into the rule table', () => {
  const valid = { acls: [{ src: ['group:office'], dst: ['node:42:443'], proto: 'tcp' }], groups: { 'group:office': ['tag:dev'] } };
  assert.deepEqual(parseACLSource(JSON.stringify(valid)), valid);
  for (const bad of [{ seed: 'private' }, { acls: [null] }, { acls: [{ src: 1 }] },
    { acls: [{ dst: ['*'], secret: 'private' }] }, { acls: [], groups: [] }, { acls: [], hosts: { alias: 42 } }]) {
    assert.throws(() => parseACLSource(JSON.stringify(bad)), /ACL JSON/);
  }
});
