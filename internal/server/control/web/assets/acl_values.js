// Shared by the browser and Mock. The real Go compiler still validates every save.
export function aclAction(raw) {
  if (raw != null && typeof raw !== 'string') return '';
  const action = (raw ?? '').trim().toLowerCase() || 'accept';
  return action === 'accept' || action === 'drop' ? action : '';
}

export function aclProtocol(raw) {
  if (raw != null && typeof raw !== 'string') return '';
  const name = (raw ?? '').trim().toLowerCase();
  if (name === '' || name === '*') return 'any';
  if (['any', 'tcp', 'udp', 'icmp'].includes(name)) return name;
  if (/^[+-]?\d+$/.test(raw) && Number(raw) >= 0 && Number(raw) <= 255) return String(Number(raw));
  return '';
}

export function usesBusinessPorts(protocol) {
  return ['tcp', 'udp', 'any', '6', '17', '0'].includes(protocol);
}

function isIPv6Address(value) {
  const zone = value.indexOf('%');
  if (zone === value.length - 1) return false;
  const ip = zone < 0 ? value : value.slice(0, zone);
  if (!ip.includes(':') || !/^[a-f0-9:.]+$/i.test(ip)) return false;
  try {
    // URL parses the literal locally; no lookup or network request is made.
    new URL(`http://[${ip}]/`);
    return true;
  } catch {
    return false;
  }
}

function isIPv6OrPrefix(value) {
  if (isIPv6Address(value)) return true;
  const slash = value.lastIndexOf('/');
  if (slash < 0 || value.includes('%')) return false;
  const bits = value.slice(slash + 1);
  return /^(0|[1-9]\d{0,2})$/.test(bits) && Number(bits) <= 128 && isIPv6Address(value.slice(0, slash));
}

const bareSelectorPrefix = /^(tag|group|node|id|nodekey|autogroup)$/i;

export function splitACLTarget(raw) {
  const value = raw.trim();
  const colon = value.lastIndexOf(':');
  const head = value.slice(0, colon);
  if (colon <= 0 || isIPv6OrPrefix(value) || bareSelectorPrefix.test(head)) {
    return { selector: value, ports: '*' };
  }
  return { selector: head.replace(/^[\[\]]+|[\[\]]+$/g, '').trim(), ports: value.slice(colon + 1).trim() || '*' };
}

export function formatACLTarget(selector, ports) {
  // Without brackets, 2001:db8::1:443 parses as an address, not address + port.
  const bracket = bareSelectorPrefix.test(selector) || isIPv6OrPrefix(selector) || isIPv6OrPrefix(`${selector}:${ports}`);
  const target = bracket ? `[${selector}]` : selector;
  return `${target}:${ports}`;
}

export function validBusinessPorts(ports) {
  return ports === '*' || ports.split(',').every((part) => {
    const m = /^(\+?\d+)(?:-(\+?\d+))?$/.exec(part.trim());
    if (!m) return false;
    const first = Number(m[1]);
    const last = Number(m[2] ?? m[1]);
    return first >= 1 && last <= 65535 && first <= last;
  });
}
