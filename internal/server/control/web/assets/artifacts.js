// Validate and project public artifacts before sending anything to the center.
// These checks prevent accidental disclosure, not replace server-side validation.
const hexKey = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const base64 = (s) => typeof s === 'string' && s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
const knownFields = (v, fields) => v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).every((k) => fields.includes(k));

const formats = {
  trust: {
    name: 'trust.json',
    maxBytes: 4096,
    required: { publicKey: hexKey, minimumVersion: (v) => Number.isSafeInteger(v) && v > 0 },
  },
  authorization: {
    name: 'authorization.json',
    maxBytes: 1024 * 1024,
    required: { payload: base64, signature: (s) => base64(s) && s.length === 88 },
  },
  controller: {
    name: 'controller-trust.json',
    maxBytes: 4096,
    required: {
      networkId: hexKey,
      publicKey: hexKey,
      proof: (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{86}$/.test(s),
    },
    optional: { label: (s) => typeof s === 'string' && [...s].length <= 64 },
  },
};

export async function readPublicArtifact(file, kind) {
  const { name, maxBytes, required, optional = {} } = formats[kind];
  const invalid = () => new Error(`请选择格式正确的 ${name}；请勿选择私钥文件。文件未上传。`);
  if (!file || file.size > maxBytes) throw invalid();
  let value;
  try {
    value = JSON.parse(await file.text());
  } catch {
    throw invalid();
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  const allowed = { ...required, ...optional };
  for (const k of Object.keys(value)) {
    if (!Object.hasOwn(allowed, k) || !allowed[k](value[k])) throw invalid();
  }
  for (const k of Object.keys(required)) {
    if (!Object.hasOwn(value, k)) throw invalid();
  }
  return Object.fromEntries(Object.keys(allowed).filter((k) => Object.hasOwn(value, k)).map((k) => [k, value[k]]));
}

export function parseACLSource(text) {
  const v = JSON.parse(text);
  if (!knownFields(v, ['acls', 'groups', 'hosts']) || !Array.isArray(v.acls)) {
    throw new Error('请选择包含 acls 数组的 ACL JSON，不要选择私钥文件。');
  }
  return v;
}

export function parsePolicySource(text) {
  const v = JSON.parse(text);
  if (!knownFields(v, ['members', 'acl', 'dns', 'stunAddr', 'stunAltAddr']) || !Array.isArray(v.members) ||
      (Object.hasOwn(v, 'acl') && !knownFields(v.acl, ['acls', 'groups', 'hosts']))) {
    throw new Error('请选择包含 members 的完整 policy.json，不要选择私钥文件。');
  }
  return v;
}

export function parseInventorySource(text) {
  const v = JSON.parse(text);
  if (!knownFields(v, ['transports', 'endpoints', 'routes', 'note']) ||
      (v.transports != null && (!Array.isArray(v.transports) || !v.transports.every((t) =>
        knownFields(t, ['proto', 'port']) && typeof t.proto === 'string' && Number.isInteger(t.port)))) ||
      (v.endpoints != null && (!Array.isArray(v.endpoints) || !v.endpoints.every((e) =>
        knownFields(e, ['proto', 'addr', 'isLan']) && typeof e.proto === 'string' && typeof e.addr === 'string' &&
        (e.isLan == null || typeof e.isLan === 'boolean')))) ||
      (v.routes != null && (!Array.isArray(v.routes) || !v.routes.every((r) => typeof r === 'string'))) ||
      (v.note != null && typeof v.note !== 'string')) {
    throw new Error('请选择包含 transports、endpoints、routes 或 note 的能力清单 JSON，不要选择私钥文件。');
  }
  return { transports: v.transports ?? [], endpoints: v.endpoints ?? [], routes: v.routes ?? [], note: v.note ?? '' };
}
