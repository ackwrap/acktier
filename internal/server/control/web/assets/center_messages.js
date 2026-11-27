import { language } from './i18n.js';

// The center also serves older clients. Its existing API errors, validation
// notes, and stored audit details use Simplified Chinese. Translate them at
// display time so the wire format and saved audit history remain intact.
const exactMessages = new Map([
  ["接口不存在。", "Endpoint not found."],
  ["请先登录管理台。", "Sign in to the console first."],
  ["页面已失效，请刷新后重试。", "This page has expired. Refresh it and try again."],
  ["请先绑定所有者。", "Bind the network owner first."],
  ["密码验证繁忙，请稍后重试。", "Password verification is busy. Try again in a moment."],
  ["无法读取登录信息。", "Could not read the sign-in request."],
  ["中心尚未设置管理员密码，请在中心主机上使用 -reset-admin-password 设置。", "The center has no administrator password. Set one on the center host with -reset-admin-password."],
  ["管理员密码不正确。", "Incorrect administrator password."],
  ["密码已更新，请使用新密码登录。", "The password changed. Sign in with the new password."],
  ["无法读取请求。", "Could not read the request."],
  ["当前密码错误", "Incorrect current password"],
  ["当前密码不正确。", "Incorrect current password."],
  ["密码已更新，请重新登录。", "Password updated. Sign in again."],
  ["已撤销其他会话", "Revoked other sessions"],
  ["新密码至少 12 个字符，最多 256 字节。", "The new password must have at least 12 characters and fit within 256 bytes."],
  ["保存密码失败，请检查中心的存储。", "Could not save the password. Check the center storage."],
  ["只接受所有者导出的公钥文件 trust.json。不要上传 signer.json。", "Upload the owner's public trust.json file. Keep signer.json on the owner computer."],
  ["请先确认公钥文件来自你选定的所有者客户端。", "Confirm that the public trust file came from your selected owner computer."],
  ["已绑定", "Owner bound"],
  ["中心已经绑定所有者，不能通过 Web 更换。", "The center already has an owner. The Web console cannot replace it."],
  ["写入失败", "Write failed"],
  ["保存所有者配置失败，请检查中心的存储。中心仍处于待初始化状态。", "Could not save the owner configuration. Check the center storage. Setup is still pending."],
  ["节点公钥格式不正确。", "Invalid node public key."],
  ["中心没有这个节点的记录。", "The center has no record of this node."],
  ["条目过多：最多 8 个传输、32 个候选地址、64 个网段", "Too many entries. The limits are 8 transports, 32 candidate endpoints, and 64 routes."],
  ["备注最多 200 个字符", "The note can have up to 200 characters."],
  ["传输必须是 udp、tcp、quic 或 wss，端口 1–65535", "Use udp, tcp, quic, or wss as the transport and a port from 1 through 65535."],
  ["候选地址必须是字面量 IP:端口，并指定 udp、tcp、quic 或 wss", "Use a literal IP address and port for candidate endpoints and specify udp, tcp, quic, or wss."],
  ["网段必须是规范的 CIDR，例如 192.168.1.0/24", "Use a canonical CIDR for routes, such as 192.168.1.0/24."],
  ["只能为中心已知的节点公钥导入能力清单。", "Import inventory only for node public keys known to the center."],
  ["能力清单必须是 JSON，且只包含 transports、endpoints、routes、note。", "Inventory must be JSON and may contain only transports, endpoints, routes, and note."],
  ["保存失败，请检查中心的存储。", "Save failed. Check the center storage."],
  ["该节点没有人工导入的清单。", "This node has no imported inventory."],
  ["删除失败，请检查中心的存储。", "Delete failed. Check the center storage."],
  ["请输入 1 到 64 个字符的备注。", "Enter a label with 1 to 64 characters."],
  ["有效期需在 1 到 720 小时之间。", "The validity period must be 1 to 720 hours."],
  ["单次", "Single use"],
  ["可重复", "Reusable"],
  ["无法保存申请码，请检查中心的存储。", "Could not save the enrollment key. Check the center storage."],
  ["找不到此申请码。", "Enrollment key not found."],
  ["无法保存吊销记录，请检查中心的存储。", "Could not save the revocation. Check the center storage."],
  ["草稿名称最多 64 个字符", "The draft name can have up to 64 characters."],
  ["草稿备注最多 240 个字符", "The draft note can have up to 240 characters."],
  ["中心没有与当前签名快照相符的策略源文件。请导入所有者当时签发用的完整 policy.json，再修改或加入节点。", "The center has no source policy for the active signed snapshot. Import the complete policy.json used to sign it before editing or adding nodes."],
  ["草稿数量已达上限（32 份），请先删除不再使用的草稿。", "The center can store up to 32 drafts. Delete unused drafts to make room."],
  ["保存草稿失败，请检查中心的存储。", "Could not save the draft. Check the center storage."],
  ["找不到该草稿。", "Draft not found."],
  ["读取草稿失败。", "Could not read the draft."],
  ["草稿版本无效，请刷新后重试。", "Invalid draft revision. Refresh the page and try again."],
  ["草稿已经更新，请刷新并核对最新内容后重试。", "The draft has changed. Refresh and review the latest version before trying again."],
  ["草稿操作失败，请检查中心的存储。", "Could not update the draft. Check the center storage."],
  ["策略校验未通过", "Policy validation failed"],
  ["成员参数格式不正确。", "Invalid member parameters."],
  ["请提供有效的节点公钥。", "Provide a valid node public key."],
  ["虚拟 IPv4 地址无效。", "Invalid overlay IPv4 address."],
  ["虚拟 IPv6 地址无效。", "Invalid overlay IPv6 address."],
  ["标签必须以 tag: 开头，例如 tag:server。", "Tags must start with tag:, for example tag:server."],
  ["草稿中不存在该成员。", "This member is missing from the draft."],
  ["草稿存在校验错误，请先修复后再导出待签 policy.json。", "Fix the draft validation errors before exporting policy.json for signing."],
  ["序列化草稿失败。", "Could not serialize the draft."],
  ["中心尚未绑定所有者公钥。", "The center has no bound owner public key."],
  ["拒绝发布：版本低于当前最低水位，或与已发布的同版本内容不一致（禁止降级或篡改重签）。", "Publication rejected. The version is below the current version floor or conflicts with a published snapshot of the same version."],
  ["拒绝发布：该授权属于其他组网（networkId 与本中心绑定的所有者公钥指纹不匹配）。", "Publication rejected. The authorization belongs to a different network. Its networkId must match the bound owner's public key fingerprint."],
  ["拒绝发布：该签名快照已过期，请在所有者电脑重新签发。", "Publication rejected. This signed snapshot has expired. Sign a new one on the owner computer."],
  ["拒绝发布：Ed25519 签名校验失败（非绑定所有者签发或载荷已被改动）。", "Publication rejected. The Ed25519 signature failed verification against the bound owner public key."],
  ["保存签名授权失败，请检查中心的存储。", "Could not save the signed authorization. Check the center storage."],
  ["文件不是合法的 authorization.json（请勿上传 signer.json 或未签名的草稿）。", "Upload a valid authorization.json. Keep signer.json private and sign drafts before publishing them."],
  ["文件不是合法的 authorization.json。", "Invalid authorization.json."],
  ["版本号无效。", "Invalid version."],
  ["无法解码历史快照。", "Could not decode the historical snapshot."],
  ["找不到该历史版本。", "Historical version not found."],
  ["名称", "Name"],
  ["地址", "Address"],
  ["子网/出口", "Subnet or exit route"],
  ["标签", "Tags"],
  ["ACL 超过编译上限，请减少规则、端口或展开的成员与路由。", "The ACL exceeds the compilation limit. Reduce the rules, ports, or expanded members and routes."],
  ["ACL 为空：签发后成员之间的所有业务流量都会被默认拒绝。", "The ACL is empty. Publication will deny traffic between members by default."],
  ["有规则允许任意来源访问任意目标和端口，相当于关闭 ACL。", "A rule allows every source to reach every destination and port, effectively allowing all traffic."],
  ["选择器引用的节点公钥不在成员表里。", "The selector refers to a public key outside the member list."],
  ["规则引用了 autogroup:internet，但没有成员被批准为出口（0.0.0.0/0 或 ::/0）。", "A rule references autogroup:internet, but no member is approved as an exit node (0.0.0.0/0 or ::/0)."],
  ["该公钥已在草稿成员表中", "This public key is already in the draft member list."],
  ["只接受控制端导出的 controller-trust.json（包含 networkId、独立管理公钥与私钥持有证明）。", "Use controller-trust.json exported by the controller. It must contain a network ID, a separate administrator public key, and proof of private key possession."],
  ["备注最多 64 个字符。", "The label can have up to 64 characters."],
  ["无法保存取消委托设置。", "Could not save the delegation revocation."],
  ["原控制端 API 凭据已立即失效", "The previous controller API credentials are no longer valid"],
]);

const prefixedMessages = [
  ["策略 JSON 格式无效或包含未知字段：", "Invalid policy JSON or unknown field: "],
  ["策略草稿 ", "Policy draft "],
  ["草稿请求或 policy.json 格式不正确：", "Invalid draft request or policy.json: "],
  ["ACL JSON 格式无效（仅允许 groups、hosts、acls 字段）：", "Invalid ACL JSON. Only groups, hosts, and acls are allowed: "],
  ["拒绝发布：签名快照格式或内容不合法（", "Publication rejected. Invalid signed snapshot ("],
  ["无法启用委托：", "Could not enable delegation: "],
];

const suffixedMessages = [
  [" 子网", " subnet"],
  ["（全部）", " (all)"],
  ["（QUIC/WSS 是传输方式，不是 ACL 协议；业务端口请使用 tcp 或 udp）", " (QUIC and WSS are transports. Use tcp or udp for ACL ports.)"],
  [" (幂等重传)", " (idempotent retry)"],
];

const formattedMessages = [
  ["子网或出口路由 %q 不合法。", "Invalid subnet or exit route {0}."],
  ["成员 %s 的公钥没有出现在中心的申请或连接记录里，请通过可信渠道核对。", "The center has no join request or connection record for the public key of member {0}. Verify it through a trusted channel."],
  ["成员 %s 被批准了它没有申报的网段 %s。", "Member {0} has been approved for subnet {1}, which it did not advertise."],
  ["签发后将移除成员：%s。它们会失去组网权限。", "Publication will remove member(s) {0} and revoke their network access."],
  ["选择器 %s 引用了不在成员表里的节点。", "Selector {0} refers to a node outside the member list."],
  ["没有成员带有标签 %s。", "No member has the tag {0}."],
  ["成员 ID %d 已被占用", "Member ID {0} is already in use."],
  ["名称 %s 已被占用", "The name {0} is already in use."],
  ["地址 %s 已被占用", "The address {0} is already in use."],
].map(([source, message]) => {
  const parts = source.split(/%([dsq])/g);
  const pattern = parts.map((part, index) => {
    if (index % 2) return part === 'd' ? '(\\d+)' : '(.+?)';
    return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('');
  return [new RegExp(`^${pattern}$`), message];
});

export function translateCenterMessage(value) {
  if (language !== 'en' || typeof value !== 'string') return value;
  for (const [source, message] of suffixedMessages) {
    if (value.endsWith(source)) {
      const base = value.slice(0, -source.length);
      return (exactMessages.get(base) ?? base) + message;
    }
  }
  if (exactMessages.has(value)) return exactMessages.get(value);
  for (const [source, message] of prefixedMessages) {
    if (value.startsWith(source)) return message + value.slice(source.length);
  }
  for (const [pattern, message] of formattedMessages) {
    const match = value.match(pattern);
    if (match) return message.replace(/\{(\d+)\}/g, (_, index) => match[Number(index) + 1]);
  }
  return value;
}
