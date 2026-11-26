import {
  api, el, badge, callout, searchBox, makeDropzone, copyableCode, fmtTime, fmtRelative, fmtPortsMap, toast, openModal, closeModal,
} from './api.js';
import { parseInventorySource } from './artifacts.js';
import { openAddMemberModal } from './views_overview.js';

function openInventoryModal(nodeKey, currentInv, onSaved) {
  const sample = currentInv
    ? {
      transports: currentInv.transports || [],
      endpoints: (currentInv.endpoints || []).map((e) => ({ proto: e.proto, addr: e.addr })),
      routes: currentInv.routes || [],
      note: currentInv.note || '',
    }
    : {
      transports: [{ proto: 'udp', port: 51820 }, { proto: 'quic', port: 51821 }],
      endpoints: [{ proto: 'udp', addr: '203.0.113.15:51820' }],
      routes: ['192.168.10.0/24'],
      note: '机房运维台账核对记录',
    };

  const editor = el('textarea', {
    class: 'code-editor',
    id: 'inv-json-editor',
    spellcheck: 'false',
  }, JSON.stringify(sample, null, 2));

  const previewMount = el('div', { class: 'preview-card', hidden: true });
  const errBox = el('div', { id: 'inv-error', class: 'callout error icon-start', role: 'alert', hidden: true });
  const saveBtn = el('button', { type: 'submit', class: 'btn primary btn-check icon-start' }, '保存人工核对清单');
  let parsedPayload = null;

  const invalidate = (message) => {
    parsedPayload = null;
    previewMount.hidden = true;
    saveBtn.disabled = true;
    errBox.textContent = message;
    errBox.hidden = false;
  };
  const parseAndPreview = (text) => {
    errBox.hidden = true;
    try {
      parsedPayload = parseInventorySource(text);
      saveBtn.disabled = false;
      previewMount.hidden = false;
      previewMount.replaceChildren(
        el('div', { class: 'preview-header' }, badge('待导入清单预览（仅供人工对照，不进入 NetMap）', 'accent')),
        el('dl', { class: 'kv-grid' },
          el('div', {},
            el('dt', {}, '监听传输端口'),
            el('dd', {}, parsedPayload.transports.length
              ? parsedPayload.transports.map((t) => `${String(t.proto).toUpperCase()}:${t.port}`).join(', ')
              : '未填写'),
          ),
          el('div', {},
            el('dt', {}, '候选地址数'),
            el('dd', {}, `${parsedPayload.endpoints.length} 条`),
          ),
          el('div', {},
            el('dt', {}, '申报网段'),
            el('dd', {}, parsedPayload.routes.length ? parsedPayload.routes.join(', ') : '无'),
          ),
          el('div', {},
            el('dt', {}, '备注'),
            el('dd', {}, parsedPayload.note || '—'),
          ),
        ),
      );
    } catch (e) {
      invalidate('清单无效：' + e.message);
    }
  };

  const fileInput = el('input', {
    type: 'file', id: 'inv-file',
    accept: '.json,application/json', 'aria-describedby': 'inv-error',
    onChange: async () => {
      const f = fileInput.files?.[0];
      if (!f) return;
      saveBtn.disabled = true;
      editor.disabled = true;
      editor.value = '';
      fileInput.removeAttribute('aria-invalid');
      try {
        if (f.size > 64 * 1024) throw new Error('清单文件过大（最多 64 KiB）。');
        const text = await f.text();
        if (fileInput.files?.[0] !== f) return;
        parseAndPreview(text);
        if (parsedPayload) editor.value = text;
        else fileInput.setAttribute('aria-invalid', 'true');
      } catch (err) {
        if (fileInput.files?.[0] === f) {
          fileInput.setAttribute('aria-invalid', 'true');
          invalidate(err.message);
        }
      } finally {
        if (fileInput.files?.[0] === f) editor.disabled = false;
      }
    },
  });
  editor.addEventListener('input', () => parseAndPreview(editor.value));
  parseAndPreview(editor.value);

  const form = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      if (saveBtn.disabled) return;
      parseAndPreview(editor.value);
      if (!parsedPayload) return;
      saveBtn.disabled = true;
      try {
        await api(`nodes/${encodeURIComponent(nodeKey)}/inventory`, {
          method: 'PUT',
          body: parsedPayload,
        });
        closeModal();
        toast('节点人工能力清单已保存（仅用于核对，未改变 NetMap 或 ACL）');
        onSaved();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
        saveBtn.disabled = false;
      }
    },
  },
    callout('',
      '人工能力清单绑定到当前节点公钥，仅用于在节点详情页与节点自动上报对照，绝不会下发到节点 NetMap，也不会自动批准路由或放行 ACL。',
    ),
    errBox,
    el('div', { class: 'field' },
      el('label', { for: 'inv-file' }, '从运维清单 JSON 文件导入（可选）'),
      makeDropzone(fileInput, '点击选择或拖拽能力清单 JSON', '上限 64 KiB · 支持 transports / endpoints / routes / note'),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'inv-json-editor' }, '能力清单 JSON 编辑'),
      el('div', { class: 'editor-frame' },
        el('div', { class: 'editor-bar' }, el('span', { class: 'mono' }, 'inventory.json'), el('span', {}, 'Read-Only Comparison Metadata')),
        editor,
      ),
    ),
    previewMount,
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, '取消'),
      saveBtn,
    ),
  );
  openModal('导入节点能力核对清单', form);
}

async function renderNodeDetailCard(nodeKey, navTo, onRefresh) {
  const d = await api(`nodes/${encodeURIComponent(nodeKey)}`);
  const flags = d.flags || {};
  const signed = d.signed;
  const rep = d.reported;
  const inv = d.inventory;

  const statusBadges = [];
  if (signed) statusBadges.push(badge(`已签成员 #${signed.id}`, 'ok'));
  else statusBadges.push(badge('未签入当前成员表', 'warn'));
  if (flags.authorizationExpired) statusBadges.push(badge('签名授权已过期', 'err'));
  if (flags.revoked) statusBadges.push(badge('协调密钥已撤权', 'err'));
  if (flags.missingReport) statusBadges.push(badge('缺少节点上报数据', 'warn'));
  else if (rep?.online) statusBadges.push(badge('协调流：在线', 'ok'));
  else statusBadges.push(badge('协调流：离线', 'neutral'));
  if (inv) statusBadges.push(badge('含人工核对清单', 'accent'));

  // Column 1: Owner-signed authoritative identity
  const signedCol = el('article', { class: 'card source-card signed form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, '1. 所有者已签身份（权威真值）'),
      signed ? badge('已签生效', 'ok') : badge('无签名身份', 'warn'),
    ),
    signed
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, '唯一名称 / ID'), el('dd', {}, `${signed.name} (#${signed.id})`)),
        el('div', {}, el('dt', {}, '虚拟 IPv4 / IPv6'), el('dd', {},
          el('code', {}, signed.ipv4),
          signed.ipv6 ? el('div', {}, el('code', {}, signed.ipv6)) : null,
        )),
        el('div', {}, el('dt', {}, '授权标签 (ACL)'), el('dd', {},
          (signed.tags || []).length
            ? el('div', { class: 'chip-list' }, ...signed.tags.map((t) => el('code', { class: 'chip' }, t)))
            : '无标签',
        )),
        el('div', {}, el('dt', {}, '已批准子网 / 出口路由'), el('dd', {},
          (signed.routes || []).length
            ? el('div', { class: 'chip-list' }, ...signed.routes.map((rt) => el('code', { class: 'chip' }, rt)))
            : '无',
        )),
      )
      : el('div', { class: 'form-stack' },
        el('p', { class: 'muted' }, '当前生效快照中不包含该公钥，节点无法进入数据面通信。'),
        rep && !flags.revoked
          ? el('button', {
            type: 'button', class: 'btn primary sm btn-plus icon-start',
            onClick: () => openAddMemberModal({
              nodeKey: d.nodeKey, hostname: rep.hostname, advertisedRoutes: rep.advertisedRoutes,
            }, navTo),
          }, '核对并加入策略草稿')
          : null,
      ),
  );

  // Column 2: Node auto-reported hints
  const repPorts = fmtPortsMap(rep?.transportPorts);
  const reportedCol = el('article', { class: 'card source-card reported form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, '2. 节点自动上报（连接提示）'),
      rep ? badge(`心跳：${fmtRelative(rep.lastSeen)}`, rep.online ? 'ok' : 'neutral') : badge('从未上报', 'warn'),
    ),
    rep
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, '自报主机名 / 系统'), el('dd', {}, `${rep.hostname || '未填写'} (${rep.os || '—'})`)),
        el('div', {}, el('dt', {}, '本地传输监听端口'), el('dd', {},
          repPorts
            ? el('div', { class: 'chip-list' }, ...repPorts.map((p) => el('code', { class: 'chip' }, p)))
            : badge('未上报（未启用直连监听）', 'neutral'),
        )),
        el('div', {}, el('dt', {}, '对外候选地址 (IP:端口)'), el('dd', {},
          (rep.endpoints || []).length
            ? el('div', { class: 'chip-list' }, ...rep.endpoints.map((ep) => el('code', { class: 'chip' },
              `${ep.addr}/${String(ep.proto).toUpperCase()}${ep.isLan ? ' · LAN' : ''}`)))
            : '无候选地址',
        )),
        el('div', {}, el('dt', {}, '节点申报路由'), el('dd', {},
          (rep.advertisedRoutes || []).length
            ? el('div', { class: 'chip-list' }, ...rep.advertisedRoutes.map((rt) => el('code', { class: 'chip' }, rt)))
            : '无申报路由',
        )),
        el('div', {}, el('dt', {}, '对等跳板中继能力'), el('dd', {}, rep.canRelay ? '支持作为跳板 (CanRelay)' : '普通终端节点')),
      )
      : el('p', { class: 'muted' }, '该公钥已在快照中签发，但尚未向中心注册或发送心跳。'),
  );

  // Column 3: Operator-imported manual inventory (comparison only)
  const invCol = el('article', { class: 'card source-card inventory form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, '3. 人工导入能力清单（仅供核对）'),
      inv ? badge(`更新于 ${fmtTime(inv.importedAt)}`, 'accent') : badge('未登记', 'neutral'),
    ),
    inv
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, '登记监听传输'), el('dd', {},
          (inv.transports || []).length
            ? el('div', { class: 'chip-list' }, ...inv.transports.map((t) => el('code', { class: 'chip' }, `${String(t.proto).toUpperCase()}:${t.port}`)))
            : '—',
        )),
        el('div', {}, el('dt', {}, '登记候选地址'), el('dd', {},
          (inv.endpoints || []).length
            ? el('div', { class: 'chip-list' }, ...inv.endpoints.map((ep) => el('code', { class: 'chip' }, `${ep.addr}/${String(ep.proto).toUpperCase()}`)))
            : '—',
        )),
        el('div', {}, el('dt', {}, '登记网段'), el('dd', {},
          (inv.routes || []).length
            ? el('div', { class: 'chip-list' }, ...inv.routes.map((rt) => el('code', { class: 'chip' }, rt)))
            : '—',
        )),
        el('div', {}, el('dt', {}, '核对备注'), el('dd', {}, inv.note || '—')),
      )
      : el('p', { class: 'muted' }, '尚未上传人工核对清单。可导入运维台账中的预期监听端口、公网 IP 与子网，在此与自动上报逐项比对。'),
    el('div', { class: 'toolbar-row' },
      el('button', { type: 'button', class: 'btn secondary sm btn-upload icon-start', onClick: () => openInventoryModal(d.nodeKey, inv, onRefresh) },
        inv ? '更新能力清单' : '上传能力清单'),
      inv
        ? el('button', {
          type: 'button', class: 'btn danger sm btn-trash icon-start',
          onClick: async () => {
            await api(`nodes/${encodeURIComponent(d.nodeKey)}/inventory`, { method: 'DELETE' });
            toast('人工能力清单已移除');
            onRefresh();
          },
        }, '清除清单')
        : null,
    ),
  );

  const mismatchAlerts = [];
  if ((flags.unapprovedRoutes || []).length) {
    mismatchAlerts.push(callout('warn',
      `节点自报了尚未获所有者签发批准的网段：${flags.unapprovedRoutes.join('、')}（未签发前不会进入转发平面）。`));
  }
  if ((flags.unadvertisedRoutes || []).length) {
    mismatchAlerts.push(callout('warn',
      `已签快照批准了网段 ${flags.unadvertisedRoutes.join('、')}，但节点当前心跳未申报该网段。`));
  }

  return el('section', { class: 'card form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('div', { class: 'form-stack' },
        el('div', { class: 'toolbar-row' },
          el('h2', {}, `节点三方对照详情：${signed?.name || rep?.hostname || '未知节点'}`),
          ...statusBadges,
        ),
        copyableCode(d.nodeKey, '复制完整节点公钥'),
      ),
      el('button', { type: 'button', class: 'btn secondary sm btn-close icon-start', onClick: () => navTo('nodes') }, '关闭详情'),
    ),
    ...mismatchAlerts,
    el('div', { class: 'three-col' }, signedCol, reportedCol, invCol),
    el('p', { class: 'field-hint' },
      '说明：传输监听端口（UDP/TCP/QUIC/WSS）仅代表底层加密隧道可达性；业务流量访问权限（如 TCP 8443）仅由已签 ACL 策略决定，绝不从传输端口自动放行。'),
  );
}

export async function renderNodes(container, navTo, selectedKey = '') {
  let state = { q: '', status: '', page: 1, size: 20, detailKey: selectedKey };
  const detailMount = el('div', {});
  const tableMount = el('div', {});
  const pagerMount = el('div', { class: 'toolbar-row between' });

  const searchInput = el('input', {
    type: 'search',
    placeholder: '搜索已签名称、自报主机名、虚拟 IP 或节点公钥…',
    'aria-label': '搜索节点',
    onInput: () => { state.q = searchInput.value.trim(); state.page = 1; loadList(); },
  });

  const filterDefs = [
    ['', '全部设备'],
    ['member', '已签成员'],
    ['request', '待审申请'],
    ['revoked', '已撤权'],
  ];
  const segBtns = filterDefs.map(([val, label]) => el('button', {
    type: 'button',
    class: 'seg-btn',
    'aria-pressed': val === state.status ? 'true' : 'false',
    onClick: () => {
      state.status = val;
      state.page = 1;
      for (let i = 0; i < segBtns.length; i++) {
        segBtns[i].setAttribute('aria-pressed', filterDefs[i][0] === val ? 'true' : 'false');
      }
      loadList();
    },
  }, label));
  const segmentedBar = el('div', { class: 'segmented', role: 'group', 'aria-label': '按角色状态筛选节点' }, ...segBtns);

  async function loadDetail() {
    if (!state.detailKey) {
      detailMount.replaceChildren();
      return;
    }
    try {
      const card = await renderNodeDetailCard(state.detailKey, navTo, () => { loadDetail(); loadList(); });
      detailMount.replaceChildren(card);
    } catch (err) {
      detailMount.replaceChildren(callout('error', err.message));
    }
  }

  async function loadList() {
    const qs = `q=${encodeURIComponent(state.q)}&status=${encodeURIComponent(state.status)}&page=${state.page}&size=${state.size}`;
    const res = await api(`nodes?${qs}`);
    const items = res.items || [];
    if (!items.length) {
      tableMount.replaceChildren(el('div', { class: 'empty-state' }, '暂无符合筛选条件的设备或密钥记录。'));
    } else {
      const rows = items.map((n) => {
        const ports = fmtPortsMap(n.transportPorts);
        const roleBadge = n.status === 'member'
          ? badge(`已签 #${n.memberId}`, 'ok')
          : n.status === 'revoked' ? badge('已撤权', 'err') : badge('待签申请', 'warn');
        const connBadge = !n.reported
          ? badge('缺少上报', 'warn')
          : n.online ? badge('在线', 'ok') : badge('离线', 'neutral');
        const dotKind = !n.reported ? 'warn' : n.online ? 'online' : '';

        return el('tr', {},
          el('th', { scope: 'row' },
            el('div', { class: 'node-title' },
              el('span', { class: `status-dot ${dotKind}` }),
              n.name || n.hostname || '未命名节点',
            ),
            el('div', { class: 'muted' },
              n.os ? `${n.os}` : '系统未知',
              n.name && n.hostname && n.name !== n.hostname ? ` · 自报 ${n.hostname}` : '',
            ),
          ),
          el('td', {}, el('div', { class: 'toolbar-row' }, roleBadge, connBadge, n.inventory ? badge('人工清单', 'accent') : null)),
          el('td', {}, n.ipv4 ? copyableCode(n.ipv4, '复制虚拟 IPv4') : '—'),
          el('td', {}, copyableCode(n.nodeKey, '复制节点公钥', true)),
          el('td', {},
            ports
              ? el('div', { class: 'chip-list' }, ...ports.map((p) => el('code', { class: 'chip' }, p)))
              : badge('未上报', 'neutral'),
          ),
          el('td', {}, n.reported ? fmtRelative(n.lastSeen) : '从未连接'),
          el('td', {},
            el('button', {
              type: 'button', class: 'btn secondary sm',
              onClick: () => navTo(`nodes/${encodeURIComponent(n.nodeKey)}`),
            }, '三方对照'),
          ),
        );
      });
      tableMount.replaceChildren(
        el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'nodes-cap' },
          el('table', { class: 'tbl-nodes' },
            el('caption', { id: 'nodes-cap' }, `节点与能力台账（共 ${res.total} 条）`),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, '设备名称'),
              el('th', { scope: 'col' }, '身份与协调状态'),
              el('th', { scope: 'col' }, '已签虚拟地址'),
              el('th', { scope: 'col' }, '节点公钥'),
              el('th', { scope: 'col' }, '传输监听端口'),
              el('th', { scope: 'col' }, '最近心跳'),
              el('th', { scope: 'col' }, '操作'),
            )),
            el('tbody', {}, rows),
          ),
        ),
      );
    }
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / state.size));
    pagerMount.replaceChildren(
      el('span', { class: 'muted' }, `共 ${res.total} 条 · 第 ${res.page} / ${maxPage} 页`),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page <= 1, onClick: () => { state.page--; loadList(); } }, '上一页'),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page >= maxPage, onClick: () => { state.page++; loadList(); } }, '下一页'),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, '节点详情与能力库存对照'),
        el('p', {}, '在同一视图严格并排核对「所有者已签身份」「节点自动上报提示」与「运维人工导入清单」。'),
      ),
    ),
    detailMount,
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' }, searchBox(searchInput), segmentedBar),
      tableMount,
      pagerMount,
    ),
  );
  await Promise.all([loadDetail(), loadList()]);
}
