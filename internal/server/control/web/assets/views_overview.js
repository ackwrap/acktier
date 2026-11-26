import {
  api, el, badge, callout, searchBox, copyableCode, fmtTime, fmtRelative, fmtBytes, fmtPortsMap, toast, openModal, closeModal,
} from './api.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined) n.setAttribute(k, String(v));
  }
  return n;
}

function buildTopologyCanvas(topo, revision) {
  const nodes = topo?.nodes || [];
  const links = topo?.links || [];
  if (!nodes.length) {
    return el('div', { class: 'empty-state' }, '尚无已签成员。完成首次策略签发并发布后，此处将渲染实时 P2P 链路、RTT 延迟与跳板拓扑。');
  }

  const width = 780;
  const height = 340;
  const cx = width / 2;
  const cy = height / 2;
  const rx = Math.min(265, Math.max(115, nodes.length * 44));
  const ry = 88;

  const svg = svgEl('svg', {
    viewBox: `0 0 ${width} ${height}`,
    class: 'topo-svg',
    role: 'img',
    'aria-label': '组网成员与实测链路拓扑图',
  });

  // Subtle dot-matrix background pattern
  const defs = svgEl('defs', {});
  const pattern = svgEl('pattern', { id: 'mesh-grid', width: 24, height: 24, patternUnits: 'userSpaceOnUse' });
  pattern.append(svgEl('circle', { cx: 2, cy: 2, r: 1, class: 'topo-grid-dot' }));
  defs.append(pattern);
  svg.append(defs);
  svg.append(svgEl('rect', { width, height, fill: 'url(#mesh-grid)' }));

  const pos = new Map();
  nodes.forEach((n, idx) => {
    const angle = nodes.length === 1 ? 0 : (2 * Math.PI * idx) / nodes.length - Math.PI / 2;
    const x = nodes.length === 1 ? cx : Math.round(cx + rx * Math.cos(angle));
    const y = nodes.length === 1 ? cy : Math.round(cy + ry * Math.sin(angle));
    pos.set(n.key, { x, y, node: n });
  });

  // Curved quadratic Bezier links + pill RTT badges
  for (const l of links) {
    const a = pos.get(l.a);
    const b = pos.get(l.b);
    if (!a || !b) continue;
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const pullX = Math.round(mx + (cx - mx) * 0.16);
    const pullY = Math.round(my + (cy - my) * 0.16);
    svg.append(svgEl('path', {
      d: `M ${a.x} ${a.y} Q ${pullX} ${pullY} ${b.x} ${b.y}`,
      class: 'topo-link',
    }));

    const lx = Math.round(0.25 * a.x + 0.5 * pullX + 0.25 * b.x);
    const ly = Math.round(0.25 * a.y + 0.5 * pullY + 0.25 * b.y);
    const textStr = `${(l.proto || 'p2p').toUpperCase()} · ${Number(l.rttMs || 0).toFixed(1)} ms`;
    const pillW = Math.max(76, textStr.length * 6.4);
    svg.append(svgEl('rect', {
      x: Math.round(lx - pillW / 2), y: ly - 10, width: Math.round(pillW), height: 19, rx: 9.5,
      class: 'topo-pill-bg',
    }));
    const label = svgEl('text', { x: lx, y: ly + 3.5, 'text-anchor': 'middle', class: 'topo-link-label' });
    label.textContent = textStr;
    svg.append(label);
  }

  // Multi-ring node markers + structured node plates
  for (const { x, y, node } of pos.values()) {
    const g = svgEl('g', {});
    if (node.online) {
      g.append(svgEl('circle', { cx: x, cy: y, r: 22, class: 'topo-halo' }));
    }
    if (node.canRelay) {
      g.append(svgEl('circle', { cx: x, cy: y, r: 17, class: 'topo-relay-ring' }));
    }
    g.append(svgEl('circle', {
      cx: x, cy: y, r: 11,
      class: node.online ? 'topo-node-online' : 'topo-node-offline',
    }));

    const titleText = `${node.name}${node.canRelay ? ' · 跳板' : ''}`;
    const ipText = node.ip || '—';
    const plateW = Math.max(110, Math.max(titleText.length * 8.5, ipText.length * 7.2) + 20);
    const placeAbove = nodes.length > 1 && y < cy - 10;
    const plateY = placeAbove ? y - 56 : y + 20;
    g.append(svgEl('rect', {
      x: Math.round(x - plateW / 2), y: plateY, width: Math.round(plateW), height: 36, rx: 7,
      class: 'topo-plate',
    }));
    const nameEl = svgEl('text', { x, y: plateY + 15, 'text-anchor': 'middle', class: 'topo-node-name' });
    nameEl.textContent = titleText;
    const ipEl = svgEl('text', { x, y: plateY + 29, 'text-anchor': 'middle', class: 'topo-node-ip' });
    ipEl.textContent = ipText;
    g.append(nameEl);
    g.append(ipEl);
    svg.append(g);
  }

  return el('div', { class: 'topo-frame' },
    el('div', { class: 'topo-legend' },
      el('div', { class: 'topo-legend-items' },
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot online' }), '在线成员'),
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot warn' }), '支持对等跳板 (CanRelay)'),
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot' }), '离线成员'),
      ),
      el('span', { class: 'mono' }, `NetMap 修订号 #${revision ?? 0}`),
    ),
    svg,
  );
}

function kpiCard(label, value, foot, iconClass) {
  return el('article', { class: 'kpi-card' },
    el('div', { class: 'kpi-top' },
      el('span', { class: 'kpi-label' }, label),
      el('span', { class: `kpi-glyph icon ${iconClass}`, 'aria-hidden': 'true' }),
    ),
    el('span', { class: 'kpi-value' }, value),
    el('span', { class: 'kpi-foot' }, foot),
  );
}

export async function renderOverview(container, navTo, updateChrome) {
  const data = await api('overview');
  updateChrome(data);

  const auth = data.authorization;
  const counts = data.counts || {};
  const relay = data.relay || {};

  let authSection;
  if (!auth) {
    authSection = callout('warn',
      el('strong', {}, '尚未发布任何已签授权快照。'),
      ' 当前所有者公钥已锁定，但数据面尚无生效成员表。请先在「入网申请」核对设备公钥并加入草稿，导出后在所有者电脑本地执行 ',
      el('code', {}, 'acktier owner sign'),
      '，再到「签名发布与历史」上传 ',
      el('code', {}, 'authorization.json'),
      '。',
    );
  } else {
    const expMs = new Date(auth.expiresAt).getTime() - Date.now();
    const hoursLeft = Math.max(0, Math.round(expMs / 3600000));
    const pct = auth.expired ? 0 : Math.min(100, Math.max(6, Math.round((hoursLeft / 168) * 100)));
    const barState = auth.expired ? 'err' : hoursLeft < 24 ? 'warn' : 'ok';
    authSection = el('div', { class: 'form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('div', { class: 'toolbar-row' },
          badge(`活动版本 v${auth.version}`, 'accent'),
          auth.expired ? badge('授权已过期（节点数据面停用）', 'err') : badge(`有效期内 · 约剩 ${hoursLeft} 小时`, hoursLeft < 24 ? 'warn' : 'ok'),
        ),
        el('span', { class: 'muted' }, `到期时间：${fmtTime(auth.expiresAt)}`),
      ),
      el('progress', { class: `expiry-bar ${barState}`, value: pct, max: 100, 'aria-label': '授权剩余有效期比例' }),
      el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, '快照 SHA-256 摘要'), el('dd', {}, copyableCode(auth.digest, '复制快照摘要', true))),
        el('div', {}, el('dt', {}, '防回滚最低水位'), el('dd', {}, `v${data.minimumVersion}`)),
        el('div', {}, el('dt', {}, '已签成员 / 编译规则'), el('dd', {}, `${auth.members} 台成员 · ${auth.rules} 条过滤规则`)),
      ),
    );
  }

  const auditRows = (data.recentAudit || []).map((a) => el('tr', {},
    el('th', { scope: 'row', class: 'mono' }, fmtTime(a.at)),
    el('td', {}, a.actor || '—'),
    el('td', {}, el('code', { class: 'chip' }, a.action)),
    el('td', {}, a.target ? el('code', { class: 'breakable' }, a.target) : '—'),
    el('td', {}, badge(a.result === 'success' ? '成功' : '失败', a.result === 'success' ? 'ok' : 'err'), a.detail ? ` ${a.detail}` : ''),
  ));

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, '概览与实时协调状态'),
        el('p', {}, '严格区分「所有者信任根已绑定」「快照已签成员」与「中心协调流心跳」三种独立状态。'),
      ),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary', onClick: () => navTo('requests') }, `入网申请 (${counts.requests || 0})`),
        el('button', { type: 'button', class: 'btn primary btn-upload icon-start', onClick: () => navTo('publish') }, '上传已签授权'),
      ),
    ),

    el('div', { class: 'kpi-grid' },
      kpiCard('根信任状态', '已锁定', `最低版本要求 v${data.minimumVersion}`, 'kpi-icon-trust'),
      kpiCard('已签授权成员', String(counts.members || 0), auth ? `来自已签快照 v${auth.version}` : '尚未发布签名快照', 'kpi-icon-members'),
      kpiCard('协调流在线', `${counts.membersOnline || 0} / ${counts.members || 0}`, '仅代表中心控制流心跳', 'kpi-icon-online'),
      kpiCard('待审入网申请', String(counts.requests || 0), '核对公钥后可加入草稿', 'kpi-icon-requests'),
      kpiCard('待签策略草稿', String(counts.drafts || 0), `可用申请码 ${counts.keysActive || 0} 个`, 'kpi-icon-drafts'),
      kpiCard('中心密文中继', `${relay.clients || 0} 会话`, `转发 ${relay.frames || 0} 帧 (${fmtBytes(relay.bytes)})`, 'kpi-icon-relay'),
    ),

    el('section', { class: 'card form-stack' },
      el('h2', {}, '活动签名授权租约'),
      authSection,
    ),

    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, '组网成员与实测链路拓扑'),
        el('button', { type: 'button', class: 'btn ghost sm', onClick: () => navTo('nodes') }, '查看全部设备台账'),
      ),
      buildTopologyCanvas(data.topology, data.revision),
    ),

    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, '最近关键操作审计'),
        el('button', { type: 'button', class: 'btn ghost sm', onClick: () => navTo('security') }, '查看完整审计日志'),
      ),
      auditRows.length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': '最近关键操作记录' },
          el('table', { class: 'tbl-audit' },
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, '时间'),
              el('th', { scope: 'col' }, '操作者'),
              el('th', { scope: 'col' }, '动作'),
              el('th', { scope: 'col' }, '目标'),
              el('th', { scope: 'col' }, '结果与说明'),
            )),
            el('tbody', {}, auditRows),
          ),
        )
        : el('div', { class: 'empty-state' }, '暂无管理审计记录。'),
    ),
  );
}

export async function openAddMemberModal(reqRow, navTo) {
  const drafts = await api('drafts');
  const draftSelect = el('select', { id: 'add-draft-id' },
    el('option', { value: '__new__' }, '＋ 新建一份基于当前生效快照的草稿'),
    ...drafts.map((d) => el('option', { value: d.id }, `${d.name} (基于 v${d.baseVersion} · ${d.members} 成员)`)),
  );
  if (drafts.length > 0) draftSelect.value = drafts[0].id;

  const nameInput = el('input', {
    type: 'text', id: 'add-member-name', placeholder: '留空则按申请名规范化分配',
    value: (reqRow.hostname || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, ''),
  });
  const ipInput = el('input', { type: 'text', id: 'add-member-ip', placeholder: '留空则自动分配 100.64.x.y' });
  const tagsInput = el('input', { type: 'text', id: 'add-member-tags', placeholder: '可选，逗号分隔，如 tag:dev, tag:server' });

  const routeChecks = (reqRow.advertisedRoutes || []).map((rt) => {
    const cb = el('input', { type: 'checkbox', value: rt });
    return { cb, row: el('label', { class: 'checkbox-row' }, cb, el('code', {}, rt)) };
  });
  const extraRoutes = el('input', { type: 'text', id: 'add-member-routes', placeholder: '额外批准 CIDR（可选，逗号分隔，出口填 0.0.0.0/0）' });
  const errBox = el('div', { class: 'callout error icon-start', hidden: true });

  const form = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      errBox.hidden = true;
      try {
        let draftId = draftSelect.value;
        if (draftId === '__new__') {
          const created = await api('drafts', {
            method: 'POST',
            body: { name: `入网变更草稿 (${reqRow.hostname || '新节点'})`, fromActive: true },
          });
          draftId = created.draft.id;
        }
        const tags = tagsInput.value.split(',').map((s) => s.trim()).filter(Boolean);
        const routes = [
          ...routeChecks.filter((x) => x.cb.checked).map((x) => x.cb.value),
          ...extraRoutes.value.split(',').map((s) => s.trim()).filter(Boolean),
        ];
        await api(`drafts/${encodeURIComponent(draftId)}/members`, {
          method: 'POST',
          body: {
            nodeKey: reqRow.nodeKey,
            name: nameInput.value.trim(),
            ipv4: ipInput.value.trim(),
            tags,
            routes,
          },
        });
        closeModal();
        toast('已将节点加入策略草稿（尚未生效，需导出给所有者本地签名发布）');
        navTo(`policy/${draftId}`);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
      }
    },
  },
    callout('warn',
      '注意：将节点加入草稿不会授予任何组网权限。请务必通过节点本机执行 ',
      el('code', {}, 'acktier owner node-key'),
      ' 或其他独立可信渠道核对下方公钥！',
    ),
    errBox,
    el('div', { class: 'field' },
      el('label', {}, '待核对节点公钥'),
      copyableCode(reqRow.nodeKey, '复制申请节点公钥'),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'add-draft-id' }, '目标策略草稿'),
      draftSelect,
    ),
    el('div', { class: 'form-row' },
      el('div', { class: 'field' }, el('label', { for: 'add-member-name' }, '签发唯一 DNS 名称'), nameInput),
      el('div', { class: 'field' }, el('label', { for: 'add-member-ip' }, '签发虚拟 IPv4'), ipInput),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'add-member-tags' }, '管理员授予标签（用于 ACL 选择器）'),
      tagsInput,
    ),
    routeChecks.length
      ? el('div', { class: 'field' },
        el('label', {}, '节点自报网段（默认不勾选，核实后按需批准）'),
        ...routeChecks.map((x) => x.row),
      )
      : null,
    el('div', { class: 'field' },
      el('label', { for: 'add-member-routes' }, '附加批准子网 / 出口路由'),
      extraRoutes,
    ),
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal, autofocus: true }, '取消'),
      el('button', { type: 'submit', class: 'btn primary btn-plus icon-start' }, '加入策略草稿'),
    ),
  );
  openModal('核对申请并加入策略草稿', form);
}

export async function renderRequests(container, navTo) {
  let state = { q: '', page: 1, size: 15 };
  const tableMount = el('div', {});
  const pagerMount = el('div', { class: 'toolbar-row between' });

  const searchInput = el('input', {
    type: 'search',
    placeholder: '搜索自报主机名、操作系统或节点公钥…',
    'aria-label': '搜索入网申请',
    onInput: () => {
      state.q = searchInput.value.trim();
      state.page = 1;
      load();
    },
  });

  async function load() {
    const res = await api(`requests?q=${encodeURIComponent(state.q)}&page=${state.page}&size=${state.size}`);
    const items = res.items || [];
    if (!items.length) {
      tableMount.replaceChildren(el('div', { class: 'empty-state' },
        state.q ? '没有匹配筛选条件的入网申请。' : '当前没有待处理的入网申请。节点使用申请码执行 acktier up 后会在此显示。'));
    } else {
      const rows = items.map((r) => {
        const ports = fmtPortsMap(r.transportPorts);
        return el('tr', {},
          el('th', { scope: 'row' },
            el('div', { class: 'node-title' },
              el('span', { class: 'status-dot warn' }),
              r.hostname || '未填写主机名',
            ),
            el('span', { class: 'muted' }, '未核验自报主机名'),
          ),
          el('td', {}, el('span', { class: 'chip' }, r.os || 'unknown')),
          el('td', {}, copyableCode(r.nodeKey, '复制节点公钥', true)),
          el('td', {},
            ports
              ? el('div', { class: 'chip-list' }, ...ports.map((p) => el('code', { class: 'chip' }, p)))
              : badge('监听端口：未上报', 'neutral'),
            el('div', { class: 'muted' }, `候选地址 ${r.endpoints || 0} 个 · ${fmtRelative(r.lastSeen)}`),
          ),
          el('td', {},
            (r.advertisedRoutes || []).length
              ? el('div', { class: 'chip-list' }, ...r.advertisedRoutes.map((rt) => el('code', { class: 'chip' }, rt)))
              : '—',
          ),
          el('td', {},
            el('div', { class: 'toolbar-row' },
              el('button', { type: 'button', class: 'btn primary sm btn-plus icon-start', onClick: () => openAddMemberModal(r, navTo) }, '加入草稿'),
              el('button', { type: 'button', class: 'btn secondary sm', onClick: () => navTo(`nodes/${encodeURIComponent(r.nodeKey)}`) }, '详情'),
            ),
          ),
        );
      });
      tableMount.replaceChildren(
        el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'req-cap' },
          el('table', { class: 'tbl-requests' },
            el('caption', { id: 'req-cap' }, `待处理入网申请（共 ${res.total} 条，当前第 ${res.page} 页）`),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, '申请设备'),
              el('th', { scope: 'col' }, '系统'),
              el('th', { scope: 'col' }, '节点公钥'),
              el('th', { scope: 'col' }, '传输与上报'),
              el('th', { scope: 'col' }, '申报网段'),
              el('th', { scope: 'col' }, '操作'),
            )),
            el('tbody', {}, rows),
          ),
        ),
      );
    }
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / state.size));
    pagerMount.replaceChildren(
      el('span', { class: 'muted' }, `共 ${res.total} 条记录 · 第 ${res.page} / ${maxPage} 页`),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page <= 1, onClick: () => { state.page--; load(); } }, '上一页'),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page >= maxPage, onClick: () => { state.page++; load(); } }, '下一页'),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, '入网申请审查'),
        el('p', {}, '中心仅展示节点凭申请码提交的未验证申请。核对设备公钥后可将其加入策略草稿，交由所有者离线签发。'),
      ),
      el('button', { type: 'button', class: 'btn secondary btn-key icon-start', onClick: () => navTo('security') }, '管理入网申请码'),
    ),
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' }, searchBox(searchInput)),
      tableMount,
      pagerMount,
    ),
  );
  await load();
}
