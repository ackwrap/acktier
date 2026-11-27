import { translateMessage } from './i18n.js';
import {
  api, el, badge, callout, createSearchInput, copyableCode, fmtTime, fmtRelative, fmtBytes, fmtPortsMap, toast, openModal, closeModal,
} from './api.js';
import { renderAuditRow } from './views_audit.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined) n.setAttribute(k, String(v));
  }
  return n;
}

function buildTopologyCanvas(topo) {
  const nodes = topo?.nodes || [];
  const links = topo?.links || [];
  if (!nodes.length) {
    return el('div', { class: 'empty-state' }, translateMessage("Publish the first signed policy to see the member topology, RTT, and peer relays."));
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
    'aria-label': translateMessage("Network members and observed link topology"),
  });

  // Subtle dot-matrix background pattern + soft card drop-shadow
  const defs = svgEl('defs', {});
  const pattern = svgEl('pattern', { id: 'mesh-grid', width: 22, height: 22, patternUnits: 'userSpaceOnUse' });
  pattern.append(svgEl('circle', { cx: 2, cy: 2, r: 1, class: 'topo-grid-dot' }));
  const shadow = svgEl('filter', { id: 'plate-shadow', x: '-12%', y: '-12%', width: '124%', height: '132%' });
  shadow.append(svgEl('feDropShadow', { dx: '0', dy: '2', stdDeviation: '2.5', 'flood-opacity': '0.09' }));
  defs.append(pattern);
  defs.append(shadow);
  svg.append(defs);
  svg.append(svgEl('rect', { width, height, fill: 'url(#mesh-grid)' }));

  const pos = new Map();
  nodes.forEach((n, idx) => {
    const angle = nodes.length === 1 ? 0 : (2 * Math.PI * idx) / nodes.length - Math.PI / 2;
    const x = nodes.length === 1 ? cx : Math.round(cx + rx * Math.cos(angle));
    const y = nodes.length === 1 ? cy : Math.round(cy + ry * Math.sin(angle));
    pos.set(n.key, { x, y, node: n });
  });

  // Curved quadratic Bezier links + staggered collision-free pill RTT badges
  const placedPills = [];
  links.forEach((l, idx) => {
    const a = pos.get(l.a);
    const b = pos.get(l.b);
    if (!a || !b) return;
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.hypot(dx, dy) || 1;
    const bend = (idx % 2 === 0 ? 1 : -1) * Math.min(26, len * 0.1);
    const pullX = Math.round(mx + (-dy / len) * bend);
    const pullY = Math.round(my + (dx / len) * bend);
    const protoKey = String(l.proto || 'p2p').toLowerCase();
    svg.append(svgEl('path', {
      d: `M ${a.x} ${a.y} Q ${pullX} ${pullY} ${b.x} ${b.y}`,
      class: `topo-link proto-${protoKey}`,
    }));

    const t = [0.5, 0.36, 0.64, 0.43][idx % 4];
    const omt = 1 - t;
    let lx = Math.round(omt * omt * a.x + 2 * omt * t * pullX + t * t * b.x);
    let ly = Math.round(omt * omt * a.y + 2 * omt * t * pullY + t * t * b.y);
    const textStr = `${protoKey.toUpperCase()} · ${Number(l.rttMs || 0).toFixed(1)} ms`;
    const pillW = Math.round(Math.max(80, textStr.length * 6.5));
    for (const prev of placedPills) {
      if (Math.abs(lx - prev.x) < (pillW + prev.w) / 2 + 4 && Math.abs(ly - prev.y) < 22) {
        ly = ly >= prev.y ? prev.y + 23 : prev.y - 23;
      }
    }
    placedPills.push({ x: lx, y: ly, w: pillW });
    svg.append(svgEl('rect', {
      x: Math.round(lx - pillW / 2), y: ly - 10, width: pillW, height: 19, rx: 9.5,
      class: 'topo-pill-bg', filter: 'url(#plate-shadow)',
    }));
    const label = svgEl('text', { x: lx, y: ly + 3.5, 'text-anchor': 'middle', class: 'topo-link-label' });
    label.textContent = textStr;
    svg.append(label);
  });

  // Interactive clickable node markers + structured node plates
  for (const { x, y, node } of pos.values()) {
    const link = svgEl('a', {
      href: `#nodes/${encodeURIComponent(node.key)}`,
      class: 'topo-node-link',
      'aria-label': translateMessage("View capability details for {0}", node.name),
    });
    if (node.online) {
      link.append(svgEl('circle', { cx: x, cy: y, r: 22, class: 'topo-halo' }));
    }
    if (node.canRelay) {
      link.append(svgEl('circle', { cx: x, cy: y, r: 17, class: 'topo-relay-ring' }));
    }
    link.append(svgEl('circle', {
      cx: x, cy: y, r: 11,
      class: node.online ? 'topo-node-online' : 'topo-node-offline',
    }));

    const titleText = `${node.name}${node.canRelay ? translateMessage(" · relay") : ''}`;
    const ipText = node.ip || '—';
    const plateW = Math.max(110, Math.max(titleText.length * 8.5, ipText.length * 7.2) + 20);
    const placeAbove = nodes.length > 1 && y < cy - 10;
    const plateY = placeAbove ? y - 57 : y + 20;
    link.append(svgEl('rect', {
      x: Math.round(x - plateW / 2), y: plateY, width: Math.round(plateW), height: 36, rx: 8,
      class: 'topo-plate', filter: 'url(#plate-shadow)',
    }));
    const nameEl = svgEl('text', { x, y: plateY + 15, 'text-anchor': 'middle', class: 'topo-node-name' });
    nameEl.textContent = titleText;
    const ipEl = svgEl('text', { x, y: plateY + 29, 'text-anchor': 'middle', class: 'topo-node-ip' });
    ipEl.textContent = ipText;
    link.append(nameEl);
    link.append(ipEl);
    svg.append(link);
  }

  return el('div', { class: 'topo-frame' },
    el('div', { class: 'topo-legend' },
      el('div', { class: 'topo-legend-items' },
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot online' }), translateMessage("Online member")),
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot warn' }), translateMessage("Peer relay capable (CanRelay)")),
        el('span', { class: 'legend-item' }, el('span', { class: 'status-dot' }), translateMessage("Offline member")),
      ),
      el('span', { class: 'muted' }, translateMessage("Select a node to compare its capabilities.")),
    ),
    svg,
  );
}

function kpiCard(label, value, foot, iconClass, href = '') {
  const titleNode = href
    ? el('a', { class: 'card-link kpi-label', href }, label)
    : el('span', { class: 'kpi-label' }, label);
  return el('article', { class: 'kpi-card' },
    el('div', { class: 'kpi-top' },
      titleNode,
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
      el('strong', {}, translateMessage("No signed authorization published.")),
      translateMessage(" The owner key is pinned. To authorize members, verify their keys in Join requests, add them to a draft, export the policy, and run "),
      el('code', {}, 'acktier owner sign'),
      translateMessage(" on the owner computer. Then open Publish authorization and upload "),
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
        auth.expired ? badge(translateMessage("Authorization expired (node data plane suspended)"), 'err') : badge(translateMessage("Valid · About {0} hour(s) remaining", hoursLeft), hoursLeft < 24 ? 'warn' : 'ok'),
        el('span', { class: 'muted' }, translateMessage("Expires {0}", fmtTime(auth.expiresAt))),
      ),
      el('progress', { class: `expiry-bar ${barState}`, value: pct, max: 100, 'aria-label': translateMessage("Remaining authorization lifetime") }),
      el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, translateMessage("Snapshot SHA-256 digest")), el('dd', {}, copyableCode(auth.digest, translateMessage("Copy snapshot digest"), true))),
        el('div', {}, el('dt', {}, translateMessage("Signed members / compiled rules")), el('dd', {}, translateMessage("{0} member(s) · {1} filter rule(s)", auth.members, auth.rules))),
      ),
    );
  }

  const auditRows = (data.recentAudit || []).map(renderAuditRow);

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("Overview and coordination")),
        el('p', {}, translateMessage("Root binding, signed membership, and control-stream heartbeats represent independent states.")),
      ),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary', onClick: () => navTo('requests') }, translateMessage("Join requests ({0})", counts.requests || 0)),
        el('button', { type: 'button', class: 'btn primary btn-upload icon-start', onClick: () => navTo('publish') }, translateMessage("Upload signed authorization")),
      ),
    ),

    el('div', { class: 'kpi-grid' },
      kpiCard(translateMessage("Root trust"), translateMessage("Pinned"), translateMessage("View authorization and history"), 'kpi-icon-trust', '#publish'),
      kpiCard(translateMessage("Signed members"), String(counts.members || 0), auth ? translateMessage("Show all signed members") : translateMessage("No authorization published"), 'kpi-icon-members', '#nodes/status:member'),
      kpiCard(translateMessage("Control stream online"), `${counts.membersOnline || 0} / ${counts.members || 0}`, translateMessage("Based on the center's control-stream heartbeat"), 'kpi-icon-online', '#nodes/status:member'),
      kpiCard(translateMessage("Pending join requests"), String(counts.requests || 0), translateMessage("Review keys and add to a draft"), 'kpi-icon-requests', '#requests'),
      kpiCard(translateMessage("Unsigned policy drafts"), String(counts.drafts || 0), translateMessage("{0} available enrollment key(s)", counts.keysActive || 0), 'kpi-icon-drafts', '#policy'),
      kpiCard(translateMessage("Center relay"), translateMessage("{0} session(s)", relay.clients || 0), translateMessage("Forwarded {0} frames ({1})", relay.frames || 0, fmtBytes(relay.bytes)), 'kpi-icon-relay'),
    ),

    el('section', { class: 'card form-stack' },
      el('h2', {}, translateMessage("Authorization status")),
      authSection,
    ),

    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, translateMessage("Member and link topology")),
        el('button', { type: 'button', class: 'btn ghost sm', onClick: () => navTo('nodes') }, translateMessage("View all nodes")),
      ),
      buildTopologyCanvas(data.topology),
    ),

    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, translateMessage("Recent audit events")),
        el('button', { type: 'button', class: 'btn ghost sm', onClick: () => navTo('security') }, translateMessage("View full audit log")),
      ),
      auditRows.length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': translateMessage("Recent actions") },
          el('table', { class: 'tbl-audit' },
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, translateMessage("Time")),
              el('th', { scope: 'col' }, translateMessage("Actor")),
              el('th', { scope: 'col' }, translateMessage("Action")),
              el('th', { scope: 'col' }, translateMessage("Destination")),
              el('th', { scope: 'col' }, translateMessage("Result and details")),
            )),
            el('tbody', {}, auditRows),
          ),
        )
        : el('div', { class: 'empty-state' }, translateMessage("No audit events yet.")),
    ),
  );
}

export async function openAddMemberModal(reqRow, navTo) {
  const drafts = await api('drafts');
  const draftSelect = el('select', { id: 'add-draft-id' },
    el('option', { value: '__new__' }, translateMessage("＋ Create a draft from the active snapshot")),
    ...drafts.map((d) => el('option', { value: d.id }, translateMessage("{0} ({1} member(s))", d.name, d.members))),
  );
  if (drafts.length > 0) draftSelect.value = drafts[0].id;

  const nameInput = el('input', {
    type: 'text', id: 'add-member-name', placeholder: translateMessage("Leave blank to derive a name from the request"),
    value: (reqRow.hostname || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, ''),
  });
  const ipInput = el('input', { type: 'text', id: 'add-member-ip', placeholder: translateMessage("Leave blank to assign an address in 100.64.x.y") });
  const tagsInput = el('input', { type: 'text', id: 'add-member-tags', placeholder: translateMessage("Optional comma-separated tags, such as tag:dev, tag:server") });

  const routeChecks = (reqRow.advertisedRoutes || []).map((rt) => {
    const cb = el('input', { type: 'checkbox', value: rt });
    return { cb, row: el('label', { class: 'checkbox-row' }, cb, el('code', {}, rt)) };
  });
  const extraRoutes = el('input', { type: 'text', id: 'add-member-routes', placeholder: translateMessage("Additional approved CIDRs (optional, comma-separated)") });
  const addExitChip = el('button', {
    type: 'button', class: 'preset-chip',
    onClick: () => {
      const parts = extraRoutes.value.split(',').map((s) => s.trim()).filter(Boolean);
      if (!parts.includes('0.0.0.0/0')) parts.push('0.0.0.0/0');
      extraRoutes.value = parts.join(', ');
    },
  }, translateMessage("＋ Add default exit route 0.0.0.0/0"));
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
            body: { name: translateMessage("Enrollment draft ({0})", reqRow.hostname || translateMessage("New node")), fromActive: true },
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
        toast(translateMessage("Node added to the draft. The owner must sign and publish it to grant access."));
        navTo(`policy/${draftId}`);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
      }
    },
  },
    callout('warn',
      translateMessage("Verify the public key before granting access. Run "),
      el('code', {}, 'acktier owner node-key'),
      translateMessage(" on the node or use another trusted channel."),
    ),
    errBox,
    el('div', { class: 'field' },
      el('label', {}, translateMessage("Node public key to verify")),
      copyableCode(reqRow.nodeKey, translateMessage("Copy requesting node's public key")),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'add-draft-id' }, translateMessage("Target policy draft")),
      draftSelect,
    ),
    el('div', { class: 'form-row' },
      el('div', { class: 'field' }, el('label', { for: 'add-member-name' }, translateMessage("Signed DNS name")), nameInput),
      el('div', { class: 'field' }, el('label', { for: 'add-member-ip' }, translateMessage("Signed overlay IPv4")), ipInput),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'add-member-tags' }, translateMessage("Administrator-assigned ACL tags")),
      tagsInput,
    ),
    routeChecks.length
      ? el('div', { class: 'field' },
        el('label', {}, translateMessage("Node-advertised subnets (select only after verification)")),
        ...routeChecks.map((x) => x.row),
      )
      : null,
    el('div', { class: 'field' },
      el('label', { for: 'add-member-routes' }, translateMessage("Additional approved subnets and exits")),
      extraRoutes,
      el('div', { class: 'preset-row' }, addExitChip),
    ),
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal, autofocus: true }, translateMessage("Cancel")),
      el('button', { type: 'submit', class: 'btn primary btn-plus icon-start' }, translateMessage("Add to policy draft")),
    ),
  );
  openModal(translateMessage("Review request and add to a draft"), form);
}

export async function renderRequests(container, navTo) {
  let state = { q: '', page: 1, size: 15 };
  const tableMount = el('div', {});
  const pagerMount = el('div', { class: 'toolbar-row between' });

  const searchWidget = createSearchInput({
    placeholder: translateMessage("Search by reported hostname, OS, or node public key…"),
    ariaLabel: translateMessage("Search join requests"),
    onSearch: (q) => {
      state.q = q;
      state.page = 1;
      load();
    },
  });

  async function load() {
    const res = await api(`requests?q=${encodeURIComponent(state.q)}&page=${state.page}&size=${state.size}`);
    const items = res.items || [];
    if (!items.length) {
      tableMount.replaceChildren(el('div', { class: 'empty-state' },
        state.q ? translateMessage("No join requests match the filters.") : translateMessage("No pending join requests. Requests appear after a node runs acktier up with an enrollment key.")));
    } else {
      const rows = items.map((r) => {
        const ports = fmtPortsMap(r.transportPorts);
        return el('tr', {},
          el('th', { scope: 'row' },
            el('div', { class: 'node-title' },
              el('span', { class: 'status-dot warn' }),
              r.hostname || translateMessage("No hostname provided"),
            ),
            el('span', { class: 'muted' }, translateMessage("Unverified hostname")),
          ),
          el('td', {}, el('span', { class: 'chip' }, r.os || 'unknown')),
          el('td', {}, copyableCode(r.nodeKey, translateMessage("Copy node public key"), true)),
          el('td', {},
            ports
              ? el('div', { class: 'chip-list' }, ...ports.map((p) => el('code', { class: 'chip' }, p)))
              : badge(translateMessage("No transport listeners reported"), 'neutral'),
            el('div', { class: 'muted' }, translateMessage("{0} candidate(s) · {1}", r.endpoints || 0, fmtRelative(r.lastSeen))),
          ),
          el('td', {},
            (r.advertisedRoutes || []).length
              ? el('div', { class: 'chip-list' }, ...r.advertisedRoutes.map((rt) => el('code', { class: 'chip' }, rt)))
              : '—',
          ),
          el('td', {},
            el('div', { class: 'toolbar-row' },
              el('button', { type: 'button', class: 'btn primary sm btn-plus icon-start', onClick: () => openAddMemberModal(r, navTo) }, translateMessage("Add to draft")),
              el('button', { type: 'button', class: 'btn secondary sm', onClick: () => navTo(`nodes/${encodeURIComponent(r.nodeKey)}`) }, translateMessage("Details")),
            ),
          ),
        );
      });
      tableMount.replaceChildren(
        el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'req-cap' },
          el('table', { class: 'tbl-requests' },
            el('caption', { id: 'req-cap' }, translateMessage("Pending join requests ({0} total, page {1})", res.total, res.page)),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, translateMessage("Requesting node")),
              el('th', { scope: 'col' }, translateMessage("OS")),
              el('th', { scope: 'col' }, translateMessage("Node public key")),
              el('th', { scope: 'col' }, translateMessage("Transports and reports")),
              el('th', { scope: 'col' }, translateMessage("Advertised subnets")),
              el('th', { scope: 'col' }, translateMessage("Actions")),
            )),
            el('tbody', {}, rows),
          ),
        ),
      );
    }
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / state.size));
    pagerMount.replaceChildren(
      el('span', { class: 'muted' }, translateMessage("{0} result(s) · Page {1} of {2}", res.total, res.page, maxPage)),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page <= 1, onClick: () => { state.page--; load(); } }, translateMessage("Previous")),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page >= maxPage, onClick: () => { state.page++; load(); } }, translateMessage("Next")),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("Review join requests")),
        el('p', {}, translateMessage("The center lists unverified requests submitted with enrollment keys. Verify each public key before adding a node to a draft for the owner to sign.")),
      ),
      el('button', { type: 'button', class: 'btn secondary btn-key icon-start', onClick: () => navTo('security') }, translateMessage("Manage enrollment keys")),
    ),
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' }, searchWidget),
      tableMount,
      pagerMount,
    ),
  );
  await load();
}
