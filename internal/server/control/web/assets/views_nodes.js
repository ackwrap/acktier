import { translateMessage } from './i18n.js';
import {
  api, el, badge, callout, createSearchInput, makeDropzone, copyableCode, fmtTime, fmtRelative, fmtPortsMap, toast, openModal, closeModal, confirmModal,
} from './api.js';
import { parseInventorySource } from './artifacts.js';
import { openAddMemberModal } from './views_overview.js';

async function openApproveRoutesModal(detail, navTo) {
  const signed = detail.signed;
  const unapproved = detail.flags?.unapprovedRoutes || [];
  const drafts = await api('drafts');
  const draftSelect = el('select', { id: 'route-draft-id' },
    el('option', { value: '__new__' }, translateMessage("＋ Create a draft from the active snapshot")),
    ...drafts.map((d) => el('option', { value: d.id }, translateMessage("{0} ({1} member(s))", d.name, d.members))),
  );
  if (drafts.length > 0) draftSelect.value = drafts[0].id;

  const checks = unapproved.map((rt) => {
    const cb = el('input', { type: 'checkbox', value: rt, checked: true });
    return { cb, row: el('label', { class: 'checkbox-row' }, cb, el('code', {}, rt)) };
  });
  const errBox = el('div', { class: 'callout error icon-start', hidden: true });

  const form = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      errBox.hidden = true;
      const chosen = checks.filter((x) => x.cb.checked).map((x) => x.cb.value);
      if (!chosen.length) {
        errBox.textContent = translateMessage("Select at least one subnet route to add to the draft.");
        errBox.hidden = false;
        return;
      }
      try {
        let draftId = draftSelect.value;
        if (draftId === '__new__') {
          const created = await api('drafts', {
            method: 'POST',
            body: { name: translateMessage("Route approval draft ({0})", signed.name), fromActive: true },
          });
          draftId = created.draft.id;
        }
        const cur = await api(`drafts/${encodeURIComponent(draftId)}`);
        const nextPol = structuredClone(cur.draft.policy);
        const member = nextPol.members.find((m) => m.nodeKey === detail.nodeKey);
        if (member) {
          member.routes = [...new Set([...(member.routes || []), ...chosen])];
          await api(`drafts/${encodeURIComponent(draftId)}`, { method: 'PUT', body: { policy: nextPol } });
        } else {
          await api(`drafts/${encodeURIComponent(draftId)}/members`, {
            method: 'POST',
            body: {
              nodeKey: detail.nodeKey,
              name: signed.name,
              ipv4: signed.ipv4,
              ipv6: signed.ipv6 || '',
              tags: signed.tags || [],
              routes: [...new Set([...(signed.routes || []), ...chosen])],
            },
          });
        }
        closeModal();
        toast(translateMessage("Routes added to the draft. Export, sign, and publish to apply them."));
        navTo(`policy/${draftId}`);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
      }
    },
  },
    callout('', translateMessage("Select the advertised subnets to approve in the policy draft. Active routes change after signed publication.")),
    errBox,
    el('div', { class: 'field' }, el('label', { for: 'route-draft-id' }, translateMessage("Target policy draft")), draftSelect),
    el('div', { class: 'field' }, el('label', {}, translateMessage("Unapproved subnets advertised by {0}", signed.name)), ...checks.map((x) => x.row)),
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
      el('button', { type: 'submit', class: 'btn primary btn-check icon-start' }, translateMessage("Save to policy draft")),
    ),
  );
  openModal(translateMessage("Draft route approval for {0}", signed.name), form);
}

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
      note: translateMessage("Datacenter inventory verification"),
    };

  const editor = el('textarea', {
    class: 'code-editor',
    id: 'inv-json-editor',
    spellcheck: 'false',
  }, JSON.stringify(sample, null, 2));

  const previewMount = el('div', { class: 'preview-card', hidden: true });
  const errBox = el('div', { id: 'inv-error', class: 'callout error icon-start', role: 'alert', hidden: true });
  const saveBtn = el('button', { type: 'submit', class: 'btn primary btn-check icon-start' }, translateMessage("Save imported inventory"));
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
        el('div', { class: 'preview-header' }, badge(translateMessage("Inventory preview (for review only)"), 'accent')),
        el('dl', { class: 'kv-grid' },
          el('div', {},
            el('dt', {}, translateMessage("Transport listeners")),
            el('dd', {}, parsedPayload.transports.length
              ? parsedPayload.transports.map((t) => `${String(t.proto).toUpperCase()}:${t.port}`).join(', ')
              : translateMessage("Not provided")),
          ),
          el('div', {},
            el('dt', {}, translateMessage("Candidate addresses")),
            el('dd', {}, translateMessage("{0} rule(s)", parsedPayload.endpoints.length)),
          ),
          el('div', {},
            el('dt', {}, translateMessage("Advertised subnets")),
            el('dd', {}, parsedPayload.routes.length ? parsedPayload.routes.join(', ') : translateMessage("None")),
          ),
          el('div', {},
            el('dt', {}, translateMessage("Note")),
            el('dd', {}, parsedPayload.note || '—'),
          ),
        ),
      );
    } catch (e) {
      invalidate(translateMessage("Invalid inventory. ") + e.message);
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
        if (f.size > 64 * 1024) throw new Error(translateMessage("The inventory file exceeds 64 KiB."));
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
        toast(translateMessage("Node inventory saved for comparison. NetMap and ACL are unchanged."));
        onSaved();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
        saveBtn.disabled = false;
      }
    },
  },
    callout('',
      translateMessage("The imported inventory is tied to this node public key and appears alongside its reported capabilities. The center uses it for review only."),
    ),
    errBox,
    el('div', { class: 'field' },
      el('label', { for: 'inv-file' }, translateMessage("Import inventory JSON (optional)")),
      makeDropzone(fileInput, translateMessage("Select or drop inventory JSON"), translateMessage("Up to 64 KiB · transports, endpoints, routes, or note")),
    ),
    el('div', { class: 'field' },
      el('label', { for: 'inv-json-editor' }, translateMessage("Inventory JSON")),
      el('div', { class: 'editor-frame' },
        el('div', { class: 'editor-bar' }, el('span', { class: 'mono' }, 'inventory.json'), el('span', {}, 'Read-Only Comparison Metadata')),
        editor,
      ),
    ),
    previewMount,
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
      saveBtn,
    ),
  );
  openModal(translateMessage("Import node capability inventory"), form);
}

async function renderNodeDetailCard(nodeKey, navTo, onRefresh) {
  const d = await api(`nodes/${encodeURIComponent(nodeKey)}`);
  const flags = d.flags || {};
  const signed = d.signed;
  const rep = d.reported;
  const inv = d.inventory;

  const statusBadges = [];
  if (signed) statusBadges.push(badge(translateMessage("Signed member #{0}", signed.id), 'ok'));
  else statusBadges.push(badge(translateMessage("Not in the active member list"), 'warn'));
  if (flags.authorizationExpired) statusBadges.push(badge(translateMessage("Signed authorization expired"), 'err'));
  if (flags.revoked) statusBadges.push(badge(translateMessage("Coordination key revoked"), 'err'));
  if (flags.missingReport) statusBadges.push(badge(translateMessage("Node reports unavailable"), 'warn'));
  else if (rep?.online) statusBadges.push(badge(translateMessage("Control stream online"), 'ok'));
  else statusBadges.push(badge(translateMessage("Control stream offline"), 'neutral'));
  if (inv) statusBadges.push(badge(translateMessage("Imported inventory available"), 'accent'));

  // Column 1: Owner-signed authoritative identity
  const signedCol = el('article', { class: 'card source-card signed form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, translateMessage("1. Owner-signed identity")),
      signed ? badge(translateMessage("Signed and active"), 'ok') : badge(translateMessage("No signed identity"), 'warn'),
    ),
    signed
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, translateMessage("Unique name / ID")), el('dd', {}, `${signed.name} (#${signed.id})`)),
        el('div', {}, el('dt', {}, translateMessage("Overlay IPv4 / IPv6")), el('dd', {},
          el('code', {}, signed.ipv4),
          signed.ipv6 ? el('div', {}, el('code', {}, signed.ipv6)) : null,
        )),
        el('div', {}, el('dt', {}, translateMessage("Authorized ACL tags")), el('dd', {},
          (signed.tags || []).length
            ? el('div', { class: 'chip-list' }, ...signed.tags.map((t) => el('code', { class: 'chip' }, t)))
            : translateMessage("No tags"),
        )),
        el('div', {}, el('dt', {}, translateMessage("Approved subnets and exit routes")), el('dd', {},
          (signed.routes || []).length
            ? el('div', { class: 'chip-list' }, ...signed.routes.map((rt) => el('code', { class: 'chip' }, rt)))
            : translateMessage("None"),
        )),
      )
      : el('div', { class: 'form-stack' },
        el('p', { class: 'muted' }, translateMessage("This public key needs an active signed authorization before it can carry data-plane traffic.")),
        rep && !flags.revoked
          ? el('button', {
            type: 'button', class: 'btn primary sm btn-plus icon-start',
            onClick: () => openAddMemberModal({
              nodeKey: d.nodeKey, hostname: rep.hostname, advertisedRoutes: rep.advertisedRoutes,
            }, navTo),
          }, translateMessage("Verify and add to policy draft"))
          : null,
      ),
  );

  // Column 2: Node auto-reported hints
  const repPorts = fmtPortsMap(rep?.transportPorts);
  const reportedCol = el('article', { class: 'card source-card reported form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, translateMessage("2. Node-reported connection hints")),
      rep ? badge(translateMessage("Heartbeat {0}", fmtRelative(rep.lastSeen)), rep.online ? 'ok' : 'neutral') : badge(translateMessage("Never reported"), 'warn'),
    ),
    rep
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, translateMessage("Reported hostname / OS")), el('dd', {}, `${rep.hostname || translateMessage("Not provided")} (${rep.os || '—'})`)),
        el('div', {}, el('dt', {}, translateMessage("Local transport listeners")), el('dd', {},
          repPorts
            ? el('div', { class: 'chip-list' }, ...repPorts.map((p) => el('code', { class: 'chip' }, p)))
            : badge(translateMessage("No direct listeners reported"), 'neutral'),
        )),
        el('div', {}, el('dt', {}, translateMessage("External candidates (IP:port)")), el('dd', {},
          (rep.endpoints || []).length
            ? el('div', { class: 'chip-list' }, ...rep.endpoints.map((ep) => el('code', { class: 'chip' },
              `${ep.addr}/${String(ep.proto).toUpperCase()}${ep.isLan ? ' · LAN' : ''}`)))
            : translateMessage("No candidate addresses"),
        )),
        el('div', {}, el('dt', {}, translateMessage("Node-advertised routes")), el('dd', {},
          (rep.advertisedRoutes || []).length
            ? el('div', { class: 'chip-list' }, ...rep.advertisedRoutes.map((rt) => el('code', { class: 'chip' }, rt)))
            : translateMessage("No advertised routes"),
        )),
        el('div', {}, el('dt', {}, translateMessage("Peer relay capability")), el('dd', {}, rep.canRelay ? translateMessage("Can act as a peer relay (CanRelay)") : translateMessage("Endpoint node"))),
      )
      : el('p', { class: 'muted' }, translateMessage("This key is signed, but the node has yet to register or send a heartbeat.")),
  );

  // Column 3: Operator-imported manual inventory (comparison only)
  const invCol = el('article', { class: 'card source-card inventory form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('h3', {}, translateMessage("3. Imported inventory for comparison")),
      inv ? badge(translateMessage("Updated {0}", fmtTime(inv.importedAt)), 'accent') : badge(translateMessage("No inventory"), 'neutral'),
    ),
    inv
      ? el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, translateMessage("Recorded transport listeners")), el('dd', {},
          (inv.transports || []).length
            ? el('div', { class: 'chip-list' }, ...inv.transports.map((t) => el('code', { class: 'chip' }, `${String(t.proto).toUpperCase()}:${t.port}`)))
            : '—',
        )),
        el('div', {}, el('dt', {}, translateMessage("Recorded candidate addresses")), el('dd', {},
          (inv.endpoints || []).length
            ? el('div', { class: 'chip-list' }, ...inv.endpoints.map((ep) => el('code', { class: 'chip' }, `${ep.addr}/${String(ep.proto).toUpperCase()}`)))
            : '—',
        )),
        el('div', {}, el('dt', {}, translateMessage("Recorded subnets")), el('dd', {},
          (inv.routes || []).length
            ? el('div', { class: 'chip-list' }, ...inv.routes.map((rt) => el('code', { class: 'chip' }, rt)))
            : '—',
        )),
        el('div', {}, el('dt', {}, translateMessage("Verification note")), el('dd', {}, inv.note || '—')),
      )
      : el('p', { class: 'muted' }, translateMessage("No inventory uploaded. Import expected listeners, public IPs, and subnets to compare with the node's reports.")),
    el('div', { class: 'toolbar-row' },
      el('button', { type: 'button', class: 'btn secondary sm btn-upload icon-start', onClick: () => openInventoryModal(d.nodeKey, inv, onRefresh) },
        inv ? translateMessage("Update inventory") : translateMessage("Upload inventory")),
      inv
        ? el('button', {
          type: 'button', class: 'btn danger sm btn-trash icon-start',
          onClick: async () => {
            const ok = await confirmModal({
              title: translateMessage("Remove imported inventory"),
              message: translateMessage("Remove imported inventory for {0}?", signed?.name || rep?.hostname || ''),
              detail: translateMessage("The node keeps its active authorization and reports."),
              confirmText: translateMessage("Confirm removal"),
            });
            if (!ok) return;
            await api(`nodes/${encodeURIComponent(d.nodeKey)}/inventory`, { method: 'DELETE' });
            toast(translateMessage("Imported inventory removed"));
            onRefresh();
          },
        }, translateMessage("Clear inventory"))
        : null,
    ),
  );

  const mismatchAlerts = [];
  if ((flags.unapprovedRoutes || []).length) {
    mismatchAlerts.push(el('div', { class: 'callout warn icon-start toolbar-row between' },
      el('span', {}, translateMessage("The node advertised unapproved subnets {0}. They require a signed authorization before forwarding.", flags.unapprovedRoutes.join('、'))),
      signed
        ? el('button', {
          type: 'button', class: 'btn secondary sm btn-plus icon-start',
          onClick: () => openApproveRoutesModal(d, navTo),
        }, translateMessage("Add routes to draft"))
        : null,
    ));
  }
  if ((flags.unadvertisedRoutes || []).length) {
    mismatchAlerts.push(callout('warn',
      translateMessage("The active snapshot approves subnet {0}, but the node did not advertise it in its latest heartbeat.", flags.unadvertisedRoutes.join('、'))));
  }

  return el('section', { class: 'card form-stack' },
    el('div', { class: 'toolbar-row between' },
      el('div', { class: 'form-stack' },
        el('div', { class: 'toolbar-row' },
          el('h2', {}, translateMessage("Node details for {0}", signed?.name || rep?.hostname || translateMessage("Unknown node"))),
          ...statusBadges,
        ),
        copyableCode(d.nodeKey, translateMessage("Copy full node public key")),
      ),
      el('button', { type: 'button', class: 'btn secondary sm btn-close icon-start', onClick: () => navTo('nodes') }, translateMessage("Close details")),
    ),
    ...mismatchAlerts,
    el('div', { class: 'three-col' }, signedCol, reportedCol, invCol),
    el('p', { class: 'field-hint' },
      translateMessage("UDP, TCP, QUIC, and WSS listeners show how the encrypted tunnel can be reached. Access to a service such as TCP 8443 requires a separate signed ACL rule.")),
  );
}

export async function renderNodes(container, navTo, selectedKey = '') {
  const isFilterParam = selectedKey.startsWith('status:');
  const initialStatus = isFilterParam ? selectedKey.slice(7) : '';
  let state = { q: '', status: initialStatus, page: 1, size: 20, detailKey: isFilterParam ? '' : selectedKey };
  const detailMount = el('div', {});
  const tableMount = el('div', {});
  const pagerMount = el('div', { class: 'toolbar-row between' });

  const searchWidget = createSearchInput({
    placeholder: translateMessage("Search by signed name, reported hostname, overlay IP, or public key…"),
    ariaLabel: translateMessage("Search nodes"),
    onSearch: (q) => { state.q = q; state.page = 1; loadList(); },
  });

  const filterDefs = [
    ['', translateMessage("All nodes")],
    ['member', translateMessage("Signed members")],
    ['request', translateMessage("Pending requests")],
    ['revoked', translateMessage("Revoked")],
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
  const segmentedBar = el('div', { class: 'segmented', role: 'group', 'aria-label': translateMessage("Filter by node status") }, ...segBtns);

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
      tableMount.replaceChildren(el('div', { class: 'empty-state' }, translateMessage("No nodes or keys match these filters.")));
    } else {
      const rows = items.map((n) => {
        const ports = fmtPortsMap(n.transportPorts);
        const roleBadge = n.status === 'member'
          ? badge(translateMessage("Signed #{0}", n.memberId), 'ok')
          : n.status === 'revoked' ? badge(translateMessage("Revoked"), 'err') : badge(translateMessage("Awaiting approval"), 'warn');
        const connBadge = !n.reported
          ? badge(translateMessage("No report"), 'warn')
          : n.online ? badge(translateMessage("Online"), 'ok') : badge(translateMessage("Offline"), 'neutral');
        const dotKind = !n.reported ? 'warn' : n.online ? 'online' : '';

        return el('tr', {},
          el('th', { scope: 'row' },
            el('div', { class: 'node-title' },
              el('span', { class: `status-dot ${dotKind}` }),
              n.name || n.hostname || translateMessage("Unnamed node"),
            ),
            el('div', { class: 'muted' },
              n.os ? `${n.os}` : translateMessage("Unknown OS"),
              n.name && n.hostname && n.name !== n.hostname ? translateMessage(" · reported as {0}", n.hostname) : '',
            ),
          ),
          el('td', {}, el('div', { class: 'toolbar-row' }, roleBadge, connBadge, n.inventory ? badge(translateMessage("Imported inventory"), 'accent') : null)),
          el('td', {}, n.ipv4 ? copyableCode(n.ipv4, translateMessage("Copy overlay IPv4")) : '—'),
          el('td', {}, copyableCode(n.nodeKey, translateMessage("Copy node public key"), true)),
          el('td', {},
            ports
              ? el('div', { class: 'chip-list' }, ...ports.map((p) => el('code', { class: 'chip' }, p)))
              : badge(translateMessage("Not reported"), 'neutral'),
          ),
          el('td', {}, n.reported ? fmtRelative(n.lastSeen) : translateMessage("Never connected")),
          el('td', {},
            el('div', { class: 'toolbar-row' },
              n.status === 'request'
                ? el('button', {
                  type: 'button', class: 'btn primary sm btn-plus icon-start',
                  onClick: () => openAddMemberModal({
                    nodeKey: n.nodeKey, hostname: n.hostname, advertisedRoutes: n.advertisedRoutes,
                  }, navTo),
                }, translateMessage("Add to draft"))
                : null,
              el('button', {
                type: 'button', class: 'btn secondary sm',
                onClick: () => navTo(`nodes/${encodeURIComponent(n.nodeKey)}`),
              }, translateMessage("Compare details")),
            ),
          ),
        );
      });
      tableMount.replaceChildren(
        el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'nodes-cap' },
          el('table', { class: 'tbl-nodes' },
            el('caption', { id: 'nodes-cap' }, translateMessage("Node and capability inventory ({0})", res.total)),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, translateMessage("Node name")),
              el('th', { scope: 'col' }, translateMessage("Identity and coordination")),
              el('th', { scope: 'col' }, translateMessage("Signed overlay addresses")),
              el('th', { scope: 'col' }, translateMessage("Node public key")),
              el('th', { scope: 'col' }, translateMessage("Transport listeners")),
              el('th', { scope: 'col' }, translateMessage("Last heartbeat")),
              el('th', { scope: 'col' }, translateMessage("Actions")),
            )),
            el('tbody', {}, rows),
          ),
        ),
      );
    }
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / state.size));
    pagerMount.replaceChildren(
      el('span', { class: 'muted' }, translateMessage("{0} total · Page {1} of {2}", res.total, res.page, maxPage)),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page <= 1, onClick: () => { state.page--; loadList(); } }, translateMessage("Previous")),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: state.page >= maxPage, onClick: () => { state.page++; loadList(); } }, translateMessage("Next")),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("Nodes and capabilities")),
        el('p', {}, translateMessage("Compare owner-signed identity, node-reported connection hints, and imported inventory side by side.")),
      ),
    ),
    detailMount,
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' }, searchWidget, segmentedBar),
      tableMount,
      pagerMount,
    ),
  );
  await Promise.all([loadDetail(), loadList()]);
}
