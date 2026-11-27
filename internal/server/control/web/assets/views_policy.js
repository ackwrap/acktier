import { translateMessage } from './i18n.js';
import { translateCenterMessage } from './center_messages.js';
import {
  api, downloadFile, el, badge, callout, bindDropzone, copyableCode, terminalSnippet, fmtTime, toast, openModal, closeModal, confirmModal, buildTabs,
} from './api.js';
import { confirmDiscardACL, renderACLEditor } from './acl_editor.js';
import { parsePolicySource, readPublicArtifact } from './artifacts.js';

function renderRuleTable(rules, captionText) {
  if (!rules || !rules.length) {
    return el('div', { class: 'empty-state' }, translateMessage("No compiled rules. Traffic between nodes needs an explicit allow rule."));
  }
  return el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': captionText },
    el('table', { class: 'tbl-rules' },
      el('caption', {}, captionText),
      el('thead', {}, el('tr', {},
        el('th', { scope: 'col' }, translateMessage("Action")),
        el('th', { scope: 'col' }, translateMessage("Protocol")),
        el('th', { scope: 'col' }, translateMessage("Source prefix")),
        el('th', { scope: 'col' }, translateMessage("Destination prefix")),
        el('th', { scope: 'col' }, translateMessage("Destination service port")),
      )),
      el('tbody', {}, rules.map((r) => el('tr', {},
        el('th', { scope: 'row' }, badge(r.action === 'accept' ? translateMessage("Allow · accept") : translateMessage("Drop · drop"), r.action === 'accept' ? 'ok' : 'err')),
        el('td', {}, el('code', { class: 'chip' }, String(r.proto || '*').toUpperCase())),
        el('td', {}, el('div', { class: 'chip-list' }, ...(r.src || []).slice(0, 6).map((s) => el('code', { class: 'chip' }, translateCenterMessage(s))),
          (r.src || []).length > 6 ? el('span', { class: 'muted' }, translateMessage("+{0} more", r.src.length - 6)) : null)),
        el('td', {}, el('div', { class: 'chip-list' }, ...(r.dst || []).slice(0, 6).map((d) => el('code', { class: 'chip' }, translateCenterMessage(d))),
          (r.dst || []).length > 6 ? el('span', { class: 'muted' }, translateMessage("+{0} more", r.dst.length - 6)) : null)),
        el('td', {}, el('code', { class: 'chip' }, r.ports || '*')),
      ))),
    ),
  );
}

function renderDiffSummary(diff) {
  if (!diff) return el('p', { class: 'muted' }, translateMessage("No comparison available."));
  const items = [];
  if (!diff.hasActive) {
    items.push(callout('', translateMessage("The center has no active snapshot. Publication will authorize {0} member(s) and install {1} packet filter rule(s).", diff.added?.length || 0, diff.rulesAfter || 0)));
  } else {
    items.push(el('dl', { class: 'kv-grid' },
      el('div', {}, el('dt', {}, translateMessage("＋ Added members")), el('dd', {}, diff.added?.length ? diff.added.map((m) => `${m.name} (${m.ipv4})`).join('、') : translateMessage("None"))),
      el('div', {}, el('dt', {}, translateMessage("− Removed members")), el('dd', {}, diff.removed?.length
        ? badge(diff.removed.map((m) => m.name).join('、'), 'err') : translateMessage("None"))),
      el('div', {}, el('dt', {}, translateMessage("~ Changed members")), el('dd', {}, diff.changed?.length
        ? diff.changed.map((c) => `${c.member.name} [${c.fields.map(translateCenterMessage).join('/')}]`).join(', ') : translateMessage("None"))),
      el('div', {}, el('dt', {}, translateMessage("Compiled filter rules")), el('dd', {}, diff.rulesSame
        ? translateMessage("Unchanged ({0} rule(s))", diff.rulesAfter) : translateMessage("{0} → {1} rule(s)", diff.rulesBefore, diff.rulesAfter))),
      el('div', {}, el('dt', {}, translateMessage("DNS / STUN changes")), el('dd', {},
        `${diff.dnsChanged ? translateMessage("DNS changed") : translateMessage("DNS unchanged")} · ${diff.stunChanged ? translateMessage("STUN changed") : translateMessage("STUN unchanged")}`)),
    ));
  }
  return el('div', { class: 'form-stack' }, ...items);
}

async function openEditDraftMemberModal(draft, member, onSaved) {
  const detail = await api(`nodes/${encodeURIComponent(member.nodeKey)}`).catch(() => null);
  const currentRoutes = new Set(member.routes || []);
  const reportedExtra = (detail?.reported?.advertisedRoutes || []).filter((rt) => !currentRoutes.has(rt));

  const nameIn = el('input', { type: 'text', id: 'edit-mem-name', required: true, value: member.name || '' });
  const ip4In = el('input', { type: 'text', id: 'edit-mem-ip4', required: true, value: member.ipv4 || '' });
  const ip6In = el('input', { type: 'text', id: 'edit-mem-ip6', placeholder: translateMessage("Optional, such as fd7a:115c:a1e0::11"), value: member.ipv6 || '' });
  const tagsIn = el('input', {
    type: 'text', id: 'edit-mem-tags', placeholder: translateMessage("Comma-separated tags, such as tag:dev, tag:server"),
    value: (member.tags || []).join(', '),
  });
  const routesIn = el('input', {
    type: 'text', id: 'edit-mem-routes', placeholder: translateMessage("Comma-separated CIDRs, such as 192.168.10.0/24"),
    value: (member.routes || []).join(', '),
  });
  const extraChecks = reportedExtra.map((rt) => {
    const cb = el('input', { type: 'checkbox', value: rt });
    return { cb, row: el('label', { class: 'checkbox-row' }, cb, el('code', {}, rt), el('span', { class: 'muted' }, translateMessage(" (last node report)"))) };
  });
  const exitBtn = el('button', {
    type: 'button', class: 'preset-chip',
    onClick: () => {
      const list = routesIn.value.split(',').map((s) => s.trim()).filter(Boolean);
      if (!list.includes('0.0.0.0/0')) list.push('0.0.0.0/0');
      routesIn.value = list.join(', ');
    },
  }, translateMessage("＋ Add default exit route 0.0.0.0/0"));
  const errBox = el('div', { class: 'callout error icon-start', hidden: true });

  const form = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      errBox.hidden = true;
      const name = nameIn.value.trim().toLowerCase();
      if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(name)) {
        errBox.textContent = translateMessage("Use lowercase letters, digits, and hyphens. The name must start and end with a letter or digit.");
        errBox.hidden = false;
        return;
      }
      const tags = tagsIn.value.split(',').map((s) => s.trim()).filter(Boolean);
      if (tags.some((t) => !/^tag:[a-zA-Z0-9_-]+$/.test(t))) {
        errBox.textContent = translateMessage("Start each tag with tag:, for example tag:dev.");
        errBox.hidden = false;
        return;
      }
      const routes = [...new Set([
        ...routesIn.value.split(',').map((s) => s.trim()).filter(Boolean),
        ...extraChecks.filter((x) => x.cb.checked).map((x) => x.cb.value),
      ])];
      try {
        const nextPol = structuredClone(draft.policy);
        const idx = nextPol.members.findIndex((m) => m.nodeKey === member.nodeKey);
        if (idx < 0) throw new Error(translateMessage("This member was not found in the draft."));
        const updatedMember = {
          ...nextPol.members[idx],
          name,
          ipv4: ip4In.value.trim(),
          tags,
          routes,
        };
        const ip6 = ip6In.value.trim();
        if (ip6) updatedMember.ipv6 = ip6;
        else delete updatedMember.ipv6;
        nextPol.members[idx] = updatedMember;
        await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'PUT', body: { policy: nextPol, requireValid: true } });
        closeModal();
        toast(translateMessage("Updated draft member {0}", name));
        onSaved();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
      }
    },
  },
    errBox,
    el('div', { class: 'field' }, el('label', {}, translateMessage("Node public key (member #{0})", member.id)), copyableCode(member.nodeKey, translateMessage("Copy member public key"))),
    el('div', { class: 'form-row' },
      el('div', { class: 'field' }, el('label', { for: 'edit-mem-name' }, translateMessage("Unique DNS name")), nameIn),
      el('div', { class: 'field' }, el('label', { for: 'edit-mem-ip4' }, translateMessage("Overlay IPv4")), ip4In),
    ),
    el('div', { class: 'field' }, el('label', { for: 'edit-mem-ip6' }, translateMessage("Overlay IPv6 (optional)")), ip6In),
    el('div', { class: 'field' }, el('label', { for: 'edit-mem-tags' }, translateMessage("Authorized ACL tags")), tagsIn),
    extraChecks.length
      ? el('div', { class: 'field' }, el('label', {}, translateMessage("Select newly advertised subnets to add")), ...extraChecks.map((x) => x.row))
      : null,
    el('div', { class: 'field' },
      el('label', { for: 'edit-mem-routes' }, translateMessage("Approved subnets and exit routes")),
      routesIn,
      el('div', { class: 'preset-row' }, exitBtn),
    ),
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
      el('button', { type: 'submit', class: 'btn primary btn-check icon-start' }, translateMessage("Save member changes")),
    ),
  );
  openModal(translateMessage("Edit draft member {0}", member.name), form);
}

function openDraftMetaModal({ mode, draft, onTriggerImport, onDone }) {
  const isCreate = mode === 'create';
  const nameIn = el('input', {
    type: 'text', id: 'draft-meta-name', maxlength: 64, required: true,
    value: isCreate ? translateMessage("Policy draft") : (draft?.name || ''),
    placeholder: translateMessage("For example, engineering node enrollment"),
    autofocus: true,
  });
  const noteIn = el('input', {
    type: 'text', id: 'draft-meta-note', maxlength: 240,
    value: isCreate ? '' : (draft?.note || ''),
    placeholder: translateMessage("Optional note about the change"),
  });
  const errBox = el('div', { class: 'callout error icon-start', hidden: true });
  const importFallbackBtn = el('button', {
    type: 'button', class: 'btn secondary sm btn-upload icon-start', hidden: true,
    onClick: () => { closeModal(); onTriggerImport?.(); },
  }, translateMessage("Import complete policy.json"));

  const form = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      errBox.hidden = true;
      importFallbackBtn.hidden = true;
      try {
        if (isCreate) {
          const created = await api('drafts', {
            method: 'POST',
            body: { name: nameIn.value.trim(), note: noteIn.value.trim(), fromActive: true },
          });
          closeModal();
          toast(translateMessage("Policy draft created"));
          onDone(created.draft.id);
        } else {
          await api(`drafts/${encodeURIComponent(draft.id)}`, {
            method: 'PUT',
            body: { name: nameIn.value.trim(), note: noteIn.value.trim() },
          });
          closeModal();
          toast(translateMessage("Draft metadata updated"));
          onDone(draft.id);
        }
      } catch (err) {
        errBox.textContent = err.message;
        errBox.hidden = false;
        if (err.code === 'policy_source_required') importFallbackBtn.hidden = false;
      }
    },
  },
    errBox,
    importFallbackBtn,
    el('div', { class: 'field' }, el('label', { for: 'draft-meta-name' }, translateMessage("Draft name")), nameIn),
    el('div', { class: 'field' }, el('label', { for: 'draft-meta-note' }, translateMessage("Change note (optional)")), noteIn),
    el('div', { class: 'form-actions' },
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
      el('button', { type: 'submit', class: 'btn primary btn-check icon-start' }, isCreate ? translateMessage("Create draft") : translateMessage("Save details")),
    ),
  );
  openModal(isCreate ? translateMessage("New policy draft") : translateMessage("Edit draft name and note"), form);
  requestAnimationFrame(() => nameIn.select());
}

export async function renderPolicy(container, navTo, refreshGlobal, initialDraftId = '') {
  const [activeData, draftsList] = await Promise.all([api('policy/active'), api('drafts')]);
  let selectedId = initialDraftId || draftsList[0]?.id || '';
  let workspaceSeq = 0;

  const draftSidebarMount = el('div', { class: 'draft-list' });
  const workspaceMount = el('div', { class: 'form-stack' });

  async function reloadSidebar() {
    const list = await api('drafts');
    if (!selectedId && list.length) selectedId = list[0].id;
    if (selectedId && !list.some((d) => d.id === selectedId)) selectedId = list[0]?.id || '';
    draftSidebarMount.replaceChildren(
      ...(list.length
        ? list.map((d) => el('button', {
          type: 'button',
          class: `draft-item${d.id === selectedId ? ' active' : ''}`,
          dataset: { draftId: d.id },
          'aria-pressed': d.id === selectedId ? 'true' : 'false',
          onClick: () => {
            if (selectedId === d.id || !confirmDiscardACL(workspaceMount)) return;
            selectedId = d.id;
            for (const button of draftSidebarMount.querySelectorAll('.draft-item')) {
              const selected = button.dataset.draftId === selectedId;
              button.classList.toggle('active', selected);
              button.setAttribute('aria-pressed', String(selected));
            }
            loadDraftWorkspace();
          },
        },
          el('div', { class: 'toolbar-row between' },
            el('strong', {}, d.name),
            d.valid ? badge(translateMessage("Valid"), 'ok') : badge(translateMessage("Needs attention"), 'err'),
          ),
          el('span', { class: 'muted' }, translateMessage("{0} member(s) · {1} ACL rule(s)", d.members, d.aclRules)),
          d.baseStale ? badge(translateMessage("Review needed"), 'warn') : null,
        ))
        : [el('div', { class: 'empty-state' }, translateMessage("Create or import a draft to get started."))]),
    );
    refreshGlobal();
  }

  async function loadDraftWorkspace(initialTab = 'acl', data = null) {
    const seq = ++workspaceSeq;
    const afterACLSave = data !== null;
    if (!selectedId) {
      workspaceMount.replaceChildren(
        el('section', { class: 'card form-stack' },
          el('h2', {}, translateMessage("Published signed rules (read only)")),
          activeData.hasActive
            ? renderRuleTable(activeData.rules, translateMessage("Signed packet filter rules"))
            : el('div', { class: 'empty-state' }, translateMessage("No signed policy published. Create a draft to define members and ACLs.")),
        ),
      );
      return;
    }

    const id = selectedId;
    if (!data) {
      workspaceMount.replaceChildren(el('p', { role: 'status', class: 'muted' }, translateMessage("Loading the draft…")));
      try {
        data = await api(`drafts/${encodeURIComponent(id)}`);
      } catch (err) {
        if (seq === workspaceSeq) workspaceMount.replaceChildren(callout('error', err.message));
        return;
      }
    }
    if (seq !== workspaceSeq || id !== selectedId) return;
    const { draft, analysis } = data;
    const pol = draft.policy;
    let tabsRef = null;

    const issuesNodes = (analysis.issues || []).map(({ level, message }) => {
      const isStaleWarn = level === 'warning' && analysis.baseStale && message.startsWith('草稿基于 v');
      if (!isStaleWarn) {
        const text = translateCenterMessage(message);
        return level === 'error'
          ? callout('error', translateMessage("Validation error: {0}", text))
          : callout('warn', translateMessage("Review note: {0}", text));
      }
      return el('div', { class: 'callout warn icon-start toolbar-row between' },
        el('span', {}, translateMessage("The active policy has changed since this draft was created. Review the changes before exporting.")),
        el('div', { class: 'toolbar-row' },
          el('button', { type: 'button', class: 'btn ghost sm', onClick: () => tabsRef?.select('diff', true) }, translateMessage("View changes")),
          el('button', {
            type: 'button', class: 'btn secondary sm btn-check icon-start',
            onClick: async () => {
              if (!confirmDiscardACL(workspaceMount)) return;
              await api(`drafts/${encodeURIComponent(draft.id)}`, {
                method: 'PUT',
                body: { name: draft.name, note: draft.note || '', rebase: true },
              });
              toast(translateMessage("Updated the draft's base version"));
              await reloadSidebar();
              if (seq === workspaceSeq) loadDraftWorkspace();
            },
          }, translateMessage("Confirm review and update base")),
        ),
      );
    });

    // Members & DNS/STUN
    const dnsEnable = el('input', { type: 'checkbox', checked: !!pol.dns?.enableMagicDNS });
    const dnsSuffix = el('input', { type: 'text', value: pol.dns?.magicDNSSuffix || 'ack.internal', placeholder: 'ack.internal' });
    const stun1 = el('input', { type: 'text', value: pol.stunAddr || '', placeholder: translateMessage("Literal IP and port, such as 203.0.113.10:3478") });
    const stun2 = el('input', { type: 'text', value: pol.stunAltAddr || '', placeholder: translateMessage("Optional secondary STUN IP and port") });

    const membersTab = el('div', { class: 'form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('span', { class: 'muted' }, translateMessage("Edit names, tags, and approved routes here. Use Join requests to add new nodes.")),
        el('button', { type: 'button', class: 'btn secondary sm btn-plus icon-start', onClick: () => navTo('requests') }, translateMessage("Open join requests")),
      ),
      (pol.members || []).length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': translateMessage("Draft members") },
          el('table', { class: 'tbl-members' },
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, 'ID'),
              el('th', { scope: 'col' }, translateMessage("Unique name")),
              el('th', { scope: 'col' }, translateMessage("Overlay addresses")),
              el('th', { scope: 'col' }, translateMessage("Node public key")),
              el('th', { scope: 'col' }, translateMessage("Tags and approved routes")),
              el('th', { scope: 'col' }, translateMessage("Actions")),
            )),
            el('tbody', {}, pol.members.map((m) => el('tr', {},
              el('th', { scope: 'row', class: 'mono' }, `#${m.id}`),
              el('td', {}, el('code', {}, m.name)),
              el('td', {}, el('code', {}, m.ipv4), m.ipv6 ? el('div', {}, el('code', {}, m.ipv6)) : null),
              el('td', {}, copyableCode(m.nodeKey, translateMessage("Copy member public key"), true)),
              el('td', {},
                (m.tags || []).length || (m.routes || []).length
                  ? el('div', { class: 'chip-list' },
                    ...(m.tags || []).map((t) => el('code', { class: 'chip' }, t)),
                    ...(m.routes || []).map((rt) => el('code', { class: 'chip' }, rt)),
                  )
                  : el('span', { class: 'muted' }, '—'),
              ),
              el('td', {},
                el('div', { class: 'toolbar-row' },
                  el('button', {
                    type: 'button', class: 'btn secondary sm',
                    onClick: () => {
                      if (!confirmDiscardACL(workspaceMount)) return;
                      openEditDraftMemberModal(draft, m, () => {
                        reloadSidebar();
                        if (seq === workspaceSeq) loadDraftWorkspace('members');
                      });
                    },
                  }, translateMessage("Edit")),
                  el('button', {
                    type: 'button', class: 'btn danger sm btn-trash icon-start',
                    onClick: async () => {
                      if (!confirmDiscardACL(workspaceMount)) return;
                      const ok = await confirmModal({
                        title: translateMessage("Remove member from draft"),
                        message: translateMessage("Remove {1} (#{2}) from draft {0}?", draft.name, m.name, m.id),
                        detail: translateMessage("This edits the draft. The node loses access when the owner signs and publishes the updated policy."),
                        confirmText: translateMessage("Confirm removal"),
                      });
                      if (!ok) return;
                      await api(`drafts/${encodeURIComponent(draft.id)}/members/${encodeURIComponent(m.nodeKey)}`, { method: 'DELETE' });
                      toast(translateMessage("Removed {0} from the draft", m.name));
                      reloadSidebar();
                      if (seq === workspaceSeq) loadDraftWorkspace('members');
                    },
                  }, translateMessage("Remove")),
                ),
              ),
            ))),
          ),
        )
        : el('div', { class: 'empty-state' }, translateMessage("This draft has no members.")),

      el('div', { class: 'card form-stack' },
        el('h3', {}, translateMessage("DNS and signed STUN settings")),
        el('label', { class: 'checkbox-row' }, dnsEnable, el('span', {}, translateMessage("Enable MagicDNS (100.100.100.100)"))),
        el('div', { class: 'form-row' },
          el('div', { class: 'field' }, el('label', {}, translateMessage("MagicDNS suffix")), dnsSuffix),
          el('div', { class: 'field' }, el('label', {}, translateMessage("Primary STUN (literal IP:port)")), stun1),
          el('div', { class: 'field' }, el('label', {}, translateMessage("Secondary STUN (literal IP:port)")), stun2),
        ),
        el('div', { class: 'form-actions' },
          el('button', {
            type: 'button', class: 'btn primary sm btn-check icon-start',
            onClick: async () => {
              if (!confirmDiscardACL(workspaceMount)) return;
              const nextPol = structuredClone(pol);
              nextPol.dns = { enableMagicDNS: dnsEnable.checked, magicDNSSuffix: dnsSuffix.value.trim(), nameservers: pol.dns?.nameservers };
              nextPol.stunAddr = stun1.value.trim();
              nextPol.stunAltAddr = stun2.value.trim();
              await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'PUT', body: { policy: nextPol } });
              toast(translateMessage("DNS and STUN settings saved to draft"));
              reloadSidebar();
              if (seq === workspaceSeq) loadDraftWorkspace('members');
            },
          }, translateMessage("Save DNS / STUN to draft")),
        ),
      ),
    );

    const exportButtons = [];
    const pendingNotice = el('p', { class: 'callout warn icon-start', hidden: true }, translateMessage("Save the unsaved changes in ACL rules before comparing or exporting the draft."));
    const diffPreview = el('div', { class: 'form-stack' },
      renderDiffSummary(analysis.diff),
      renderRuleTable(analysis.rules, translateMessage("Packet filter rules for signing")),
    );
    const aclTab = renderACLEditor(draft,
      analysis.valid
        ? renderRuleTable(analysis.rules, translateMessage("Compiled packet filter rules ({0})", analysis.rules.length))
        : callout('warn', translateMessage("Fix the validation errors and save the draft to see compiled rules.")),
      (saved) => {
        if (seq !== workspaceSeq || !workspaceMount.isConnected) return;
        toast(translateMessage("ACL draft saved. The active authorization is unchanged."));
        loadDraftWorkspace('acl', saved);
        reloadSidebar().catch((err) => toast(err.message));
      },
      (pending) => {
        pendingNotice.hidden = !pending;
        diffPreview.hidden = pending;
        for (const button of exportButtons) button.disabled = pending || !analysis.valid;
      });

    // Full policy.json editor & stateless check
    const fullEditor = el('textarea', { class: 'code-editor', spellcheck: 'false' }, JSON.stringify(pol, null, 2));
    const fullMsg = el('div', { hidden: true });
    const fullTab = el('div', { class: 'form-stack' },
      fullMsg,
      el('div', { class: 'field' },
        el('label', {}, translateMessage("Complete policy.json (members, acl, dns, and stunAddr)")),
        el('div', { class: 'editor-frame' },
          el('div', { class: 'editor-bar' },
            el('span', { class: 'mono' }, `${draft.id}-policy.json`),
            el('button', {
              type: 'button', class: 'btn ghost sm',
              onClick: () => {
                try { fullEditor.value = JSON.stringify(JSON.parse(fullEditor.value), null, 2); } catch (e) { toast(translateMessage("Invalid JSON syntax. ") + e.message); }
              },
            }, translateMessage("Format JSON")),
          ),
          fullEditor,
        ),
      ),
      el('div', { class: 'form-actions' },
        el('button', {
          type: 'button', class: 'btn secondary',
          onClick: async () => {
            try {
              const candidate = parsePolicySource(fullEditor.value);
              const res = await api('policy/validate', { method: 'POST', body: { policy: candidate, baseVersion: draft.baseVersion } });
              fullMsg.className = `callout ${res.valid ? 'ok' : 'error'} icon-start`;
              fullMsg.textContent = res.valid
                ? translateMessage("Validation passed. The policy compiles to {0} packet filter rule(s) with {1} notice(s).", res.rules?.length || 0, res.issues?.length || 0)
                : translateMessage("Validation failed. ") + (res.issues?.find((issue) => issue.level === 'error')?.message || translateMessage("Errors found"));
              fullMsg.hidden = false;
            } catch (err) {
              fullMsg.className = 'callout error icon-start';
              fullMsg.textContent = err.message;
              fullMsg.hidden = false;
            }
          },
        }, translateMessage("Validate JSON")),
        el('button', {
          type: 'button', class: 'btn primary btn-check icon-start',
          onClick: async () => {
            try {
              const candidate = parsePolicySource(fullEditor.value);
              if (!confirmDiscardACL(workspaceMount)) return;
              await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'PUT', body: { policy: candidate } });
              toast(translateMessage("Full policy draft saved"));
              reloadSidebar();
              if (seq === workspaceSeq) loadDraftWorkspace('json');
            } catch (err) {
              fullMsg.className = 'callout error icon-start';
              fullMsg.textContent = err.message;
              fullMsg.hidden = false;
            }
          },
        }, translateMessage("Save full draft")),
      ),
    );

    // Diff vs Active & Export for offline signing
    const signCmd = `acktier owner sign --dir ./data/owner --policy ./${draft.id}-policy.json --valid-for 168h`;
    const downloadDraft = async () => {
      try {
        await downloadFile(`drafts/${encodeURIComponent(draft.id)}/export`, `${draft.id}-policy.json`);
        toast(translateMessage("Exported policy.json for signing"));
      } catch (err) {
        toast(err.message);
      }
    };
    const exportButton = (label, size = '') => {
      const button = el('button', {
        type: 'button', class: `btn primary ${size} btn-download icon-start`, disabled: !analysis.valid, onClick: downloadDraft,
      }, label);
      exportButtons.push(button);
      return button;
    };
    const diffTab = el('div', { class: 'form-stack' },
      pendingNotice,
      diffPreview,
      el('div', { class: 'card form-stack' },
        el('h3', {}, translateMessage("Export the policy for offline signing")),
        el('p', { class: 'muted' }, translateMessage("Export the JSON. Verify member public keys and changes on the owner computer, then run the signing command there. Upload the resulting authorization.json under Publish authorization.")),
        terminalSnippet(signCmd, translateMessage("Copy local signing command")),
        el('div', { class: 'form-actions' },
          exportButton(translateMessage("Export policy.json for signing")),
          el('button', { type: 'button', class: 'btn secondary btn-upload icon-start', onClick: () => navTo('publish') }, translateMessage("Upload authorization.json")),
        ),
      ),
    );

    tabsRef = buildTabs(translateMessage("Policy draft workspace"), [
      { id: 'acl', title: translateMessage("ACL rules"), content: aclTab },
      { id: 'members', title: translateMessage("Members and routes ({0})", pol.members?.length || 0), content: membersTab },
      { id: 'diff', title: translateMessage("Compare and export"), content: diffTab },
      { id: 'json', title: translateMessage("Full policy JSON"), content: fullTab },
    ], initialTab);

    workspaceMount.replaceChildren(
      el('section', { class: 'card form-stack' },
        el('div', { class: 'toolbar-row between' },
          el('div', {},
            el('div', { class: 'toolbar-row' },
              el('h2', {}, draft.name),
              analysis.valid ? badge(translateMessage("Validation passed"), 'ok') : badge(translateMessage("Errors found"), 'err'),
            ),
            el('span', { class: 'muted' },
              draft.note ? `${draft.note} · ` : '',
              translateMessage("Last saved {0}", fmtTime(draft.updatedAt)),
            ),
          ),
          el('div', { class: 'toolbar-row' },
            el('button', {
              type: 'button', class: 'btn ghost sm',
              onClick: () => {
                if (!confirmDiscardACL(workspaceMount)) return;
                openDraftMetaModal({
                  mode: 'edit',
                  draft,
                  onDone: async () => {
                    await reloadSidebar();
                    if (seq === workspaceSeq) loadDraftWorkspace();
                  },
                });
              },
            }, translateMessage("Rename or edit note")),
            exportButton(translateMessage("Export policy.json"), 'sm'),
            el('button', {
              type: 'button', class: 'btn danger sm btn-trash icon-start',
              onClick: async () => {
                if (!confirmDiscardACL(workspaceMount)) return;
                const ok = await confirmModal({
                  title: translateMessage("Delete policy draft"),
                  message: translateMessage("Delete draft {0} permanently?", draft.name),
                  detail: translateMessage("Deletion discards unpublished draft changes. The published authorization stays active."),
                  confirmText: translateMessage("Confirm draft deletion"),
                });
                if (!ok) return;
                await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'DELETE' });
                selectedId = '';
                toast(translateMessage("Draft deleted"));
                await reloadSidebar();
                loadDraftWorkspace();
              },
            }, translateMessage("Delete draft")),
          ),
        ),
        ...issuesNodes,
        tabsRef.root,
      ),
    );
    if (afterACLSave) aclTab.querySelector('h3').focus({ preventScroll: true });
  }

  const importFullInput = el('input', {
    type: 'file', accept: '.json,application/json', hidden: true,
    onChange: async () => {
      const f = importFullInput.files?.[0];
      if (!f) return;
      try {
        if (f.size > 512 * 1024) throw new Error(translateMessage("The policy file exceeds 512 KiB."));
        const policy = parsePolicySource(await f.text());
        if (importFullInput.files?.[0] !== f) return;
        const created = await api('drafts', {
          method: 'POST',
          body: { name: f.name.replace(/\.json$/i, ''), policy },
        });
        selectedId = created.draft.id;
        toast(translateMessage("Imported policy.json as an unsigned draft"));
        await reloadSidebar();
        loadDraftWorkspace();
      } catch (err) {
        if (importFullInput.files?.[0] === f) toast(translateMessage("Import failed. ") + err.message);
      } finally {
        if (importFullInput.files?.[0] === f) importFullInput.value = '';
      }
    },
  });

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("ACL and policy drafts")),
        el('p', {}, translateMessage("Edit access rules and members in a draft, review the changes, and export it for the owner to sign offline.")),
      ),
      el('div', { class: 'toolbar-row' },
        importFullInput,
        el('button', { type: 'button', class: 'btn secondary btn-upload icon-start',
          onClick: () => { if (confirmDiscardACL(workspaceMount)) importFullInput.click(); } }, translateMessage("Import full policy.json")),
        el('button', {
          type: 'button', class: 'btn primary btn-plus icon-start',
          onClick: () => {
            if (!confirmDiscardACL(workspaceMount)) return;
            openDraftMetaModal({
              mode: 'create',
              onTriggerImport: () => importFullInput.click(),
              onDone: async (newId) => {
                selectedId = newId;
                await reloadSidebar();
                await loadDraftWorkspace();
              },
            });
          },
        }, translateMessage("New draft")),
      ),
    ),
    el('div', { class: 'draft-layout' },
      el('aside', { class: 'card form-stack' },
        el('h2', {}, translateMessage("Policy drafts")),
        draftSidebarMount,
      ),
      workspaceMount,
    ),
  );

  await reloadSidebar();
  await loadDraftWorkspace();
}

export async function renderPublish(container, navTo, refreshGlobal) {
  const previewMount = el('div', {});
  const uploadAlert = el('div', { id: 'auth-upload-alert', class: 'callout error icon-start', role: 'alert', hidden: true });
  const historyMount = el('div', {});
  let stagedEnvelope = null;
  let previewSeq = 0;

  const publishBtn = el('button', {
    type: 'button', class: 'btn primary btn-check icon-start', disabled: true,
    onClick: async () => {
      if (!stagedEnvelope || publishBtn.disabled) return;
      publishBtn.disabled = true;
      fileInput.disabled = true;
      try {
        const res = await api('authorization', { method: 'POST', body: stagedEnvelope });
        toast(res.idempotent ? translateMessage("This authorization is already published.") : translateMessage("Signed authorization published."));
        stagedEnvelope = null;
        publishBtn.disabled = true;
        previewMount.replaceChildren(callout('ok', translateMessage("Saved the signed authorization. Online nodes will receive it.")));
        refreshGlobal();
        loadHistory();
      } catch (err) {
        previewMount.replaceChildren(callout('error', err.message));
      } finally {
        fileInput.disabled = false;
        publishBtn.disabled = !stagedEnvelope;
      }
    },
  }, translateMessage("Verify and publish"));

  const uploadTitle = translateMessage("Select or drop signed authorization.json here");
  const uploadHint = translateMessage("The center verifies the signature, fingerprint, and expiry, rejects older snapshots, and stores the signed file as received.");
  const dzTitle = el('span', { class: 'dropzone-title' }, uploadTitle);
  const dzSub = el('span', { class: 'dropzone-sub' }, uploadHint);

  const fileInput = el('input', {
    type: 'file', id: 'auth-upload-input', accept: '.json,application/json', 'aria-describedby': 'auth-upload-alert',
    onChange: async () => {
      const seq = ++previewSeq;
      const f = fileInput.files?.[0];
      stagedEnvelope = null;
      publishBtn.disabled = true;
      previewMount.replaceChildren();
      uploadAlert.hidden = true;
      fileInput.removeAttribute('aria-invalid');
      if (!f) return;
      try {
        const env = await readPublicArtifact(f, 'authorization');
        if (seq !== previewSeq) return;
        const prev = await api('authorization/preview', { method: 'POST', body: env });
        if (seq !== previewSeq) return;
        if (!prev.valid) {
          dropzone.classList.remove('has-file');
          previewMount.replaceChildren(
            callout('error', el('strong', {}, translateMessage("Authorization check failed. ")), prev.reason || translateMessage("Unknown error")),
            ...(prev.authorization ? [renderDiffSummary(prev.diff)] : []),
          );
          return;
        }
        stagedEnvelope = env;
        publishBtn.disabled = false;
        const auth = prev.authorization;
        previewMount.replaceChildren(
          el('div', { class: 'preview-card form-stack' },
            el('div', { class: 'toolbar-row' },
              badge(translateMessage("Ed25519 signature verified"), 'ok'),
              prev.idempotent ? badge(translateMessage("Matches active authorization"), 'neutral') : null,
            ),
            el('dl', { class: 'kv-grid' },
              el('div', {}, el('dt', {}, translateMessage("Snapshot digest")), el('dd', {}, copyableCode(auth.digest, translateMessage("Copy snapshot digest"), true))),
              el('div', {}, el('dt', {}, translateMessage("Expires")), el('dd', {}, fmtTime(auth.expiresAt))),
              el('div', {}, el('dt', {}, translateMessage("Members / filter rules")), el('dd', {}, translateMessage("{0} member(s) · {1} rule(s)", auth.members, auth.rules))),
            ),
            renderDiffSummary(prev.diff),
          ),
        );
      } catch (err) {
        if (seq !== previewSeq) return;
        dropzone.classList.remove('has-file');
        fileInput.setAttribute('aria-invalid', 'true');
        uploadAlert.textContent = err.message;
        uploadAlert.hidden = false;
      }
    },
  });

  const dropzone = el('div', { class: 'dropzone' },
    fileInput,
    el('span', { class: 'dropzone-glyph icon', 'aria-hidden': 'true' }),
    el('div', { class: 'dropzone-copy' }, dzTitle, dzSub),
  );
  bindDropzone(dropzone, fileInput, dzTitle, dzSub, uploadTitle, uploadHint);

  async function inspectPublication(version) {
    const detail = await api(`authorization/history/${version}`);
    openModal(translateMessage("Signed authorization details"), el('div', { class: 'form-stack' },
      callout('', translateMessage("Use publication history to review previous authorizations.")),
      el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, translateMessage("Digest")), el('dd', {}, copyableCode(detail.digest, translateMessage("Copy historical digest"), true))),
        el('div', {}, el('dt', {}, translateMessage("Published")), el('dd', {}, fmtTime(detail.publishedAt))),
        el('div', {}, el('dt', {}, translateMessage("Expires")), el('dd', {}, fmtTime(detail.expiresAt))),
      ),
      renderRuleTable(detail.rules, translateMessage("Packet filter rules ({0})", detail.rules?.length || 0)),
    ));
  }

  async function loadHistory() {
    const list = await api('authorization/history');
    if (!list.length) {
      historyMount.replaceChildren(el('div', { class: 'empty-state' }, translateMessage("No signed publication history yet.")));
      return;
    }
    historyMount.replaceChildren(
      el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'hist-cap' },
        el('table', { class: 'tbl-history' },
          el('caption', { id: 'hist-cap' }, translateMessage("Signed authorizations ({0})", list.length)),
          el('thead', {}, el('tr', {},
            el('th', { scope: 'col' }, translateMessage("Published")),
            el('th', { scope: 'col' }, translateMessage("Snapshot digest")),
            el('th', { scope: 'col' }, translateMessage("Members / rules")),
            el('th', { scope: 'col' }, translateMessage("Expiry and status")),
            el('th', { scope: 'col' }, translateMessage("Actions")),
          )),
          el('tbody', {}, list.map((h) => el('tr', {},
            el('th', { scope: 'row' }, el('time', { datetime: h.publishedAt }, fmtTime(h.publishedAt))),
            el('td', {}, copyableCode(h.digest, translateMessage("Copy digest"), true)),
            el('td', {}, translateMessage("{0} member(s) / {1} rule(s)", h.members, h.rules)),
            el('td', {},
              el('time', { datetime: h.expiresAt }, fmtTime(h.expiresAt)), ' ',
              h.expired ? badge(translateMessage("Expired"), 'err') : h.active ? badge(translateMessage("Active"), 'ok') : badge(translateMessage("History"), 'neutral'),
            ),
            el('td', {}, el('button', {
              type: 'button', class: 'btn secondary sm',
              'aria-label': translateMessage("View snapshot published {0}", fmtTime(h.publishedAt)),
              onClick: () => inspectPublication(h.version),
            }, translateMessage("View snapshot"))),
          ))),
        ),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("Publish authorization")),
        el('p', {}, translateMessage("Upload authorization.json signed by the owner. The center verifies it and distributes it unchanged.")),
      ),
      el('button', { type: 'button', class: 'btn secondary', onClick: () => navTo('policy') }, translateMessage("Back to policy drafts")),
    ),
    el('section', { class: 'card form-stack' },
      el('h2', {}, translateMessage("Upload and verify authorization.json")),
      el('div', { class: 'field' },
        el('label', { for: 'auth-upload-input' }, translateMessage("Signed authorization.json")),
        dropzone,
      ),
      uploadAlert,
      previewMount,
      el('div', { class: 'form-actions' }, publishBtn),
    ),
    el('section', { class: 'card form-stack' },
      el('h2', {}, translateMessage("Publication history")),
      historyMount,
    ),
  );
  await loadHistory();
}
