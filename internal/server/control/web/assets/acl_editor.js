import { translateMessage } from './i18n.js';
import { api, badge, el, makeDropzone, toast } from './api.js';
import { aclSelectorOptions, openACLRuleForm } from './acl_rule_form.js';
import { aclAction, aclProtocol, splitACLTarget, usesBusinessPorts } from './acl_values.js';
import { parseACLSource } from './artifacts.js';

const maxACLBytes = 256 * 1024;

export function confirmDiscardACL(scope) {
  const has = (selector) => scope.matches(selector) || scope.querySelector(selector);
  if (has('[data-acl-saving]')) {
    toast(translateMessage("Saving the ACL draft. Please wait."));
    return false;
  }
  return !has('[data-acl-dirty]') || window.confirm(translateMessage("The ACL has unsaved changes. Discard them?"));
}

function selectorLabel(value, names) {
  const selector = value.trim();
  if (selector === '*') return el('span', {}, translateMessage("Any"));
  const name = names.get(selector);
  return el('span', { class: 'acl-selector-label' }, name, el('code', { class: 'chip' }, selector));
}

export function renderACLEditor(draft, compiledPreview, onSaved, onPendingChange) {
  const saved = { ...draft.policy.acl, acls: draft.policy.acl?.acls ?? [] };
  const savedText = JSON.stringify(saved, null, 2);
  let working, rows, selectors, appliedText;
  let saving = false;
  let reading = false;
  let fileSeq = 0;
  let rowsEditable;

  const status = el('span', { role: 'status', class: 'acl-status' });
  const error = el('div', { id: 'acl-editor-error', class: 'callout error', role: 'alert', tabindex: '-1', hidden: true });
  const count = el('span', { class: 'acl-rule-count' });
  const tbody = el('tbody');
  const table = el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': translateMessage("ACL draft rules") },
    el('table', { class: 'acl-rule-table' },
      el('thead', {}, el('tr', {}, [translateMessage("Rule"), translateMessage("Source"), translateMessage("Destination / port"), translateMessage("Protocol"), translateMessage("Actions")]
        .map((label) => el('th', { scope: 'col' }, label)))),
      tbody,
    ));
  const empty = el('div', { class: 'empty-state' },
    el('strong', {}, translateMessage("No ACL rules yet")),
    el('p', {}, translateMessage("An empty ACL denies traffic between members by default. Select Add rule to begin.")));
  const add = el('button', {
    type: 'button', class: 'btn primary btn-plus icon-start', onClick: () => editRow(),
  }, translateMessage("Add rule"));
  const save = el('button', {
    type: 'button', class: 'btn secondary btn-check icon-start', onClick: saveACL,
    'aria-describedby': 'acl-editor-error',
  }, translateMessage("Validate and save draft"));
  const discard = el('button', {
    type: 'button', class: 'btn ghost', onClick: () => {
      if (!confirmDiscardACL(root)) return;
      error.hidden = true;
      file.value = '';
      file.dispatchEvent(new Event('change'));
      replaceACL(saved);
      add.focus();
    },
  }, translateMessage("Discard changes"));
  const json = el('textarea', {
    id: 'acl-source-editor', class: 'code-editor', spellcheck: 'false',
    'aria-describedby': 'acl-editor-error',
    onInput: () => { error.hidden = true; updateState(); },
  });
  const file = el('input', {
    type: 'file', id: 'draft-acl-file', accept: '.json,application/json',
    'aria-describedby': 'acl-editor-error', onChange: readFile,
  });
  const loadJSON = el('button', { type: 'button', class: 'btn secondary', onClick: () => {
    try {
      const acl = parseACLSource(json.value);
      replaceACL(acl, translateMessage("JSON loaded into the rule table"));
      (save.disabled ? add : save).focus();
    } catch (err) {
      showError(err.message);
    }
  } }, translateMessage("Load rule table"));
  const resetJSON = el('button', { type: 'button', class: 'btn ghost', onClick: () => {
    error.hidden = true;
    json.value = appliedText;
    updateState();
    json.focus();
  } }, translateMessage("Restore from rule table"));
  const root = el('div', { class: 'form-stack acl-editor' },
    el('div', { class: 'toolbar-row between acl-editor-head' },
      el('div', {}, el('h3', { tabindex: '-1' }, translateMessage("Access rules"), count),
        el('p', { class: 'field-hint' }, translateMessage("Rules match from top to bottom. The first match applies. Unmatched traffic is denied."))),
      add,
    ),
    table, empty,
    el('div', { class: 'acl-savebar' },
      el('div', {}, status, el('p', { class: 'field-hint' }, translateMessage("Edits affect the draft. The owner must sign and publish it to apply the rules."))),
      el('div', { class: 'form-actions' }, discard, save),
    ),
    error,
    el('details', { class: 'acl-details' },
      el('summary', {}, translateMessage("Advanced ACL JSON")),
      el('div', { class: 'form-stack acl-details-body' },
        el('p', { class: 'field-hint' }, translateMessage("Use JSON to maintain groups and host aliases. Importing replaces the JSON below. Load the rule table before saving. Member, DNS, STUN, and route settings are preserved.")),
        el('div', { class: 'field' }, el('label', { for: file.id }, translateMessage("Import ACL JSON (optional)")),
          makeDropzone(file, translateMessage("Select or drop ACL JSON"), translateMessage("The browser reads files up to 256 KiB locally."))),
        el('div', { class: 'field' }, el('label', { for: json.id }, 'ACL JSON'),
          el('div', { class: 'editor-frame' },
            el('div', { class: 'editor-bar' }, el('span', { class: 'mono' }, 'acl.json'), el('span', {}, 'Groups · Hosts · Rules')),
            json,
          )),
        el('div', { class: 'form-actions' }, loadJSON, resetJSON),
      ),
    ),
    el('details', { class: 'acl-details' }, el('summary', {}, translateMessage("Preview the compiled saved draft")),
      el('div', { class: 'acl-details-body' }, compiledPreview)),
  );

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
    error.focus();
  }

  const unappliedJSON = () => json.value !== appliedText;
  const canEdit = () => !saving && !reading && !unappliedJSON();
  const lock = (button, locked) => button.setAttribute('aria-disabled', String(locked));

  function updateState(note = '', rowsChanged = false) {
    const jsonDirty = unappliedJSON();
    const changed = appliedText !== savedText;
    const editable = canEdit();
    root.toggleAttribute('data-acl-dirty', changed || jsonDirty);
    root.toggleAttribute('data-acl-saving', saving);
    lock(add, !editable);
    save.disabled = !editable || !changed;
    save.classList.toggle('primary', !save.disabled);
    discard.hidden = !changed && !jsonDirty;
    discard.disabled = saving || reading;
    file.disabled = saving;
    json.readOnly = saving || reading;
    loadJSON.disabled = resetJSON.disabled = saving || reading || !jsonDirty;
    if (rowsChanged || editable !== rowsEditable) {
      rowsEditable = editable;
      count.textContent = translateMessage("{0} rule(s)", rows.length);
      rows.forEach((r, i) => {
        r.order.textContent = String(i + 1);
        for (const [button, label, unavailable] of [
          [r.edit, translateMessage("Edit"), false], [r.up, translateMessage("Move up"), i === 0], [r.down, translateMessage("Move down"), i === rows.length - 1], [r.remove, translateMessage("Delete"), false],
        ]) {
          button.setAttribute('aria-label', translateMessage("{0} rule {1}", label, i + 1));
          lock(button, unavailable || !editable);
        }
      });
    }
    empty.hidden = rows.length > 0;
    table.hidden = rows.length === 0;
    const state = saving ? translateMessage("Validating and saving…") : reading ? translateMessage("Reading ACL file…") :
      jsonDirty ? translateMessage("The JSON has unapplied changes. Load the rule table or restore the previous JSON first.") : changed ? translateMessage("Unsaved changes") : translateMessage("No changes to save");
    const text = note ? `${note} · ${state}` : state;
    if (status.textContent !== text) status.textContent = text;
    onPendingChange(changed || jsonDirty || saving);
  }

  function replaceACL(acl, note) {
    error.hidden = true;
    working = acl;
    selectors = aclSelectorOptions(draft.policy.members ?? [], working);
    rows = working.acls.map(makeRow);
    const fragment = document.createDocumentFragment();
    for (const row of rows) fragment.append(row.node);
    tbody.replaceChildren(fragment);
    syncJSON(note);
  }

  function syncJSON(note) {
    appliedText = JSON.stringify(working, null, 2);
    json.value = appliedText;
    updateState(note, true);
  }

  function rulesChanged(note) {
    error.hidden = true;
    working = { ...working, acls: rows.map((r) => r.rule) };
    syncJSON(note);
  }

  function fillCells(row) {
    const { action: rawAction, proto: rawProto, src, dst } = row.rule ?? {};
    const action = aclAction(rawAction);
    const proto = aclProtocol(rawProto);
    const number = /^\d+$/.test(proto);
    row.action.replaceChildren(action ? badge(action === 'accept' ? translateMessage("Allow") : translateMessage("Deny"), action === 'accept' ? 'ok' : 'err') : badge(translateMessage("Invalid action"), 'err'));
    row.sources.replaceChildren(el('div', { class: 'acl-selector-list' },
      Array.isArray(src) && src.length ? src.map((s) => typeof s === 'string' ? selectorLabel(s, selectors.names) : translateMessage("Invalid source")) : translateMessage("Unset")));
    row.targets.replaceChildren(el('div', { class: 'acl-selector-list' },
      Array.isArray(dst) && dst.length ? dst.map((raw) => {
        if (typeof raw !== 'string') return el('span', {}, translateMessage("Invalid destination"));
        const { selector, ports } = splitACLTarget(raw);
        const portLabel = !usesBusinessPorts(proto) && proto ? translateMessage("No port match") :
          ports === '*' ? translateMessage("All ports") : ['any', '0'].includes(proto) ? translateMessage("{0} (TCP/UDP only)", ports) : ports;
        return el('div', { class: 'acl-target-label' }, selectorLabel(selector, selectors.names), el('span', { class: 'acl-port-label' }, portLabel));
      }) : translateMessage("Unset")));
    row.protocol.replaceChildren(proto
      ? el('code', { class: 'chip' }, number ? `IP ${proto}` : proto === 'any' ? translateMessage("Any") : proto.toUpperCase())
      : badge(translateMessage("Unsupported: {0}", rawProto), 'err'));
  }

  function makeRow(rule) {
    const row = { rule, order: el('span', { class: 'acl-order mono' }), action: el('span', {}),
      sources: el('td'), targets: el('td'), protocol: el('td') };
    const button = (text, onClick, label = text, move = false) => el('button', {
      type: 'button', class: `btn ghost sm${move ? ' acl-move-rule' : ''}`, title: label, onClick,
    }, text);
    row.edit = button(translateMessage("Edit"), () => editRow(row));
    row.up = button('↑', () => moveRow(row, -1), translateMessage("Move up"), true);
    row.down = button('↓', () => moveRow(row, 1), translateMessage("Move down"), true);
    row.remove = button(translateMessage("Delete"), () => {
      if (!canEdit()) return;
      const i = rows.indexOf(row);
      rows.splice(i, 1);
      row.node.remove();
      rulesChanged(translateMessage("Deleted rule {0}", i + 1));
      (rows[i]?.edit ?? rows.at(-1)?.edit ?? add).focus();
    });
    row.node = el('tr', {}, el('th', { scope: 'row' }, el('div', { class: 'acl-rule-heading' }, row.order, row.action)),
      row.sources, row.targets, row.protocol,
      el('td', {}, el('div', { class: 'acl-row-actions' }, row.edit, row.up, row.down, row.remove)));
    fillCells(row);
    return row;
  }

  function editRow(row) {
    if (!canEdit()) return;
    openACLRuleForm(row ? row.rule ?? {} : null, rows.indexOf(row) + 1, selectors.options, (rule) => {
      if (!root.isConnected) return;
      if (row) {
        row.rule = rule;
        fillCells(row);
      } else {
        const added = makeRow(rule);
        rows.push(added);
        tbody.append(added.node);
      }
      rulesChanged(row ? translateMessage("Rule changes applied") : translateMessage("Rule added"));
    });
  }

  function moveRow(row, delta) {
    if (!canEdit()) return;
    const from = rows.indexOf(row);
    const to = from + delta;
    if (to < 0 || to >= rows.length) return;
    rows.splice(from, 1);
    rows.splice(to, 0, row);
    const before = rows[to + 1]?.node ?? null;
    if (tbody.moveBefore) {
      tbody.moveBefore(row.node, before);
    } else {
      const focused = document.activeElement;
      tbody.insertBefore(row.node, before);
      if (row.node.contains(focused)) focused.focus({ preventScroll: true });
    }
    rulesChanged(translateMessage("Rule moved to position {0}", to + 1));
  }

  async function readFile() {
    const seq = ++fileSeq;
    const selected = file.files?.[0];
    error.hidden = true;
    file.removeAttribute('aria-invalid');
    reading = Boolean(selected);
    updateState();
    if (!selected) return;
    try {
      if (selected.size > maxACLBytes) throw new Error(translateMessage("The ACL file exceeds 256 KiB."));
      const text = await selected.text();
      if (seq !== fileSeq || !root.isConnected) return;
      parseACLSource(text);
      json.value = text;
    } catch (err) {
      if (seq !== fileSeq || !root.isConnected) return;
      file.setAttribute('aria-invalid', 'true');
      showError(err.message);
    } finally {
      if (seq === fileSeq && root.isConnected) {
        reading = false;
        updateState();
      }
    }
  }

  async function saveACL() {
    if (!canEdit() || appliedText === savedText) return;
    error.hidden = true;
    saving = true;
    updateState();
    let result;
    try {
      const size = new TextEncoder().encode(JSON.stringify(working)).length;
      if (size > maxACLBytes) throw new Error(translateMessage("Reduce the ACL to 256 KiB or less before saving."));
      result = await api(`drafts/${encodeURIComponent(draft.id)}/acl`, { method: 'POST', body: working });
    } catch (err) {
      saving = false;
      updateState();
      showError(err.message);
      return;
    }
    onSaved(result);
  }

  replaceACL(saved);
  return root;
}
