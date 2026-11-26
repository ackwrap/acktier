import { api, badge, el, makeDropzone, toast } from './api.js';
import { aclSelectorOptions, openACLRuleForm } from './acl_rule_form.js';
import { aclAction, aclProtocol, splitACLTarget, usesBusinessPorts } from './acl_values.js';
import { parseACLSource } from './artifacts.js';

const maxACLBytes = 256 * 1024;

export function confirmDiscardACL(scope) {
  const has = (selector) => scope.matches(selector) || scope.querySelector(selector);
  if (has('[data-acl-saving]')) {
    toast('正在保存 ACL 草稿，请稍候。');
    return false;
  }
  return !has('[data-acl-dirty]') || window.confirm('当前 ACL 有未保存的改动，要放弃这些改动吗？');
}

function selectorLabel(value, names) {
  const selector = value.trim();
  if (selector === '*') return el('span', {}, '任意');
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
  const table = el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': 'ACL 草稿规则表' },
    el('table', { class: 'acl-rule-table' },
      el('thead', {}, el('tr', {}, ['规则', '来源', '目标 / 端口', '协议', '操作']
        .map((label) => el('th', { scope: 'col' }, label)))),
      tbody,
    ));
  const empty = el('div', { class: 'empty-state' },
    el('strong', {}, '还没有 ACL 规则'),
    el('p', {}, '空 ACL 默认拒绝成员间的业务流量。点击「添加规则」开始。'));
  const add = el('button', {
    type: 'button', class: 'btn primary btn-plus icon-start', onClick: () => editRow(),
  }, '添加规则');
  const save = el('button', {
    type: 'button', class: 'btn secondary btn-check icon-start', onClick: saveACL,
    'aria-describedby': 'acl-editor-error',
  }, '校验并保存草稿');
  const discard = el('button', {
    type: 'button', class: 'btn ghost', onClick: () => {
      if (!confirmDiscardACL(root)) return;
      error.hidden = true;
      file.value = '';
      file.dispatchEvent(new Event('change'));
      replaceACL(saved);
      add.focus();
    },
  }, '放弃改动');
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
      replaceACL(acl, 'JSON 已载入规则表');
      (save.disabled ? add : save).focus();
    } catch (err) {
      showError(err.message);
    }
  } }, '载入规则表');
  const resetJSON = el('button', { type: 'button', class: 'btn ghost', onClick: () => {
    error.hidden = true;
    json.value = appliedText;
    updateState();
    json.focus();
  } }, '还原为规则表');
  const root = el('div', { class: 'form-stack acl-editor' },
    el('div', { class: 'toolbar-row between acl-editor-head' },
      el('div', {}, el('h3', { tabindex: '-1' }, '访问规则', count),
        el('p', { class: 'field-hint' }, '从上到下匹配，首条命中即停止；未匹配的流量默认拒绝。')),
      add,
    ),
    table, empty,
    el('div', { class: 'acl-savebar' },
      el('div', {}, status, el('p', { class: 'field-hint' }, '只修改草稿；需所有者离线签发，再发布才生效。')),
      el('div', { class: 'form-actions' }, discard, save),
    ),
    error,
    el('details', { class: 'acl-details' },
      el('summary', {}, '高级：导入或编辑 ACL JSON'),
      el('div', { class: 'form-stack acl-details-body' },
        el('p', { class: 'field-hint' }, '可在这里维护组与主机别名。导入会替换下方 JSON；载入规则表后再保存，不会修改成员、DNS、STUN 或路由。'),
        el('div', { class: 'field' }, el('label', { for: file.id }, '导入 ACL JSON 文件（可选）'),
          makeDropzone(file, '选择或拖入 ACL JSON', '文件先在本地读取，最多 256 KiB。')),
        el('div', { class: 'field' }, el('label', { for: json.id }, 'ACL JSON'),
          el('div', { class: 'editor-frame' },
            el('div', { class: 'editor-bar' }, el('span', { class: 'mono' }, 'acl.json'), el('span', {}, 'Groups · Hosts · Rules')),
            json,
          )),
        el('div', { class: 'form-actions' }, loadJSON, resetJSON),
      ),
    ),
    el('details', { class: 'acl-details' }, el('summary', {}, '查看已保存草稿的编译预览'),
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
      count.textContent = `${rows.length} 条`;
      rows.forEach((r, i) => {
        r.order.textContent = String(i + 1);
        for (const [button, label, unavailable] of [
          [r.edit, '编辑', false], [r.up, '上移', i === 0], [r.down, '下移', i === rows.length - 1], [r.remove, '删除', false],
        ]) {
          button.setAttribute('aria-label', `${label}第 ${i + 1} 条规则`);
          lock(button, unavailable || !editable);
        }
      });
    }
    empty.hidden = rows.length > 0;
    table.hidden = rows.length === 0;
    const state = saving ? '正在校验并保存…' : reading ? '正在读取 ACL 文件…' :
      jsonDirty ? 'JSON 有未载入的改动。请先载入规则表或还原。' : changed ? '有未保存的改动' : '没有待保存的改动';
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
    row.action.replaceChildren(action ? badge(action === 'accept' ? '放行' : '拒绝', action === 'accept' ? 'ok' : 'err') : badge('动作无效', 'err'));
    row.sources.replaceChildren(el('div', { class: 'acl-selector-list' },
      Array.isArray(src) && src.length ? src.map((s) => typeof s === 'string' ? selectorLabel(s, selectors.names) : '无效来源') : '未设置'));
    row.targets.replaceChildren(el('div', { class: 'acl-selector-list' },
      Array.isArray(dst) && dst.length ? dst.map((raw) => {
        if (typeof raw !== 'string') return el('span', {}, '无效目标');
        const { selector, ports } = splitACLTarget(raw);
        const portLabel = !usesBusinessPorts(proto) && proto ? '不匹配端口' :
          ports === '*' ? '全部端口' : ['any', '0'].includes(proto) ? `${ports}（仅 TCP/UDP）` : ports;
        return el('div', { class: 'acl-target-label' }, selectorLabel(selector, selectors.names), el('span', { class: 'acl-port-label' }, portLabel));
      }) : '未设置'));
    row.protocol.replaceChildren(proto
      ? el('code', { class: 'chip' }, number ? `IP ${proto}` : proto === 'any' ? '任意' : proto.toUpperCase())
      : badge(`不支持：${rawProto}`, 'err'));
  }

  function makeRow(rule) {
    const row = { rule, order: el('span', { class: 'acl-order mono' }), action: el('span', {}),
      sources: el('td'), targets: el('td'), protocol: el('td') };
    const button = (text, onClick, label = text, move = false) => el('button', {
      type: 'button', class: `btn ghost sm${move ? ' acl-move-rule' : ''}`, title: label, onClick,
    }, text);
    row.edit = button('编辑', () => editRow(row));
    row.up = button('↑', () => moveRow(row, -1), '上移', true);
    row.down = button('↓', () => moveRow(row, 1), '下移', true);
    row.remove = button('删除', () => {
      if (!canEdit()) return;
      const i = rows.indexOf(row);
      rows.splice(i, 1);
      row.node.remove();
      rulesChanged(`已删除第 ${i + 1} 条规则`);
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
      rulesChanged(row ? '已应用规则修改' : '已添加规则');
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
    rulesChanged(`规则已移到第 ${to + 1} 位`);
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
      if (selected.size > maxACLBytes) throw new Error('ACL 文件过大（最多 256 KiB）。');
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
      if (size > maxACLBytes) throw new Error('ACL 超过 256 KiB，请缩小后再保存。');
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
