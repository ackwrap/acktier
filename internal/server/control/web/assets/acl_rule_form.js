import { translateMessage } from './i18n.js';
import { el, openModal, closeModal } from './api.js';
import { aclAction, aclProtocol, usesBusinessPorts, splitACLTarget, formatACLTarget, validBusinessPorts } from './acl_values.js';

const internet = 'autogroup:internet';
const manual = '__acl_manual__';
const protocolChoices = [
  ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP'], ['any', translateMessage("Any protocol")], ['number', translateMessage("Custom IP protocol number")],
];

export function aclSelectorOptions(members, acl) {
  const names = new Map();
  const hosts = Object.keys(acl.hosts ?? {}).filter((key) => key.trim() === key && key && key !== '*' && key.toLowerCase() !== internet);
  const hostSet = new Set(hosts);
  const nodes = members.flatMap((m) => {
    const id = Number.isSafeInteger(m.id) && m.id > 0 ? `node:${m.id}` : '';
    const key = m.nodeKey;
    for (const selector of [id, id && `id:${m.id}`, key]) {
      if (selector && !hostSet.has(selector)) names.set(selector, m.name);
    }
    const value = id && !hostSet.has(id) ? id : key && !hostSet.has(key) ? key : '';
    return value ? [[value, `${m.name} · ${m.ipv4 || (id || translateMessage("Node public key"))}`]] : [];
  });
  const tags = [...new Set(members.flatMap((m) => m.tags ?? []))].filter((tag) => tag.startsWith('tag:') && tag.length > 4).sort();
  const options = [
    [translateMessage("Draft member"), nodes],
    [translateMessage("Member tag"), tags.filter((tag) => !hostSet.has(tag)).map((tag) => [tag, tag])],
    [translateMessage("ACL group"), Object.keys(acl.groups ?? {}).filter((g) => g.startsWith('group:') && g.length > 6 && !hostSet.has(g)).sort().map((g) => [g, g])],
    [translateMessage("Host alias"), hosts.sort().map((h) => [h, `${h} · ${acl.hosts[h]}`])],
  ];
  return { options, names };
}

function field(label, control) {
  return el('div', { class: 'field' }, el('label', { for: control.id }, label), control);
}

function invalid(control, message) {
  control.setCustomValidity(message);
  control.setAttribute('aria-invalid', 'true');
  control.reportValidity();
}

function clearValidity(control) {
  control.setCustomValidity('');
  control.removeAttribute('aria-invalid');
}

function targetPicker(id, groups, isDst, initial = '') {
  const label = isDst ? translateMessage("Destination") : translateMessage("Source");
  const choices = groups.filter(([, items]) => items.length);
  const typed = el('input', {
    type: 'text', id: `${id}-manual`, name: `${id}-manual`, spellcheck: 'false', autocapitalize: 'none',
    placeholder: isDst ? translateMessage("For example, 192.168.20.0/24 or node:2") : translateMessage("For example, 100.64.0.5 or node:2"),
    value: initial, onInput: () => clearValidity(typed),
  });
  const typedField = field(translateMessage("Enter {0} without a port", label), typed);
  // A sentinel that cannot collide with a host alias or selector takes the manual path.
  let manualValue = manual;
  while (choices.some(([, items]) => items.some(([value]) => value === manualValue))) manualValue += '_';
  const select = el('select', { id, name: id, required: true },
    el('option', { value: '', disabled: true }, translateMessage("Select {0}", label)),
    choices.map(([group, items]) => el('optgroup', { label: group }, items.map(([value, text]) => el('option', { value }, text)))),
    isDst ? el('option', { value: internet }, translateMessage("Internet via exit node · autogroup:internet")) : null,
    el('option', { value: '*' }, translateMessage("Any {0} · *", label)),
    el('option', { value: manualValue }, translateMessage("Enter an IP, subnet, or selector")),
  );
  const hasOption = initial === '*' || (isDst && initial === internet) ||
    choices.some(([, items]) => items.some(([value]) => value === initial));
  select.value = hasOption ? initial : initial ? manualValue : '';
  const sync = () => {
    const show = select.value === manualValue;
    typedField.hidden = !show;
    typed.disabled = !show;
    typed.required = show;
    clearValidity(select);
    clearValidity(typed);
  };
  select.addEventListener('change', () => {
    sync();
    if (!typed.disabled) typed.focus();
  });
  sync();
  return {
    root: el('div', { class: 'acl-picker' }, field(translateMessage("Choose {0}", label), select), typedField),
    focus: () => select.focus(),
    control: () => typed.disabled ? select : typed,
    value: () => typed.disabled ? select.value : typed.value.trim(),
  };
}

function selectorList(kind, groups, initial, currentProtocol) {
  const isDst = kind === 'dst';
  const label = isDst ? translateMessage("Destination") : translateMessage("Source");
  const rows = [];
  let serial = 0;
  const container = el('div', { class: 'acl-form-list' });
  const add = el('button', {
    type: 'button', class: 'btn secondary btn-plus icon-start', onClick: () => append().focus(),
  }, translateMessage("Add {0}", label));
  function append(raw) {
    const id = `acl-${kind}-${++serial}`;
    const parsed = isDst && raw != null ? splitACLTarget(raw) : null;
    const picker = targetPicker(`${id}-selector`, groups, isDst, parsed?.selector ?? raw?.trim() ?? '');
    const ports = isDst ? el('input', {
      id: `${id}-ports`, name: `${id}-ports`, type: 'text', required: true,
      placeholder: translateMessage("443, 8000-8010, or *"), value: parsed?.ports ?? '',
      'aria-describedby': 'acl-port-help', spellcheck: 'false',
      onInput: () => clearValidity(ports),
    }) : null;
    const remove = el('button', {
      type: 'button', class: 'btn ghost btn-trash icon-start',
      onClick: () => {
        const index = rows.indexOf(row);
        rows.splice(index, 1);
        row.root.remove();
        syncRemovals();
        if (rows[index]) rows[index].picker.focus();
        else add.focus();
      },
    }, translateMessage("Remove"));
    const row = {
      picker, ports, parsed, raw, remove,
      root: el('div', { class: `acl-form-item${isDst ? ' acl-form-destination' : ''}` },
        picker.root, ports ? field(translateMessage("Destination service port"), ports) : null, remove),
    };
    rows.push(row);
    container.append(row.root);
    syncRemovals();
    syncPorts();
    return picker;
  }
  function syncRemovals() {
    rows.forEach(({ remove }, i) => {
      remove.setAttribute('aria-label', translateMessage("Remove {1} {0}", i + 1, label));
      remove.hidden = rows.length === 1;
    });
  }
  function syncPorts() {
    if (!isDst) return;
    const enabled = usesBusinessPorts(currentProtocol());
    for (const { ports } of rows) {
      ports.disabled = !enabled;
      ports.required = enabled;
      clearValidity(ports);
    }
  }
  const existing = Array.isArray(initial) ? initial.filter((item) => typeof item === 'string') : [];
  for (const raw of existing.length ? existing : [undefined]) append(raw);
  const values = () => {
    const result = [];
    for (const { picker, ports, parsed, raw } of rows) {
      const selector = picker.value();
      if (!selector) {
        invalid(picker.control(), translateMessage("Enter a selector for {0}.", label));
        return null;
      }
      if (!isDst) {
        result.push(raw != null && selector === raw.trim() ? raw : selector);
        continue;
      }
      const portSpec = ports.disabled ? '*' : ports.value.trim();
      // Retain the owner's exact source spelling if this destination wasn't edited.
      if (!validBusinessPorts(portSpec)) {
        invalid(ports, translateMessage("Enter a port from 1 to 65535, a range such as 8000-8010, or * for all ports. Separate multiple entries with commas."));
        return null;
      }
      if (parsed && selector === parsed.selector && (ports.disabled ? validBusinessPorts(parsed.ports) : portSpec === parsed.ports)) {
        result.push(raw);
        continue;
      }
      const encoded = formatACLTarget(selector, portSpec);
      if (splitACLTarget(encoded).selector !== selector) {
        invalid(picker.control(), translateMessage("Enter the destination without a port. IPv6 addresses need no brackets."));
        return null;
      }
      result.push(encoded);
    }
    return result;
  };
  return {
    values, syncPorts,
    root: el('fieldset', { class: 'acl-form-section' },
      el('legend', {}, label),
      container,
      isDst ? el('p', { id: 'acl-port-help', class: 'field-hint' },
        translateMessage("Ports limit TCP and UDP. With Any protocol, other protocols match regardless of port. Use commas between entries and * for all ports.")) : null,
      add,
    ),
  };
}

export function openACLRuleForm(rule, position, groups, onApply) {
  const action = aclAction(rule?.action);
  const protocol = rule ? aclProtocol(rule.proto) : 'tcp';
  const isNumber = /^\d+$/.test(protocol);
  const proto = el('select', { id: 'acl-rule-proto', name: 'proto', required: true },
    el('option', { value: '', disabled: true }, rule && !protocol ? translateMessage("Unsupported: {0}", rule.proto) : translateMessage("Select a protocol")),
    protocolChoices.map(([value, label]) => el('option', { value }, label)),
  );
  proto.value = isNumber ? 'number' : protocol;
  const protoNum = el('input', {
    id: 'acl-rule-proto-number', name: 'proto-number', type: 'text', inputmode: 'numeric',
    value: isNumber ? protocol : '', placeholder: '0–255',
    onInput: () => { clearValidity(protoNum); destinations.syncPorts(); },
  });
  const numberField = field(translateMessage("IP protocol number (0–255)"), protoNum);
  const currentProtocol = () => proto.value === 'number'
    ? (/^\d+$/.test(protoNum.value.trim()) ? aclProtocol(protoNum.value.trim()) : '') : proto.value;
  const sources = selectorList('src', groups, rule?.src, currentProtocol);
  const destinations = selectorList('dst', groups, rule?.dst, currentProtocol);
  const syncProtocol = () => {
    const custom = proto.value === 'number';
    numberField.hidden = !custom;
    protoNum.disabled = !custom;
    protoNum.required = custom;
    clearValidity(protoNum);
    destinations.syncPorts();
  };
  proto.addEventListener('change', syncProtocol);
  syncProtocol();

  const form = el('form', {
    class: 'form-stack acl-rule-form', 'aria-labelledby': 'modal-title',
    onSubmit: (event) => {
      event.preventDefault();
      const selectedAction = new FormData(form).get('action');
      const selectedProto = currentProtocol();
      if (!selectedProto) return invalid(protoNum, translateMessage("Enter an IP protocol number from 0 to 255."));
      const src = sources.values();
      if (!src) return;
      const dst = destinations.values();
      if (!dst) return;
      const next = { ...rule, action: rule && selectedAction === action ? rule.action : selectedAction, src, dst };
      if (!rule || selectedProto !== protocol) next.proto = selectedProto;
      onApply(next);
      closeModal();
    },
  },
    el('fieldset', { class: 'acl-form-section' }, el('legend', {}, translateMessage("Action")),
      el('div', { class: 'acl-action-options' }, [['accept', translateMessage("Allow")], ['drop', translateMessage("Deny")]].map(([value, label]) =>
        el('label', {},
          el('input', { type: 'radio', name: 'action', value, required: true, checked: !!rule && action === value,
            autofocus: value === (rule && action ? action : 'accept') }),
          label,
        ))),
    ),
    el('div', { class: 'acl-form-protocol' }, field(translateMessage("Traffic protocol"), proto), numberField),
    sources.root,
    destinations.root,
    el('div', { class: 'form-actions' },
      el('button', { type: 'submit', class: 'btn primary' }, rule ? translateMessage("Apply changes") : translateMessage("Add to rule table")),
      el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
    ),
  );
  openModal(rule ? translateMessage("Edit ACL rule {0}", position) : translateMessage("Add ACL rule"), form, { closedBy: 'closerequest' });
}
