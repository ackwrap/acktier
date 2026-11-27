import { translateMessage } from './i18n.js';
import {
  api, el, badge, createSearchInput, makeDropzone, copyableCode, terminalSnippet, fmtTime, toast, openModal, closeModal, confirmModal, setSessionCSRF,
} from './api.js';
import { readPublicArtifact } from './artifacts.js';
import { renderAuditRow } from './views_audit.js';

const keyStateMeta = {
  active: [translateMessage("Available"), 'ok'],
  used: [translateMessage("Used"), 'neutral'],
  expired: [translateMessage("Expired"), 'warn'],
  revoked: [translateMessage("Revoked"), 'err'],
};

const ttlPresets = [
  [1, translateMessage("1 hour")],
  [24, translateMessage("24 hours")],
  [168, translateMessage("7 days")],
  [720, translateMessage("30 days")],
];

export async function renderSecurity(container, refreshGlobal) {
  const newKeyBanner = el('div', { hidden: true });
  const keysMount = el('div', {});
  const delegMount = el('div', { class: 'form-stack' });
  const auditMount = el('div', {});
  const auditPager = el('div', { class: 'toolbar-row between' });
  let auditState = { q: '', page: 1, size: 15 };

  function openCreateKeyModal() {
    const labelIn = el('input', { type: 'text', id: 'new-key-label', maxlength: 64, required: true, placeholder: translateMessage("For example, office NAS enrollment"), autofocus: true });
    const ttlIn = el('input', { type: 'number', id: 'new-key-ttl', min: 1, max: 720, value: 24, required: true });
    const reuseCheck = el('input', { type: 'checkbox', id: 'new-key-reuse' });
    const errBox = el('div', { class: 'callout error icon-start', hidden: true });

    const presetBtns = ttlPresets.map(([hours, text]) => el('button', {
      type: 'button',
      class: 'preset-chip',
      'aria-pressed': hours === 24 ? 'true' : 'false',
      onClick: () => {
        ttlIn.value = String(hours);
        syncPresetHighlight();
      },
    }, text));
    const syncPresetHighlight = () => {
      const val = Number(ttlIn.value);
      presetBtns.forEach((btn, i) => btn.setAttribute('aria-pressed', ttlPresets[i][0] === val ? 'true' : 'false'));
    };
    ttlIn.addEventListener('input', syncPresetHighlight);

    const form = el('form', {
      class: 'form-stack',
      onSubmit: async (e) => {
        e.preventDefault();
        errBox.hidden = true;
        try {
          const created = await api('keys', {
            method: 'POST',
            body: {
              label: labelIn.value.trim(),
              ttlHours: Number(ttlIn.value || 24),
              reusable: reuseCheck.checked,
            },
          });
          closeModal();
          const joinCmd = translateMessage("acktier up --server <CENTER_NODE_URL> --auth-key \"{0}\"", created.key);
          newKeyBanner.hidden = false;
          newKeyBanner.className = 'preview-card form-stack';
          newKeyBanner.replaceChildren(
            el('div', { class: 'toolbar-row between' },
              badge(translateMessage("Enrollment key created"), 'ok'),
              el('span', { class: 'muted' }, translateMessage("Copy the key now. After leaving or refreshing, only its digest remains.")),
            ),
            el('div', { class: 'field' },
              el('label', {}, translateMessage("Enrollment key")),
              copyableCode(created.key, translateMessage("Copy new enrollment key")),
            ),
            el('div', { class: 'field' },
              el('label', {}, translateMessage("Node join command. Replace <CENTER_NODE_URL> with the center's node listener URL.")),
              terminalSnippet(joinCmd, translateMessage("Copy node join command")),
            ),
          );
          toast(translateMessage("Enrollment key created"));
          loadKeys();
          loadAudit();
          refreshGlobal();
        } catch (err) {
          errBox.textContent = err.message;
          errBox.hidden = false;
        }
      },
    },
      errBox,
      el('div', { class: 'field' }, el('label', { for: 'new-key-label' }, translateMessage("Note (required)")), labelIn),
      el('div', { class: 'field' },
        el('label', { for: 'new-key-ttl' }, translateMessage("Validity in hours (1–720)")),
        ttlIn,
        el('div', { class: 'preset-row' }, ...presetBtns),
        el('p', { class: 'field-hint' }, translateMessage("An enrollment key permits a join request. A signed authorization grants access to the data plane.")),
      ),
      el('label', { class: 'checkbox-row', for: 'new-key-reuse' },
        reuseCheck,
        el('span', {}, translateMessage("Allow reuse until expiry. Leave unchecked for a single-use key.")),
      ),
      el('div', { class: 'form-actions' },
        el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, translateMessage("Cancel")),
        el('button', { type: 'submit', class: 'btn primary btn-key icon-start' }, translateMessage("Generate key")),
      ),
    );
    openModal(translateMessage("Create enrollment key"), form);
  }

  async function loadKeys() {
    const keys = await api('keys');
    if (!keys.length) {
      keysMount.replaceChildren(el('div', { class: 'empty-state' }, translateMessage("No enrollment keys yet. Create a time-limited key to start.")));
      return;
    }
    keysMount.replaceChildren(
      el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'keys-cap' },
        el('table', { class: 'tbl-keys' },
          el('caption', { id: 'keys-cap' }, translateMessage("Enrollment keys ({0}). Plaintext is shown only at creation.", keys.length)),
          el('thead', {}, el('tr', {},
            el('th', { scope: 'col' }, translateMessage("Note and ID")),
            el('th', { scope: 'col' }, translateMessage("Status")),
            el('th', { scope: 'col' }, translateMessage("Type and uses")),
            el('th', { scope: 'col' }, translateMessage("Expires")),
            el('th', { scope: 'col' }, translateMessage("Actions")),
          )),
          el('tbody', {}, keys.map((k) => {
            const [stText, stKind] = keyStateMeta[k.state] || [k.state, 'neutral'];
            return el('tr', {},
              el('th', { scope: 'row' },
                el('div', {}, k.label || translateMessage("Not provided")),
                el('code', { class: 'muted' }, k.id),
              ),
              el('td', {}, badge(stText, stKind)),
              el('td', {}, el('span', { class: 'chip' }, k.reusable ? translateMessage("Reusable") : translateMessage("Single use")), translateMessage(" · {0} use(s)", k.usedCount)),
              el('td', {}, fmtTime(k.expiresAt)),
              el('td', {}, k.state === 'active'
                ? el('button', {
                  type: 'button', class: 'btn danger sm btn-trash icon-start',
                  onClick: async () => {
                    const ok = await confirmModal({
                      title: translateMessage("Revoke enrollment key"),
                      message: translateMessage("Revoke enrollment key {0} now?", k.label || k.id),
                      detail: translateMessage("This key can no longer submit requests. Signed memberships stay active."),
                      confirmText: translateMessage("Confirm revocation"),
                    });
                    if (!ok) return;
                    await api(`keys/${encodeURIComponent(k.id)}/revoke`, { method: 'POST' });
                    toast(translateMessage("Enrollment key revoked"));
                    loadKeys();
                    loadAudit();
                    refreshGlobal();
                  },
                }, translateMessage("Revoke"))
                : '—'),
            );
          })),
        ),
      ),
    );
  }

  async function loadDelegation() {
    const d = await api('delegation');
    const fileIn = el('input', {
      type: 'file', id: 'controller-trust-file', accept: '.json,application/json',
      onChange: async () => {
        const f = fileIn.files?.[0];
        if (!f) return;
        fileIn.removeAttribute('aria-invalid');
        try {
          const ct = await readPublicArtifact(f, 'controller');
          if (fileIn.files?.[0] !== f) return;
          fileIn.disabled = true;
          await api('delegation', { method: 'PUT', body: ct });
          toast(translateMessage("Controller API delegation enabled"));
          loadDelegation();
          loadAudit();
        } catch (err) {
          if (fileIn.files?.[0] === f) {
            fileIn.setAttribute('aria-invalid', 'true');
            toast(err.message);
          }
        } finally {
          if (fileIn.files?.[0] === f) {
            fileIn.value = '';
            fileIn.disabled = false;
          }
        }
      },
    });

    delegMount.replaceChildren(
      el('div', { class: 'toolbar-row between' },
        el('div', { class: 'toolbar-row' },
          el('h2', {}, translateMessage("Controller API delegation")),
          d.enabled ? badge(translateMessage("Delegated"), 'ok') : badge(translateMessage("Disabled"), 'neutral'),
        ),
        d.enabled
          ? el('button', {
            type: 'button', class: 'btn danger sm btn-trash icon-start',
            onClick: async () => {
              const ok = await confirmModal({
                title: translateMessage("Revoke controller delegation"),
                message: translateMessage("Revoke controller API delegation now?"),
                detail: translateMessage("The current controller credential expires immediately. Published policies and node connections stay active."),
                confirmText: translateMessage("Confirm delegation revocation"),
              });
              if (!ok) return;
              await api('delegation', { method: 'DELETE' });
              toast(translateMessage("Delegation revoked. The previous API credential is invalid."));
              loadDelegation();
              loadAudit();
            },
          }, translateMessage("Revoke delegation"))
          : null,
      ),
      el('p', { class: 'muted' },
        translateMessage("The management listener requires an Ed25519 challenge signature for each request. On the controller, run "),
        el('code', {}, 'acktier owner controller-init --dir ./data/owner'),
        translateMessage(" to export the public "),
        el('code', {}, 'controller-trust.json'),
        translateMessage(". This credential is separate from the policy signing key."),
      ),
      d.enabled
        ? el('dl', { class: 'kv-grid' },
          el('div', {}, el('dt', {}, translateMessage("Pinned controller management public key")), el('dd', {}, copyableCode(d.publicKey, translateMessage("Copy controller management public key"), true))),
          el('div', {}, el('dt', {}, translateMessage("Delegation note")), el('dd', {}, d.label || '—')),
          el('div', {}, el('dt', {}, translateMessage("Updated")), el('dd', {}, fmtTime(d.updatedAt))),
        )
        : null,
      el('div', { class: 'field' },
        el('label', { for: 'controller-trust-file' }, d.enabled ? translateMessage("Rotate the controller key with controller-trust.json") : translateMessage("Upload controller-trust.json to enable delegation")),
        makeDropzone(fileIn, translateMessage("Select or drop controller-trust.json"), translateMessage("The browser validates the public delegation file and rejects private keys locally.")),
      ),
    );
  }

  // Password Change Card
  const curPw = el('input', { type: 'password', id: 'pw-current', autocomplete: 'current-password', required: true, placeholder: translateMessage("Enter current password") });
  const nextPw = el('input', { type: 'password', id: 'pw-next', autocomplete: 'new-password', minlength: 12, maxlength: 256, required: true, placeholder: translateMessage("At least 12 characters") });
  const pwMsg = el('div', { hidden: true });
  const pwForm = el('form', {
    class: 'form-stack',
    onSubmit: async (e) => {
      e.preventDefault();
      pwMsg.hidden = true;
      try {
        const session = await api('password', {
          method: 'POST',
          body: { current: curPw.value, next: nextPw.value },
        });
        setSessionCSRF(session.csrf);
        curPw.value = '';
        nextPw.value = '';
        pwMsg.className = 'callout ok icon-start';
        pwMsg.textContent = translateMessage("Administrator password updated and stored as an Argon2id hash. Other sessions were revoked.");
        pwMsg.hidden = false;
        loadAudit();
      } catch (err) {
        pwMsg.className = 'callout error icon-start';
        pwMsg.textContent = err.message;
        pwMsg.hidden = false;
      }
    },
  },
    pwMsg,
    el('div', { class: 'form-row' },
      el('div', { class: 'field' }, el('label', { for: 'pw-current' }, translateMessage("Current administrator password")), curPw),
      el('div', { class: 'field' }, el('label', { for: 'pw-next' }, translateMessage("New password (12–256 characters)")), nextPw),
    ),
    el('div', { class: 'form-actions' },
      el('button', { type: 'submit', class: 'btn secondary btn-check icon-start' }, translateMessage("Update password and revoke other sessions")),
    ),
  );

  async function loadAudit() {
    const res = await api(`audit?q=${encodeURIComponent(auditState.q)}&page=${auditState.page}&size=${auditState.size}`);
    const items = res.items || [];
    auditMount.replaceChildren(
      items.length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'audit-cap' },
          el('table', { class: 'tbl-audit' },
            el('caption', { id: 'audit-cap' }, translateMessage("Security audit events ({0})", res.total)),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, translateMessage("Time")),
              el('th', { scope: 'col' }, translateMessage("Actor")),
              el('th', { scope: 'col' }, translateMessage("Action")),
              el('th', { scope: 'col' }, translateMessage("Destination")),
              el('th', { scope: 'col' }, translateMessage("Result and details")),
            )),
            el('tbody', {}, items.map(renderAuditRow)),
          ),
        )
        : el('div', { class: 'empty-state' }, translateMessage("No matching audit events.")),
    );
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / auditState.size));
    auditPager.replaceChildren(
      el('span', { class: 'muted' }, translateMessage("{0} total · Page {1} of {2}", res.total, res.page, maxPage)),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: auditState.page <= 1, onClick: () => { auditState.page--; loadAudit(); } }, translateMessage("Previous")),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: auditState.page >= maxPage, onClick: () => { auditState.page++; loadAudit(); } }, translateMessage("Next")),
      ),
    );
  }

  const auditSearchWidget = createSearchInput({
    placeholder: translateMessage("Filter by action, actor, or details…"),
    ariaLabel: translateMessage("Filter audit events"),
    onSearch: (q) => { auditState.q = q; auditState.page = 1; loadAudit(); },
  });

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, translateMessage("Enrollment keys, delegation, and audit")),
        el('p', {}, translateMessage("Manage enrollment keys, challenge-signed controller access, the Web administrator password, and audit events.")),
      ),
      el('button', { type: 'button', class: 'btn primary btn-key icon-start', onClick: openCreateKeyModal }, translateMessage("Generate enrollment key")),
    ),
    newKeyBanner,
    el('section', { class: 'card form-stack' },
      el('h2', {}, translateMessage("Enrollment key inventory")),
      keysMount,
    ),
    el('div', { class: 'split-grid' },
      el('section', { class: 'card form-stack' }, delegMount),
      el('section', { class: 'card form-stack' },
        el('h2', {}, translateMessage("Change Web administrator password")),
        el('p', { class: 'muted' }, translateMessage("The Web password is separate from controller credentials and node tokens. The center stores a salted Argon2id hash.")),
        pwForm,
      ),
    ),
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, translateMessage("Security audit")),
        auditSearchWidget,
      ),
      auditMount,
      auditPager,
    ),
  );

  await Promise.all([loadKeys(), loadDelegation(), loadAudit()]);
}
