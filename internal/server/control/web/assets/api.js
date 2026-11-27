import { language, translateMessage } from './i18n.js';
import { translateCenterMessage } from './center_messages.js';
// Shared API client, CSRF state, safe DOM builders, dropzone, copy command, dialog, and theme helpers.

let csrfToken = '';
let onUnauthenticated = null;

export function setSessionCSRF(token) {
  csrfToken = token || '';
}

export function onSessionExpired(fn) {
  onUnauthenticated = fn;
}

export async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const reqHeaders = { ...headers };
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) {
    reqHeaders['X-CSRF-Token'] = csrfToken;
  }
  let payload;
  if (body !== undefined) {
    reqHeaders['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const resp = await fetch('/admin/api/' + path.replace(/^\/+/, ''), {
    method,
    headers: reqHeaders,
    body: payload,
    credentials: 'same-origin',
  });
  const isJSON = (resp.headers.get('content-type') || '').includes('application/json');
  const data = isJSON ? await resp.json().catch(() => null) : await resp.text();
  if (!resp.ok) {
    if (resp.status === 401 && path !== 'login' && onUnauthenticated) {
      onUnauthenticated();
    }
    const msg = data?.error?.message || (typeof data === 'string' && data) || translateMessage("Request failed (HTTP {0})", resp.status);
    const err = new Error(translateCenterMessage(msg));
    err.status = resp.status;
    err.code = data?.error?.code || '';
    throw err;
  }
  return data;
}

export async function downloadFile(path, fallbackName) {
  const resp = await fetch('/admin/api/' + path.replace(/^\/+/, ''), { credentials: 'same-origin' });
  if (!resp.ok) {
    const data = await resp.json().catch(() => null);
    throw new Error(translateCenterMessage(data?.error?.message) || translateMessage("Export failed (HTTP {0})", resp.status));
  }
  const blob = await resp.blob();
  const cd = resp.headers.get('content-disposition') || '';
  const match = /filename="([^"]+)"/.exec(cd);
  const name = match ? match[1] : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Safe DOM helper: sets textContent for strings/numbers and never parses untrusted HTML.
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  appendChildren(node, children);
  return node;
}

function appendChildren(parent, items) {
  for (const item of items) {
    if (item === null || item === undefined || item === false) continue;
    if (Array.isArray(item)) appendChildren(parent, item);
    else if (item instanceof Node) parent.append(item);
    else parent.append(document.createTextNode(String(item)));
  }
}

export function badge(text, kind = 'neutral') {
  const withIcon = kind === 'ok' || kind === 'warn' || kind === 'err' || kind === 'accent';
  return el('span', { class: `badge ${kind}${withIcon ? ' icon-start' : ''}` }, text);
}

export function callout(kind, ...children) {
  const cls = kind ? `callout ${kind} icon-start` : 'callout icon-start';
  return el('div', { class: cls }, ...children);
}

export function searchBox(inputNode) {
  return el('div', { class: 'search-field' },
    el('span', { class: 'search-glyph icon', 'aria-hidden': 'true' }),
    inputNode,
  );
}

// IME-safe debounced search input (modern-web-guidance: ime-safe-enter-submit).
export function createSearchInput({ placeholder, ariaLabel, delayMs = 180, onSearch }) {
  let timer = null;
  let composing = false;
  let lastCompositionEndAt = null;
  let lastDispatched = '';

  const flush = () => {
    clearTimeout(timer);
    const next = input.value.trim();
    if (next === lastDispatched) return;
    lastDispatched = next;
    onSearch(next);
  };

  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(flush, delayMs);
  };

  const input = el('input', {
    type: 'search',
    placeholder,
    'aria-label': ariaLabel,
    onCompositionstart: () => {
      composing = true;
      clearTimeout(timer);
    },
    onCompositionend: (ev) => {
      composing = false;
      lastCompositionEndAt = ev.timeStamp;
      schedule();
    },
    onInput: () => {
      if (!composing) schedule();
    },
    onKeydown: (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        if (ev.isComposing || ev.keyCode === 229) return;
        if (lastCompositionEndAt !== null && Math.abs(ev.timeStamp - lastCompositionEndAt) < 50) return;
        flush();
      } else if (ev.key === 'Escape' && input.value) {
        ev.preventDefault();
        input.value = '';
        flush();
      }
    },
  });

  return searchBox(input);
}

export function terminalSnippet(commandText, label = translateMessage("Copy terminal command")) {
  const cmdId = `term-${++copySeq}`;
  return el('div', { class: 'terminal-box' },
    el('div', { class: 'terminal-cmd' },
      el('span', { class: 'terminal-glyph icon', 'aria-hidden': 'true' }),
      el('code', { id: cmdId, dataset: { fullText: commandText } }, commandText),
    ),
    el('span', { class: 'copy' },
      el('button', { type: 'button', class: 'copy-button icon-start', command: '--copy', commandfor: cmdId, 'aria-label': label }, translateMessage("Copy")),
      el('span', { class: 'tip', role: 'status' }),
    ),
  );
}

// Keeps full unbroken string in the DOM while visually keeping the trailing characters visible (single-line-overflow).
let copySeq = 0;
export function copyableCode(text, label = translateMessage("Copy content"), truncate = false) {
  const str = String(text || '');
  const id = `cp-${++copySeq}`;
  let codeNode;
  if (truncate && str.length > 24) {
    const head = str.slice(0, -8);
    const tail = str.slice(-8);
    codeNode = el('code', { id, class: 'mono truncate-mid', dataset: { fullText: str } },
      el('span', { class: 'truncate-head' }, head),
      tail,
    );
  } else if (str.length <= 24 && !str.includes(' ')) {
    codeNode = el('code', { id, class: 'mono code-nowrap', dataset: { fullText: str } }, str);
  } else {
    codeNode = el('code', { id, class: 'mono breakable', dataset: { fullText: str } }, str);
  }
  return el('span', { class: 'code-pill' },
    codeNode,
    el('span', { class: 'copy' },
      el('button', { type: 'button', class: 'copy-button icon-start', command: '--copy', commandfor: id, 'aria-label': label }, translateMessage("Copy")),
      el('span', { class: 'tip', role: 'status' }),
    ),
  );
}

// Enhances a file <input> wrapped inside a .dropzone container with drag-over styling and filename feedback.
export function bindDropzone(zone, input, titleEl, subEl, defaultTitle, defaultSub) {
  if (!zone || !input) return () => {};
  const refreshLabel = () => {
    const f = input.files?.[0];
    if (f) {
      zone.classList.add('has-file');
      if (titleEl) titleEl.textContent = translateMessage("Selected: {0}", f.name);
      if (subEl) subEl.textContent = translateMessage("{0} · Select or drop a different file", fmtBytes(f.size));
    } else {
      zone.classList.remove('has-file');
      if (titleEl) titleEl.textContent = defaultTitle;
      if (subEl) subEl.textContent = defaultSub;
    }
  };
  input.addEventListener('change', refreshLabel);
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', () => zone.classList.remove('dragover'));
  return refreshLabel;
}

export function makeDropzone(input, titleText, subText) {
  const titleNode = el('span', { class: 'dropzone-title' }, titleText);
  const subNode = el('span', { class: 'dropzone-sub' }, subText);
  const zone = el('div', { class: 'dropzone' },
    input,
    el('span', { class: 'dropzone-glyph icon', 'aria-hidden': 'true' }),
    el('div', { class: 'dropzone-copy' }, titleNode, subNode),
  );
  bindDropzone(zone, input, titleNode, subNode, titleText, subText);
  return zone;
}

export function fmtTime(iso) {
  if (!iso || iso.startsWith('0001-')) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(language, { hour12: false });
}

const relativeTime = new Intl.RelativeTimeFormat(language);

export function fmtRelative(iso) {
  if (!iso || iso.startsWith('0001-')) return translateMessage("Never reported");
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffSec = Math.round((Date.now() - d.getTime()) / 1000);
  if (diffSec < 5) return translateMessage("Just now");
  if (diffSec < 60) return relativeTime.format(-diffSec, 'second');
  if (diffSec < 3600) return relativeTime.format(-Math.floor(diffSec / 60), 'minute');
  if (diffSec < 86400) return relativeTime.format(-Math.floor(diffSec / 3600), 'hour');
  return relativeTime.format(-Math.floor(diffSec / 86400), 'day');
}

export function fmtBytes(n) {
  const v = Number(n || 0);
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KiB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MiB`;
  return `${(v / 1024 ** 3).toFixed(2)} GiB`;
}

export function fmtPortsMap(ports) {
  const entries = Object.entries(ports || {}).filter(([, p]) => p > 0);
  if (!entries.length) return null;
  return entries.map(([proto, port]) => `${proto.toUpperCase()}:${port}`);
}

export function toast(message) {
  const region = document.getElementById('toast-region');
  if (!region) return;
  const item = el('div', { class: 'toast' }, message);
  region.append(item);
  setTimeout(() => item.remove(), 3200);
}

// Modal <dialog> helpers following modern-web-guidance dialog rules.
export function openModal(title, contentNode, { closedBy = 'any' } = {}) {
  const dlg = document.getElementById('modal-dialog');
  const titleEl = document.getElementById('modal-title');
  const bodyEl = document.getElementById('modal-body');
  titleEl.textContent = title;
  bodyEl.replaceChildren(contentNode);
  dlg.returnValue = '';
  dlg.setAttribute('closedby', closedBy);
  if (!dlg.open) dlg.showModal();
}

export function closeModal() {
  const dlg = document.getElementById('modal-dialog');
  if (dlg?.open) dlg.close();
}

// Accessible confirmation modal focusing the safe Cancel control first (modern-web-guidance: dialog).
export function confirmModal({ title, message, detail = '', confirmText = translateMessage("Confirm"), danger = true }) {
  return new Promise((resolve) => {
    const dlg = document.getElementById('modal-dialog');
    const cancelBtn = el('button', { type: 'submit', value: 'cancel', class: 'btn secondary', autofocus: true }, translateMessage("Cancel"));
    const okBtn = el('button', {
      type: 'submit',
      value: 'confirm',
      class: `btn ${danger ? 'danger btn-trash' : 'primary btn-check'} icon-start`,
    }, confirmText);
    const form = el('form', { method: 'dialog', class: 'form-stack' },
      callout(danger ? 'warn' : '', message),
      detail ? el('p', { class: 'muted' }, detail) : null,
      el('div', { class: 'form-actions' }, cancelBtn, okBtn),
    );
    const onClose = () => {
      // Consume the submit value before clearing it; dismissals may leave it unchanged.
      const confirmed = dlg.returnValue === 'confirm';
      dlg.returnValue = '';
      resolve(confirmed);
    };
    dlg.addEventListener('close', onClose, { once: true });
    openModal(title, form, { closedBy: 'closerequest' });
  });
}

// Accessible tabs helper (modern-web-guidance tabs: aria-selected + hidden="until-found").
export function buildTabs(label, tabDefs, initialId) {
  const activeId = initialId || tabDefs[0]?.id;
  const buttons = [];
  const panels = [];
  const select = (id, moveFocus = false) => {
    for (let i = 0; i < tabDefs.length; i++) {
      const isSel = tabDefs[i].id === id;
      const btn = buttons[i];
      const panel = panels[i];
      btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
      btn.toggleAttribute('focusgroupstart', isSel);
      btn.tabIndex = isSel ? 0 : -1;
      if (isSel) {
        panel.removeAttribute('hidden');
        if (moveFocus) btn.focus();
      } else {
        panel.setAttribute('hidden', 'until-found');
      }
    }
  };

  for (const def of tabDefs) {
    const tabId = `tab-${def.id}-${++copySeq}`;
    const btn = el('button', {
      type: 'button',
      role: 'tab',
      id: tabId,
      'aria-selected': def.id === activeId ? 'true' : 'false',
      tabindex: def.id === activeId ? '0' : '-1',
      onClick: () => select(def.id, false),
    }, def.title);
    const panel = el('div', {
      role: 'tabpanel',
      'aria-labelledby': tabId,
      hidden: def.id === activeId ? null : 'until-found',
    }, el('div', { class: 'tabpanel-body' }, def.content));
    panel.addEventListener('beforematch', () => select(def.id, false));
    buttons.push(btn);
    panels.push(panel);
  }

  const tablist = el('div', {
    class: 'tablist',
    role: 'tablist',
    focusgroup: 'tablist nomemory',
    'aria-label': label,
    onKeydown: (e) => {
      const idx = buttons.indexOf(document.activeElement);
      if (idx < 0) return;
      let next = -1;
      if (e.key === 'ArrowRight') next = (idx + 1) % buttons.length;
      else if (e.key === 'ArrowLeft') next = (idx - 1 + buttons.length) % buttons.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = buttons.length - 1;
      if (next >= 0) {
        e.preventDefault();
        select(tabDefs[next].id, true);
      }
    },
  }, buttons);

  return { root: el('div', { class: 'tabs-block' }, tablist, panels), select };
}

// Invoker Commands --copy handler + fallback + VoiceOver duplicate-announcement fix.
const copyTimers = new WeakMap();
let lastCopyAnnouncement = '';

function legacyCopy(text) {
  const prev = document.activeElement;
  const field = Object.assign(document.createElement('textarea'), { value: text });
  field.setAttribute('readonly', '');
  field.className = 'skip-link';
  document.body.append(field);
  field.select();
  try {
    return document.execCommand('copy');
  } finally {
    field.remove();
    prev?.focus?.({ preventScroll: true });
  }
}

async function performCopy(button, target) {
  const text = target.dataset?.fullText || (target.matches('input, textarea') ? target.value : target.innerText.trim());
  if (!text) return;
  let ok = true;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    ok = legacyCopy(text);
  }
  const tip = button.nextElementSibling;
  clearTimeout(copyTimers.get(button));
  button.removeAttribute('data-copied');
  button.removeAttribute('data-failed');
  let msg = ok ? translateMessage("Copied") : translateMessage("Copy failed");
  if (msg === lastCopyAnnouncement) msg += '\u00A0';
  lastCopyAnnouncement = msg;
  if (tip) tip.textContent = '';
  void button.offsetWidth;
  button.setAttribute(ok ? 'data-copied' : 'data-failed', '');
  if (tip) requestAnimationFrame(() => { tip.textContent = msg; });
  copyTimers.set(button, setTimeout(() => {
    button.removeAttribute('data-copied');
    button.removeAttribute('data-failed');
    if (tip) tip.textContent = '';
  }, 1800));
}

export function initPlatformEnhancements() {
  if ('CommandEvent' in window) {
    document.addEventListener('command', (e) => {
      if (e.command === '--copy' && e.target) performCopy(e.source, e.target);
    }, true);
  } else {
    document.addEventListener('click', (e) => {
      if (e.defaultPrevented) return;
      const btn = e.target.closest('button[command="--copy"]');
      if (!btn) return;
      const target = document.getElementById(btn.getAttribute('commandfor'));
      if (target) performCopy(btn, target);
    });
  }

  // Dialog light-dismiss fallback where native closedby is unavailable.
  const dlg = document.getElementById('modal-dialog');
  document.getElementById('modal-close-btn')?.addEventListener('click', () => dlg.close());
  if (dlg && !('closedBy' in HTMLDialogElement.prototype)) {
    const outside = (ev) => {
      const r = dlg.getBoundingClientRect();
      return ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom;
    };
    let pressedOutside = false;
    dlg.addEventListener('pointerdown', (ev) => { pressedOutside = outside(ev); });
    dlg.addEventListener('pointerup', (ev) => {
      if (dlg.getAttribute('closedby') === 'any' && pressedOutside && outside(ev)) dlg.close();
    });
  }

  // Two-state color-scheme toggle synced with <meta name="color-scheme">.
  syncThemeMeta();
  window.addEventListener('storage', (ev) => {
    if (ev.key === 'color-scheme') syncThemeMeta();
  });
}

export function syncThemeMeta() {
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (!meta) return;
  try {
    meta.content = localStorage.getItem('color-scheme') ?? 'light dark';
  } catch {
    meta.content = 'light dark';
  }
}

export function toggleColorScheme() {
  const meta = document.querySelector('meta[name="color-scheme"]');
  const sysDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const sysScheme = sysDark ? 'dark' : 'light';
  let stored = null;
  try { stored = localStorage.getItem('color-scheme'); } catch {}
  const currentRendered = stored === 'dark' || stored === 'light' ? stored : sysScheme;
  const target = currentRendered === 'dark' ? 'light' : 'dark';
  try {
    if (target === sysScheme) localStorage.removeItem('color-scheme');
    else localStorage.setItem('color-scheme', target);
  } catch {}
  if (meta) meta.content = target === sysScheme ? 'light dark' : target;
}
