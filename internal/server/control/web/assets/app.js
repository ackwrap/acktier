import {
  api, el, callout, bindDropzone, setSessionCSRF, onSessionExpired, initPlatformEnhancements, toggleColorScheme, toast,
} from './api.js';
import { readPublicArtifact } from './artifacts.js';
import { renderOverview, renderRequests } from './views_overview.js';
import { renderNodes } from './views_nodes.js';
import { renderPolicy, renderPublish } from './views_policy.js';
import { renderSecurity } from './views_security.js';

const authShell = document.getElementById('auth-shell');
const setupShell = document.getElementById('setup-shell');
const appShell = document.getElementById('app-shell');
const mainContent = document.getElementById('main-content');

let currentSession = { authenticated: false, setupPending: true };

function showShell(which) {
  authShell.hidden = which !== 'auth';
  setupShell.hidden = which !== 'setup';
  appShell.hidden = which !== 'app';
}

function wireCompactNavigation() {
  const nav = document.getElementById('console-nav');
  const toggle = document.getElementById('console-nav-toggle');
  const sidebar = toggle.closest('.sidebar');
  const setExpanded = (expanded) => {
    toggle.setAttribute('aria-expanded', String(expanded));
    nav.classList.toggle('is-collapsed', !expanded);
  };
  setExpanded(false);
  toggle.hidden = false;
  toggle.addEventListener('click', () => setExpanded(toggle.getAttribute('aria-expanded') === 'false'));
  sidebar.addEventListener('click', (event) => {
    if (!event.target.closest('a') || !toggle.offsetWidth || event.button !== 0 ||
      event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    setExpanded(false);
    mainContent.focus({ preventScroll: true });
  });
  sidebar.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !toggle.offsetWidth || toggle.getAttribute('aria-expanded') !== 'true') return;
    event.preventDefault();
    setExpanded(false);
    toggle.focus();
  });
}

function updateTopChrome(overviewData) {
  if (!overviewData) return;
  const netEl = document.getElementById('top-network-id');
  if (netEl && overviewData.networkId) {
    const full = String(overviewData.networkId);
    netEl.dataset.fullText = full;
    netEl.className = 'mono truncate-mid';
    netEl.replaceChildren(el('span', { class: 'truncate-head' }, full.slice(0, -6)), full.slice(-6));
  }
  const reqBadge = document.getElementById('nav-badge-requests');
  const reqCount = overviewData.counts?.requests || 0;
  if (reqBadge) {
    reqBadge.textContent = String(reqCount);
    reqBadge.hidden = reqCount === 0;
  }
  const draftBadge = document.getElementById('nav-badge-drafts');
  const draftCount = overviewData.counts?.drafts || 0;
  if (draftBadge) {
    draftBadge.textContent = String(draftCount);
    draftBadge.hidden = draftCount === 0;
  }
}

async function refreshGlobalChrome() {
  if (!currentSession.authenticated || currentSession.setupPending) return;
  try {
    const data = await api('overview');
    updateTopChrome(data);
  } catch {
    // Handled by session listener if 401.
  }
}

function parseRoute() {
  const raw = (window.location.hash || '#overview').replace(/^#\/?/, '');
  const slash = raw.indexOf('/');
  if (slash < 0) return { page: raw || 'overview', param: '' };
  return { page: raw.slice(0, slash) || 'overview', param: decodeURIComponent(raw.slice(slash + 1)) };
}

export function navTo(route) {
  const targetHash = '#' + route.replace(/^#/, '');
  if (window.location.hash === targetHash) {
    renderCurrentRoute();
  } else {
    window.location.hash = targetHash;
  }
}

async function renderCurrentRoute() {
  if (!currentSession.authenticated) {
    showShell('auth');
    return;
  }
  if (currentSession.setupPending) {
    showShell('setup');
    return;
  }
  showShell('app');
  const { page, param } = parseRoute();

  for (const link of document.querySelectorAll('.nav-item')) {
    if (link.dataset.route === page) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }

  try {
    switch (page) {
      case 'requests':
        await renderRequests(mainContent, navTo);
        await refreshGlobalChrome();
        break;
      case 'nodes':
        await renderNodes(mainContent, navTo, param);
        await refreshGlobalChrome();
        break;
      case 'policy':
        await renderPolicy(mainContent, navTo, refreshGlobalChrome, param);
        break;
      case 'publish':
        await renderPublish(mainContent, navTo, refreshGlobalChrome);
        await refreshGlobalChrome();
        break;
      case 'security':
        await renderSecurity(mainContent, refreshGlobalChrome);
        await refreshGlobalChrome();
        break;
      case 'overview':
      default:
        await renderOverview(mainContent, navTo, updateTopChrome);
        break;
    }
  } catch (err) {
    mainContent.replaceChildren(callout('error', '加载页面失败：' + err.message));
  }
}

function wireLoginView() {
  const pwInput = document.getElementById('current-password');
  const toggleBtn = document.getElementById('toggle-pw-btn');
  const loginForm = document.getElementById('login-form');
  const alertBox = document.getElementById('login-alert');

  toggleBtn?.addEventListener('click', () => {
    const show = pwInput.type === 'password';
    pwInput.type = show ? 'text' : 'password';
    toggleBtn.textContent = show ? '隐藏' : '显示';
    toggleBtn.setAttribute('aria-pressed', show ? 'true' : 'false');
    toggleBtn.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  });

  loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    alertBox.hidden = true;
    const submitBtn = document.getElementById('login-submit');
    submitBtn.disabled = true;
    try {
      const s = await api('login', { method: 'POST', body: { password: pwInput.value } });
      pwInput.value = '';
      applySession(s);
      await renderCurrentRoute();
    } catch (err) {
      alertBox.textContent = err.message;
      alertBox.hidden = false;
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function wireSetupWizard() {
  const dropzone = document.getElementById('trust-dropzone');
  const fileInput = document.getElementById('trust-file-input');
  const fileTitle = document.getElementById('trust-file-title');
  const fileSub = document.getElementById('trust-file-sub');
  const previewBox = document.getElementById('trust-preview-box');
  const alertBox = document.getElementById('setup-alert');
  const confirmCheck = document.getElementById('setup-confirm-check');
  const submitBtn = document.getElementById('setup-submit-btn');
  const form = document.getElementById('setup-form');

  bindDropzone(
    dropzone, fileInput, fileTitle, fileSub,
    '点击选择或拖拽 trust.json 到此处',
    '仅接受公开信任配置（上限 16 KiB），浏览器将在本地先行拦截任何私钥文件',
  );

  let stagedTrust = null;
  let previewSeq = 0;
  const syncBtn = () => {
    submitBtn.disabled = !(stagedTrust && confirmCheck.checked);
  };

  confirmCheck?.addEventListener('change', syncBtn);
  fileInput?.addEventListener('change', async () => {
    const seq = ++previewSeq;
    alertBox.hidden = true;
    previewBox.hidden = true;
    stagedTrust = null;
    confirmCheck.checked = false;
    confirmCheck.disabled = true;
    fileInput.removeAttribute('aria-invalid');
    syncBtn();
    const f = fileInput.files?.[0];
    if (!f) return;
    try {
      const trust = await readPublicArtifact(f, 'trust');
      if (seq !== previewSeq) return;
      const preview = await api('setup/preview', { method: 'POST', body: trust });
      if (seq !== previewSeq) return;
      stagedTrust = trust;
      document.getElementById('preview-netid').textContent = preview.networkId;
      document.getElementById('preview-pubkey').textContent = preview.publicKey;
      previewBox.hidden = false;
      confirmCheck.disabled = false;
      syncBtn();
    } catch (err) {
      if (seq !== previewSeq) return;
      dropzone?.classList.remove('has-file');
      fileInput.setAttribute('aria-invalid', 'true');
      alertBox.textContent = err.message;
      alertBox.hidden = false;
    }
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!stagedTrust || !confirmCheck.checked) return;
    alertBox.hidden = true;
    submitBtn.disabled = true;
    fileInput.disabled = true;
    confirmCheck.disabled = true;
    try {
      await api('setup', {
        method: 'POST',
        body: { trust: stagedTrust, confirm: true },
      });
      toast('已成功绑定所有者公钥，中心协调现已开启！');
      const s = await api('session');
      applySession(s);
      await renderCurrentRoute();
    } catch (err) {
      alertBox.textContent = err.message;
      alertBox.hidden = false;
    } finally {
      fileInput.disabled = false;
      confirmCheck.disabled = !stagedTrust;
      syncBtn();
    }
  });
}

function applySession(s) {
  currentSession = s || { authenticated: false, setupPending: true };
  setSessionCSRF(currentSession.csrf || '');
  const badgeEl = document.getElementById('auth-state-badge');
  if (badgeEl) {
    if (!currentSession.passwordConfigured) {
      badgeEl.textContent = '等待配置管理员密码';
    } else if (currentSession.setupPending) {
      badgeEl.textContent = '登录后绑定所有者';
    } else {
      badgeEl.textContent = '所有者已绑定';
    }
  }
}

async function doLogout() {
  try {
    const s = await api('logout', { method: 'POST' });
    applySession(s);
  } catch {
    applySession({ authenticated: false, setupPending: currentSession.setupPending });
  }
  showShell('auth');
}

async function boot() {
  initPlatformEnhancements();
  wireLoginView();
  wireSetupWizard();
  wireCompactNavigation();

  document.getElementById('theme-toggle-btn')?.addEventListener('click', toggleColorScheme);
  document.getElementById('setup-theme-btn')?.addEventListener('click', toggleColorScheme);
  document.getElementById('logout-btn')?.addEventListener('click', doLogout);
  document.getElementById('setup-logout-btn')?.addEventListener('click', doLogout);
  document.getElementById('refresh-view-btn')?.addEventListener('click', () => renderCurrentRoute());

  onSessionExpired(() => {
    applySession({ authenticated: false, setupPending: currentSession.setupPending, passwordConfigured: true });
    showShell('auth');
    const alertBox = document.getElementById('login-alert');
    if (alertBox) {
      alertBox.textContent = '管理会话已过期或被重置，请重新登录。';
      alertBox.hidden = false;
    }
  });

  window.addEventListener('hashchange', () => renderCurrentRoute());

  try {
    const s = await api('session');
    applySession(s);
  } catch {
    applySession({ authenticated: false, setupPending: true });
  }
  await renderCurrentRoute();
}

boot();
