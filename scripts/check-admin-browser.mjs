// Usage: node scripts/check-admin-browser.mjs <bin-dir> <Chrome/Chromium executable>
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';

const [bin, chrome] = process.argv.slice(2);
assert.ok(bin && chrome, 'Usage: node scripts/check-admin-browser.mjs <bin-dir> <Chrome/Chromium executable>');
const dir = await mkdtemp(join(process.env.ACKTIER_TEST_TMPDIR || tmpdir(), 'acktier-browser-'));
const exe = (name) => resolve(bin, name + (process.platform === 'win32' ? '.exe' : ''));
const run = promisify(execFile);
const cli = (args) => run(exe('acktier'), args, { cwd: dir, timeout: 8000, windowsHide: true });

async function waitFor(label, check) {
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    const result = await check();
    if (result) return result;
    await delay(40);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function localAddr() {
  const server = createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((done) => server.close(done));
  return `127.0.0.1:${port}`;
}

async function connect(url, onEvent) {
  const socket = new WebSocket(url);
  await new Promise((done, fail) => {
    socket.addEventListener('open', done, { once: true });
    socket.addEventListener('error', fail, { once: true });
  });
  let seq = 0;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id) pending.get(msg.id)?.(msg);
    else onEvent(msg);
  });
  return {
    close: () => socket.close(),
    send: (method, params = {}) => new Promise((done, fail) => {
      const id = ++seq;
      const timer = setTimeout(() => {
        pending.delete(id);
        fail(new Error(`Browser command timed out: ${method}`));
      }, 5000);
      pending.set(id, ({ result, error }) => {
        clearTimeout(timer);
        pending.delete(id);
        error ? fail(new Error(error.message)) : done(result);
      });
      socket.send(JSON.stringify({ id, method, params }));
    }),
  };
}

const processes = [];
function launch(command, args, onOutput, env = process.env) {
  const child = spawn(command, args, { cwd: dir, env, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
  let failure;
  const ended = new Promise((done) => {
    child.once('exit', done);
    child.once('error', (err) => { failure = err; done(); });
  });
  processes.push({ child, ended });
  child.stderr.on('data', onOutput);
  return () => {
    if (failure) throw failure;
    assert.equal(child.exitCode, null, `${command} exited prematurely`);
  };
}

let cdp;
try {
  const [adminAddr, nodeAddr] = await Promise.all([localAddr(), localAddr()]);
  const adminURL = `http://${adminAddr}`;
  const ownerDir = join(dir, 'owner');
  const trustPath = join(ownerDir, 'trust.json');
  const signerPath = join(ownerDir, 'signer.json');
  const password = 'browser-test-password';
  await cli(['owner', 'init', '--dir', ownerDir]);
  let serverError = '';
  const checkCenter = launch(exe('acktier-server'), [
    '-listen', nodeAddr, '-admin-listen', adminAddr, '-stun=', '-stun-alt=',
    '-data', join(dir, 'center', 'server.sqlite'), '-credentials-file', join(dir, 'credentials.json'),
  ], (chunk) => { serverError = (serverError + chunk).slice(-4096); }, { ...process.env, ACKTIER_ADMIN_PASSWORD: password });
  await waitFor('the center', async () => {
    try { checkCenter(); } catch (err) { throw new Error(`${err.message}: ${serverError}`); }
    return (await fetch(`${adminURL}/healthz`, { signal: AbortSignal.timeout(300) }).catch(() => null))?.ok;
  });
  assert.equal((await fetch(`http://${nodeAddr}/admin/`)).status, 404);

  let browserLogs = '';
  const checkBrowser = launch(resolve(chrome), [
    '--headless', '--disable-background-networking', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${join(dir, 'profile')}`, '--remote-debugging-port=0', 'about:blank',
  ], (chunk) => { browserLogs = (browserLogs + chunk).slice(-4096); });
  const browserURL = await waitFor('Chrome', () => {
    checkBrowser();
    return browserLogs.match(/DevTools listening on (ws:\S+)/)?.[1];
  });
  const pages = await (await fetch(`http://${new URL(browserURL).host}/json/list`)).json();
  const uploads = [];
  cdp = await connect(pages.find((p) => p.type === 'page').webSocketDebuggerUrl, ({ method, params }) => {
    if (method !== 'Network.requestWillBeSent' || params.request.method !== 'POST') return;
    const path = new URL(params.request.url).pathname;
    if (path.startsWith('/admin/api/setup') || path.startsWith('/admin/api/authorization')) {
      uploads.push({ path, body: params.request.postData });
    }
  });
  await cdp.send('Network.enable', { maxPostDataSize: 1 << 20 });
  const js = async (expression, awaitPromise = false) => {
    const { result, exceptionDetails } = await cdp.send('Runtime.evaluate', { expression, awaitPromise, returnByValue: true });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description || 'Browser evaluation failed');
    return result.value;
  };
  const web = (path, opts = {}) => js(`import('/admin/assets/api.js').then(({api}) =>
    api(${JSON.stringify(path)}, ${JSON.stringify(opts)}))`, true);
  const selectFile = async (selector, file) => {
    const { root } = await cdp.send('DOM.getDocument');
    const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector });
    assert.ok(nodeId, `Missing file picker ${selector}`);
    await cdp.send('DOM.setFileInputFiles', { files: [file], nodeId });
  };
  const view = async (hash, heading) => {
    await js(`location.hash = ${JSON.stringify(hash)}`);
    await waitFor(heading, () => js(`document.querySelector('#main-content h1')?.textContent.includes(${JSON.stringify(heading)})`));
  };
  const noVersionLabel = async (selector) => {
    const text = await js(`document.querySelector(${JSON.stringify(selector)}).innerText`);
    assert.doesNotMatch(text, /\bv\d+\b/, `unexpected version label in ${selector}`);
  };

  // Reject a private file without POSTing it, even if an earlier valid preview
  // response comes back after the newer selection.
  const checkPicker = async ({ selector, path, validFile, ready, disabled }) => {
    const rejected = () => js(`document.querySelector('${selector}').getAttribute('aria-invalid') === 'true' && (${disabled})`);
    const before = uploads.length;
    await selectFile(selector, signerPath);
    await waitFor('local rejection of the signer file', rejected);
    assert.equal(uploads.length, before, 'private file selection sent an upload request');
    await js(`(() => {
      const fetch = window.fetch;
      window.fetch = async (...args) => {
        const response = await fetch(...args);
        if (args[0] !== ${JSON.stringify(path)}) return response;
        window.fetch = fetch;
        const data = await response.json();
        response.json = () => new Promise((done) => { window.releasePreview = () => done(data); });
        return response;
      };
    })()`);
    await selectFile(selector, validFile);
    await waitFor('paused valid preview response', () => js(`typeof window.releasePreview === 'function'`));
    await selectFile(selector, signerPath);
    await waitFor('replacement file rejection', rejected);
    await js(`(async () => {
      window.releasePreview();
      delete window.releasePreview;
      await new Promise(requestAnimationFrame);
      return true;
    })()`, true);
    assert.equal(uploads.length, before + 1, 'replacement private file sent an upload request');
    assert.ok(await js(disabled), 'stale preview enabled a submit for the rejected selection');
    await selectFile(selector, validFile);
    await waitFor('preview for the current file', () => js(ready));
  };

  await cdp.send('Page.navigate', { url: `${adminURL}/admin/` });
  await waitFor('login form', () => js(`document.querySelector('#auth-shell')?.hidden === false`));
  await js(`document.querySelector('#current-password').value = ${JSON.stringify(password)};
    document.querySelector('#login-form').requestSubmit()`);
  await waitFor('owner setup', () => js(`document.querySelector('#setup-shell')?.hidden === false`));
  await checkPicker({
    selector: '#trust-file-input', path: '/admin/api/setup/preview', validFile: trustPath,
    ready: `!document.querySelector('#setup-confirm-check').disabled`,
    disabled: `document.querySelector('#setup-submit-btn').disabled && document.querySelector('#setup-confirm-check').disabled`,
  });
  await noVersionLabel('#trust-preview-box');
  await js(`document.querySelector('#setup-confirm-check').click(); document.querySelector('#setup-form').requestSubmit()`);
  await waitFor('dashboard', () => js(`document.querySelector('#app-shell')?.hidden === false`));

  const acl = { acls: [{ action: 'accept', proto: 'tcp', src: ['*'], dst: ['*:8443'] }] };
  const draft = await web('drafts', { method: 'POST', body: { name: 'Valid draft', policy: { members: [], acl } } });
  const invalid = await web('drafts', { method: 'POST', body: { name: 'Invalid draft', policy: {
    members: [], acl: { groups: { 'group:cycle': ['group:cycle'] }, acls: [{ src: ['group:cycle'], dst: ['*:443'] }] },
  } } });
  assert.equal(invalid.analysis.valid, false);
  await view(`policy/${draft.draft.id}`, 'ACL 与策略');
  const heading = (name) => `document.querySelector('.draft-layout section h2')?.textContent === ${JSON.stringify(name)}`;
  await waitFor('valid draft workspace', () => js(heading('Valid draft')));
  assert.equal(await js(`document.querySelectorAll('.draft-list button').length`), 2);
  const selectDraft = (id) => js(`document.querySelector('.draft-item[data-draft-id="${id}"]').click()`);
  await selectDraft(invalid.draft.id);
  await waitFor('readable invalid draft', () => js(`${heading('Invalid draft')} && !!document.querySelector('.draft-layout .callout.error')`));
  await selectDraft(draft.draft.id);
  await waitFor('valid draft reopened', () => js(heading('Valid draft')));

  const policyPath = join(ownerDir, 'policy.json');
  await writeFile(policyPath, await js(`fetch('/admin/api/drafts/${draft.draft.id}/export').then(r => r.text())`, true));
  await cli(['owner', 'sign', '--dir', ownerDir, '--policy', policyPath, '--valid-for', '1h']);
  const authPath = join(ownerDir, 'authorization.json');
  const envelope = JSON.parse(await readFile(authPath, 'utf8'));
  await view('publish', '签名授权发布');
  const publishBtn = `[...document.querySelectorAll('#main-content button')].find(b => b.textContent.includes('确认验证并发布'))`;
  await checkPicker({
    selector: '#auth-upload-input', path: '/admin/api/authorization/preview', validFile: authPath,
    ready: `(${publishBtn})?.disabled === false`,
    disabled: `(${publishBtn})?.disabled === true`,
  });
  await js(`(${publishBtn}).click()`);
  await waitFor('signed publication', () => js(`document.querySelector('#main-content').textContent.includes('已持久化')`));
  const posted = uploads.filter(({ path }) => path.startsWith('/admin/api/authorization'));
  assert.equal(posted.length, 3, 'expected two valid previews and one signed publication');
  for (const req of posted) assert.deepEqual(JSON.parse(req.body), envelope, 'browser changed the signed envelope');

  const history = await web('authorization/history');
  assert.ok(history[0].version > 0, 'API must retain the signed snapshot version');
  await waitFor('publication record', () => js(`!!document.querySelector('.tbl-history tbody th time')`));
  await noVersionLabel('#main-content');
  await js(`document.querySelector('.tbl-history tbody tr td:last-child button').click()`);
  await waitFor('publication details', () => js(`document.querySelector('#modal-dialog').open`));
  await noVersionLabel('#modal-dialog');
  await js(`document.querySelector('#modal-dialog').close()`);

  await view('overview', '概览与实时协调状态');
  await noVersionLabel('.topbar');
  await noVersionLabel('#main-content');
  await view(`policy/${draft.draft.id}`, 'ACL 与策略');
  await waitFor('stale draft warning', () => js(`document.querySelector('.draft-layout section')?.innerText.includes('生效策略已有更新')`));
  await noVersionLabel('#main-content');

  const cloned = await web('drafts', { method: 'POST', body: { name: 'Clone of active', fromActive: true } });
  assert.deepEqual(cloned.draft.policy.acl, acl);
  for (const { draft: { id } } of [draft, cloned]) await web(`drafts/${id}`, { method: 'DELETE' });
  await assert.rejects(web('drafts', { method: 'POST', body: { fromActive: true } }), /完整 policy\.json/);
  console.log('Browser check passed: private files stayed local, stale previews were ignored, both drafts opened, and signed ACLs were preserved.');
} finally {
  if (cdp) {
    await Promise.race([cdp.send('Browser.close').catch(() => {}), delay(250)]);
    cdp.close();
  }
  for (const { child } of processes.reverse()) child.kill();
  await Promise.all(processes.map(({ ended }) => ended));
  await rm(dir, { recursive: true, force: true, maxRetries: 5 });
}
