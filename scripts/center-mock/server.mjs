import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createMockAPI, mockPassword, scenarios } from './api.mjs';

const web = new URL('../../internal/server/control/web/', import.meta.url);
const jsonType = 'application/json; charset=utf-8';
const types = {
  css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8',
  svg: 'image/svg+xml', png: 'image/png', webp: 'image/webp', jpg: 'image/jpeg', jpeg: 'image/jpeg',
  ico: 'image/x-icon', woff: 'font/woff', woff2: 'font/woff2',
};

function send(res, method, status, type, body, headers) {
  res.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body), ...headers });
  res.end(method === 'HEAD' ? undefined : body);
}

function previewIndex(html) {
  const loginHint = `<p class="callout warn"><strong>MOCK 预览</strong> · 演示密码 <code>${mockPassword}</code>，不要输入真实凭据。</p>\n`;
  const setupHint = `<p class="callout warn"><strong>MOCK 预览</strong> · <a href="/mock/trust.json">下载示例 trust.json</a>，不要上传真实密钥。</p>\n`;
  return html
    .replace(/<title>/i, '$&[MOCK] ')
    .replace('<div class="topbar-status">', '$&\n<span class="badge warn">MOCK · 演示数据</span>')
    .replace('<form id="login-form"', `${loginHint}$&`)
    .replace('<form id="setup-form"', `${setupHint}$&`);
}

async function readJSON(req) {
  const limit = 1024 * 1024;
  let size = 0;
  const chunks = [];
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > limit) {
      req.resume();
      throw new RangeError('Mock 请求体过大。');
    }
    chunks.push(chunk);
  }
  if (!size) return {};
  if (!req.headers['content-type']?.startsWith('application/json')) throw new SyntaxError();
  const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new SyntaxError();
  return data;
}

// This server only serves checked-in frontend files and in-memory fixtures.
// It deliberately has no proxy, persistent store, or real coordination routes.
export function createPreviewServer(scenario = 'demo') {
  if (!scenarios.includes(scenario)) throw new Error(`未知 Mock 场景：${scenario}`);
  const mock = createMockAPI(scenario);
  return createServer({ requestTimeout: 15000 }, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    const json = (status, body, headers) => send(res, req.method, status, jsonType, JSON.stringify(body), headers);
    const fail = (status, code, message) => json(status, { error: { code, message } });
    const origin = new URL(`http://127.0.0.1:${req.socket.localPort}`);
    if (req.headers.host !== origin.host) {
      return fail(403, 'mock_local_only', '请直接从本机访问 Mock 地址。');
    }

    try {
      const url = new URL(req.url, origin);
      if (url.origin !== origin.origin) return fail(403, 'mock_local_only', 'Mock 不代理其他服务。');
      const { pathname, searchParams } = url;
      const reading = req.method === 'GET' || req.method === 'HEAD';
      if (reading && (pathname === '/' || pathname === '/admin')) {
        res.writeHead(302, { Location: '/admin/' }).end();
        return;
      }
      if (reading && pathname === '/admin/') {
        const html = await readFile(new URL('index.html', web), 'utf8');
        return send(res, req.method, 200, 'text/html; charset=utf-8', previewIndex(html));
      }
      // Named assets only, without encoded segments, backslashes, or dot paths.
      const asset = pathname.match(/^\/admin\/assets\/((?:[\w-]+\/)*[\w.-]+\.(\w+))$/);
      if (reading && asset && Object.hasOwn(types, asset[2])) {
        const file = await readFile(new URL(`assets/${asset[1]}`, web));
        return send(res, req.method, 200, types[asset[2]], file);
      }
      if (reading && pathname.startsWith('/mock/')) {
        const name = pathname.slice('/mock/'.length);
        const file = mock.files.get(name);
        if (file) return json(200, file, { 'Content-Disposition': `attachment; filename="${name}"` });
      }
      if (pathname.startsWith('/admin/api/')) {
        if ((req.headers.origin && req.headers.origin !== origin.origin) || req.headers['sec-fetch-site'] === 'cross-site') {
          return fail(403, 'mock_local_only', 'Mock API 仅接受本页请求。');
        }
        const parts = pathname.slice('/admin/api/'.length).split('/').map(decodeURIComponent);
        if (parts.length <= 4 && parts.every((p) => p && !p.includes('/'))) {
          const result = mock.dispatch(reading ? 'GET' : req.method, parts, searchParams, reading ? {} : await readJSON(req));
          return json(result.status, result.body, result.headers);
        }
      }
      return fail(404, 'not_found', '没有这个 Mock 页面或接口。');
    } catch (err) {
      if (err.code === 'ENOENT') return fail(404, 'not_found', '没有这个前端文件。');
      if (err instanceof SyntaxError || err instanceof URIError) return fail(400, 'bad_request', 'Mock 请求格式无效。');
      if (err instanceof RangeError) return fail(413, 'too_large', 'Mock 请求体过大。');
      if (res.destroyed) return;
      console.error('[center-mock]', err);
      return fail(500, 'mock_error', 'Mock 预览遇到错误，请检查终端。');
    }
  });
}
