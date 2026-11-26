import { parseArgs } from 'node:util';
import { scenarios } from './center-mock/api.mjs';
import { createPreviewServer } from './center-mock/server.mjs';

try {
  const { values } = parseArgs({
    options: {
      port: { type: 'string', default: '18081' },
      scenario: { type: 'string', default: 'demo' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const usage = `node scripts/center-mock.mjs [--port 18081] [--scenario ${scenarios.join('|')}]`;
  if (values.help) {
    console.log(usage);
  } else {
    const port = Number(values.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须是 1–65535 之间的整数。');
    const server = createPreviewServer(values.scenario);
    server.on('error', (err) => {
      console.error(err.code === 'EADDRINUSE' ? `端口 ${port} 已占用，请用 --port 指定其他端口。` : err.message);
      process.exitCode = 1;
    });
    server.listen(port, '127.0.0.1', () => {
      console.log(`AckTier Mock (${values.scenario})  http://127.0.0.1:${port}/admin/`);
      console.log('只使用模拟数据，无持久化。修改前端文件后刷新即可。');
    });
  }
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
