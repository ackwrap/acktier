import {
  api, el, badge, callout, searchBox, makeDropzone, copyableCode, fmtTime, toast, openModal, closeModal, setSessionCSRF,
} from './api.js';
import { readPublicArtifact } from './artifacts.js';
import { renderAuditRow } from './views_audit.js';

const keyStateMeta = {
  active: ['可用', 'ok'],
  used: ['已使用', 'neutral'],
  expired: ['已过期', 'warn'],
  revoked: ['已吊销', 'err'],
};

export async function renderSecurity(container, refreshGlobal) {
  const newKeyBanner = el('div', { hidden: true });
  const keysMount = el('div', {});
  const delegMount = el('div', { class: 'form-stack' });
  const auditMount = el('div', {});
  const auditPager = el('div', { class: 'toolbar-row between' });
  let auditState = { q: '', page: 1, size: 15 };

  function openCreateKeyModal() {
    const labelIn = el('input', { type: 'text', id: 'new-key-label', maxlength: 64, required: true, placeholder: '例如：上海办公室 NAS 入网申请' });
    const ttlIn = el('input', { type: 'number', id: 'new-key-ttl', min: 1, max: 720, value: 24, required: true });
    const reuseCheck = el('input', { type: 'checkbox', id: 'new-key-reuse' });
    const errBox = el('div', { class: 'callout error icon-start', hidden: true });

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
          newKeyBanner.hidden = false;
          newKeyBanner.className = 'preview-card form-stack';
          newKeyBanner.replaceChildren(
            el('div', { class: 'toolbar-row between' },
              badge('入网申请码已生成（一次性明文展示）', 'ok'),
              el('span', { class: 'muted' }, '离开或刷新页面后中心仅保留哈希摘要，无法再次查看明文'),
            ),
            copyableCode(created.key, '复制新生成的申请码'),
          );
          toast('申请码已创建');
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
      el('div', { class: 'field' }, el('label', { for: 'new-key-label' }, '备注说明（必填）'), labelIn),
      el('div', { class: 'field' },
        el('label', { for: 'new-key-ttl' }, '有效时长（小时，1–720）'),
        ttlIn,
        el('p', { class: 'field-hint' }, '申请码仅允许节点向中心提交未验证入网申请，无法绕过所有者签名进入数据面。'),
      ),
      el('label', { class: 'checkbox-row', for: 'new-key-reuse' },
        reuseCheck,
        el('span', {}, '允许在有效期内重复使用（默认单次使用，生产环境建议保持不勾选）'),
      ),
      el('div', { class: 'form-actions' },
        el('button', { type: 'button', class: 'btn secondary', onClick: closeModal }, '取消'),
        el('button', { type: 'submit', class: 'btn primary btn-key icon-start' }, '生成申请码'),
      ),
    );
    openModal('创建入网申请码', form);
  }

  async function loadKeys() {
    const keys = await api('keys');
    if (!keys.length) {
      keysMount.replaceChildren(el('div', { class: 'empty-state' }, '暂无申请码记录。点击右上角可签发限时单次申请码。'));
      return;
    }
    keysMount.replaceChildren(
      el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'keys-cap' },
        el('table', { class: 'tbl-keys' },
          el('caption', { id: 'keys-cap' }, `申请码记录（共 ${keys.length} 条 · 不存储或回显明文）`),
          el('thead', {}, el('tr', {},
            el('th', { scope: 'col' }, '备注与 ID'),
            el('th', { scope: 'col' }, '状态'),
            el('th', { scope: 'col' }, '类型与使用次数'),
            el('th', { scope: 'col' }, '到期时间'),
            el('th', { scope: 'col' }, '操作'),
          )),
          el('tbody', {}, keys.map((k) => {
            const [stText, stKind] = keyStateMeta[k.state] || [k.state, 'neutral'];
            return el('tr', {},
              el('th', { scope: 'row' },
                el('div', {}, k.label || '未填写'),
                el('code', { class: 'muted' }, k.id),
              ),
              el('td', {}, badge(stText, stKind)),
              el('td', {}, el('span', { class: 'chip' }, k.reusable ? '可重复' : '单次'), ` 已用 ${k.usedCount} 次`),
              el('td', {}, fmtTime(k.expiresAt)),
              el('td', {}, k.state === 'active'
                ? el('button', {
                  type: 'button', class: 'btn danger sm btn-trash icon-start',
                  onClick: async () => {
                    await api(`keys/${encodeURIComponent(k.id)}/revoke`, { method: 'POST' });
                    toast('申请码已吊销（不影响已签成员权限）');
                    loadKeys();
                    loadAudit();
                    refreshGlobal();
                  },
                }, '吊销')
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
          toast('控制端管理 API 委托已启用');
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
          el('h2', {}, '控制端管理 API 委托'),
          d.enabled ? badge('已启用委托', 'ok') : badge('默认关闭', 'neutral'),
        ),
        d.enabled
          ? el('button', {
            type: 'button', class: 'btn danger sm btn-trash icon-start',
            onClick: async () => {
              await api('delegation', { method: 'DELETE' });
              toast('已取消控制端委托，原 API 凭据已立即失效');
              loadDelegation();
              loadAudit();
            },
          }, '立即取消委托')
          : null,
      ),
      el('p', { class: 'muted' },
        '管理接口仅在独立管理端口开放，每次请求都需要 Ed25519 挑战签名。可在控制端运行 ',
        el('code', {}, 'acktier owner controller-init --dir ./data/owner'),
        ' 导出公开的 ',
        el('code', {}, 'controller-trust.json'),
        '（与策略签名私钥严格分离）。',
      ),
      d.enabled
        ? el('dl', { class: 'kv-grid' },
          el('div', {}, el('dt', {}, '已绑定控制端管理公钥'), el('dd', {}, copyableCode(d.publicKey, '复制控制端管理公钥', true))),
          el('div', {}, el('dt', {}, '委托备注'), el('dd', {}, d.label || '—')),
          el('div', {}, el('dt', {}, '更新时间'), el('dd', {}, fmtTime(d.updatedAt))),
        )
        : null,
      el('div', { class: 'field' },
        el('label', { for: 'controller-trust-file' }, d.enabled ? '轮换控制端管理公钥 (controller-trust.json)' : '上传 controller-trust.json 启用委托'),
        makeDropzone(fileIn, '点击选择或拖拽 controller-trust.json', '浏览器将在本地校验公开委托格式并拦截任何私钥文件'),
      ),
    );
  }

  // Password Change Card
  const curPw = el('input', { type: 'password', id: 'pw-current', autocomplete: 'current-password', required: true, placeholder: '输入当前密码' });
  const nextPw = el('input', { type: 'password', id: 'pw-next', autocomplete: 'new-password', minlength: 12, maxlength: 256, required: true, placeholder: '至少 12 个字符' });
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
        pwMsg.textContent = '管理员密码已更新（Argon2id 慢哈希存储），其他所有登录会话已自动失效。';
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
      el('div', { class: 'field' }, el('label', { for: 'pw-current' }, '当前管理员密码'), curPw),
      el('div', { class: 'field' }, el('label', { for: 'pw-next' }, '新密码（12–256 字符）'), nextPw),
    ),
    el('div', { class: 'form-actions' },
      el('button', { type: 'submit', class: 'btn secondary btn-check icon-start' }, '更新密码并撤销其他会话'),
    ),
  );

  async function loadAudit() {
    const res = await api(`audit?q=${encodeURIComponent(auditState.q)}&page=${auditState.page}&size=${auditState.size}`);
    const items = res.items || [];
    auditMount.replaceChildren(
      items.length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'audit-cap' },
          el('table', { class: 'tbl-audit' },
            el('caption', { id: 'audit-cap' }, `安全审计记录（共 ${res.total} 条）`),
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, '时间'),
              el('th', { scope: 'col' }, '操作者'),
              el('th', { scope: 'col' }, '动作'),
              el('th', { scope: 'col' }, '目标'),
              el('th', { scope: 'col' }, '结果与说明'),
            )),
            el('tbody', {}, items.map(renderAuditRow)),
          ),
        )
        : el('div', { class: 'empty-state' }, '无匹配的安全审计记录。'),
    );
    const maxPage = Math.max(1, Math.ceil((res.total || 0) / auditState.size));
    auditPager.replaceChildren(
      el('span', { class: 'muted' }, `共 ${res.total} 条 · 第 ${res.page} / ${maxPage} 页`),
      el('div', { class: 'toolbar-row' },
        el('button', { type: 'button', class: 'btn secondary sm', disabled: auditState.page <= 1, onClick: () => { auditState.page--; loadAudit(); } }, '上一页'),
        el('button', { type: 'button', class: 'btn secondary sm', disabled: auditState.page >= maxPage, onClick: () => { auditState.page++; loadAudit(); } }, '下一页'),
      ),
    );
  }

  const auditSearch = el('input', {
    type: 'search', placeholder: '筛选动作、操作者或摘要…', 'aria-label': '筛选审计日志',
    onInput: () => { auditState.q = auditSearch.value.trim(); auditState.page = 1; loadAudit(); },
  });

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, '入网申请码、控制端委托与安全审计'),
        el('p', {}, '管理单次/限时申请码、控制端挑战签名 API 委托、Web 独立管理员密码及全量不可变审计记录。'),
      ),
      el('button', { type: 'button', class: 'btn primary btn-key icon-start', onClick: openCreateKeyModal }, '生成入网申请码'),
    ),
    newKeyBanner,
    el('section', { class: 'card form-stack' },
      el('h2', {}, '入网申请码台账'),
      keysMount,
    ),
    el('div', { class: 'split-grid' },
      el('section', { class: 'card form-stack' }, delegMount),
      el('section', { class: 'card form-stack' },
        el('h2', {}, '修改 Web 管理员密码'),
        el('p', { class: 'muted' }, 'Web 密码独立于控制端凭据与节点令牌，使用随机盐 Argon2id 慢哈希持久化存储。'),
        pwForm,
      ),
    ),
    el('section', { class: 'card form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('h2', {}, '关键操作安全审计'),
        searchBox(auditSearch),
      ),
      auditMount,
      auditPager,
    ),
  );

  await Promise.all([loadKeys(), loadDelegation(), loadAudit()]);
}
