import {
  api, downloadFile, el, badge, callout, bindDropzone, copyableCode, fmtTime, toast, openModal, buildTabs,
} from './api.js';
import { confirmDiscardACL, renderACLEditor } from './acl_editor.js';
import { parsePolicySource, readPublicArtifact } from './artifacts.js';

function renderRuleTable(rules, captionText) {
  if (!rules || !rules.length) {
    return el('div', { class: 'empty-state' }, '当前无编译过滤规则（默认零信任拒绝未显式放行的跨节点业务流量）。');
  }
  return el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': captionText },
    el('table', { class: 'tbl-rules' },
      el('caption', {}, captionText),
      el('thead', {}, el('tr', {},
        el('th', { scope: 'col' }, '动作'),
        el('th', { scope: 'col' }, '协议'),
        el('th', { scope: 'col' }, '来源前缀'),
        el('th', { scope: 'col' }, '目标前缀'),
        el('th', { scope: 'col' }, '目的业务端口'),
      )),
      el('tbody', {}, rules.map((r) => el('tr', {},
        el('th', { scope: 'row' }, badge(r.action === 'accept' ? '放行 · accept' : '丢弃 · drop', r.action === 'accept' ? 'ok' : 'err')),
        el('td', {}, el('code', { class: 'chip' }, String(r.proto || '*').toUpperCase())),
        el('td', {}, el('div', { class: 'chip-list' }, ...(r.src || []).slice(0, 6).map((s) => el('code', { class: 'chip' }, s)),
          (r.src || []).length > 6 ? el('span', { class: 'muted' }, `+${r.src.length - 6} 项`) : null)),
        el('td', {}, el('div', { class: 'chip-list' }, ...(r.dst || []).slice(0, 6).map((d) => el('code', { class: 'chip' }, d)),
          (r.dst || []).length > 6 ? el('span', { class: 'muted' }, `+${r.dst.length - 6} 项`) : null)),
        el('td', {}, el('code', { class: 'chip' }, r.ports || '*')),
      ))),
    ),
  );
}

function renderDiffSummary(diff) {
  if (!diff) return el('p', { class: 'muted' }, '暂无差异信息。');
  const items = [];
  if (!diff.hasActive) {
    items.push(callout('', `当前中心尚无生效快照；签发发布后将首次准入 ${diff.added?.length || 0} 台成员、下发 ${diff.rulesAfter || 0} 条底层包过滤规则。`));
  } else {
    items.push(el('dl', { class: 'kv-grid' },
      el('div', {}, el('dt', {}, '＋ 新增准入成员'), el('dd', {}, diff.added?.length ? diff.added.map((m) => `${m.name} (${m.ipv4})`).join('、') : '无')),
      el('div', {}, el('dt', {}, '－ 移除（撤权）成员'), el('dd', {}, diff.removed?.length
        ? badge(diff.removed.map((m) => m.name).join('、'), 'err') : '无')),
      el('div', {}, el('dt', {}, '～ 属性变更成员'), el('dd', {}, diff.changed?.length
        ? diff.changed.map((c) => `${c.member.name} [${c.fields.join('/')}]`).join('、') : '无')),
      el('div', {}, el('dt', {}, '编译过滤规则变化'), el('dd', {}, diff.rulesSame
        ? `无变化（${diff.rulesAfter} 条）` : `${diff.rulesBefore} 条 → ${diff.rulesAfter} 条`)),
      el('div', {}, el('dt', {}, 'DNS / STUN 变更'), el('dd', {},
        `${diff.dnsChanged ? 'DNS 已变更' : 'DNS 未变'} · ${diff.stunChanged ? 'STUN 已变更' : 'STUN 未变'}`)),
    ));
  }
  return el('div', { class: 'form-stack' }, ...items);
}

function terminalSnippet(commandText, label = '复制终端命令') {
  const cmdId = `term-${Math.random().toString(36).slice(2, 9)}`;
  return el('div', { class: 'terminal-box' },
    el('div', { class: 'terminal-cmd' },
      el('span', { class: 'terminal-glyph icon', 'aria-hidden': 'true' }),
      el('code', { id: cmdId, dataset: { fullText: commandText } }, commandText),
    ),
    el('span', { class: 'copy' },
      el('button', { type: 'button', class: 'copy-button icon-start', command: '--copy', commandfor: cmdId, 'aria-label': label }, '复制'),
      el('span', { class: 'tip', role: 'status' }),
    ),
  );
}

export async function renderPolicy(container, navTo, refreshGlobal, initialDraftId = '') {
  const [activeData, draftsList] = await Promise.all([api('policy/active'), api('drafts')]);
  let selectedId = initialDraftId || draftsList[0]?.id || '';
  let workspaceSeq = 0;

  const draftSidebarMount = el('div', { class: 'draft-list' });
  const workspaceMount = el('div', { class: 'form-stack' });

  async function reloadSidebar() {
    const list = await api('drafts');
    if (!selectedId && list.length) selectedId = list[0].id;
    if (selectedId && !list.some((d) => d.id === selectedId)) selectedId = list[0]?.id || '';
    draftSidebarMount.replaceChildren(
      ...(list.length
        ? list.map((d) => el('button', {
          type: 'button',
          class: `draft-item${d.id === selectedId ? ' active' : ''}`,
          dataset: { draftId: d.id },
          'aria-pressed': d.id === selectedId ? 'true' : 'false',
          onClick: () => {
            if (selectedId === d.id || !confirmDiscardACL(workspaceMount)) return;
            selectedId = d.id;
            for (const button of draftSidebarMount.querySelectorAll('.draft-item')) {
              const selected = button.dataset.draftId === selectedId;
              button.classList.toggle('active', selected);
              button.setAttribute('aria-pressed', String(selected));
            }
            loadDraftWorkspace();
          },
        },
          el('div', { class: 'toolbar-row between' },
            el('strong', {}, d.name),
            d.valid ? badge('有效', 'ok') : badge('待修正', 'err'),
          ),
          el('span', { class: 'muted' }, `${d.members} 成员 · ${d.aclRules} 条 ACL`),
          d.baseStale ? badge('需核对变更', 'warn') : null,
        ))
        : [el('div', { class: 'empty-state' }, '尚无草稿，请点击右上角新建或导入。')]),
    );
    refreshGlobal();
  }

  async function loadDraftWorkspace(initialTab = 'acl', data = null) {
    const seq = ++workspaceSeq;
    const afterACLSave = data !== null;
    if (!selectedId) {
      workspaceMount.replaceChildren(
        el('section', { class: 'card form-stack' },
          el('h2', {}, '已发布的签名规则（只读）'),
          activeData.hasActive
            ? renderRuleTable(activeData.rules, '签名授权的包过滤规则')
            : el('div', { class: 'empty-state' }, '当前尚未发布任何已签策略。请点击右上角「新建草稿」开始编排成员与 ACL。'),
        ),
      );
      return;
    }

    const id = selectedId;
    if (!data) {
      workspaceMount.replaceChildren(el('p', { role: 'status', class: 'muted' }, '正在加载草稿工作台…'));
      try {
        data = await api(`drafts/${encodeURIComponent(id)}`);
      } catch (err) {
        if (seq === workspaceSeq) workspaceMount.replaceChildren(callout('error', err.message));
        return;
      }
    }
    if (seq !== workspaceSeq || id !== selectedId) return;
    const { draft, analysis } = data;
    const pol = draft.policy;

    const issuesNodes = (analysis.issues || []).map(({ level, message }) => {
      const text = level === 'warning' && analysis.baseStale
        ? message.replace(/^草稿基于 v\d+，当前生效的是 v\d+。/, '草稿建立后，生效策略已有更新。')
        : message;
      return callout(level === 'error' ? 'error' : 'warn', `${level === 'error' ? '校验错误：' : '核对提示：'}${text}`);
    });

    // Members & DNS/STUN
    const dnsEnable = el('input', { type: 'checkbox', checked: !!pol.dns?.enableMagicDNS });
    const dnsSuffix = el('input', { type: 'text', value: pol.dns?.magicDNSSuffix || 'ack.internal', placeholder: 'ack.internal' });
    const stun1 = el('input', { type: 'text', value: pol.stunAddr || '', placeholder: '字面量 IP:端口，如 203.0.113.10:3478' });
    const stun2 = el('input', { type: 'text', value: pol.stunAltAddr || '', placeholder: '可选辅助 STUN IP:端口' });

    const membersTab = el('div', { class: 'form-stack' },
      el('div', { class: 'toolbar-row between' },
        el('span', { class: 'muted' }, '可从「入网申请」核对设备公钥加入，或在此移除撤权成员。'),
        el('button', { type: 'button', class: 'btn secondary sm btn-plus icon-start', onClick: () => navTo('requests') }, '前往入网申请添加节点'),
      ),
      (pol.members || []).length
        ? el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-label': '草稿成员列表' },
          el('table', { class: 'tbl-members' },
            el('thead', {}, el('tr', {},
              el('th', { scope: 'col' }, 'ID'),
              el('th', { scope: 'col' }, '唯一名称'),
              el('th', { scope: 'col' }, '虚拟地址'),
              el('th', { scope: 'col' }, '节点公钥'),
              el('th', { scope: 'col' }, '标签与批准路由'),
              el('th', { scope: 'col' }, '操作'),
            )),
            el('tbody', {}, pol.members.map((m) => el('tr', {},
              el('th', { scope: 'row', class: 'mono' }, `#${m.id}`),
              el('td', {}, el('code', {}, m.name)),
              el('td', {}, el('code', {}, m.ipv4), m.ipv6 ? el('div', {}, el('code', {}, m.ipv6)) : null),
              el('td', {}, copyableCode(m.nodeKey, '复制成员公钥', true)),
              el('td', {},
                el('div', { class: 'chip-list' },
                  ...(m.tags || []).map((t) => el('code', { class: 'chip' }, t)),
                  ...(m.routes || []).map((rt) => el('code', { class: 'chip' }, rt)),
                ),
              ),
              el('td', {}, el('button', {
                 type: 'button', class: 'btn danger sm btn-trash icon-start',
                 onClick: async () => {
                   if (!confirmDiscardACL(workspaceMount)) return;
                   await api(`drafts/${encodeURIComponent(draft.id)}/members/${encodeURIComponent(m.nodeKey)}`, { method: 'DELETE' });
                   toast(`已从草稿移除成员 ${m.name}`);
                   reloadSidebar();
                   if (seq === workspaceSeq) loadDraftWorkspace('members');
                },
              }, '移除')),
            ))),
          ),
        )
        : el('div', { class: 'empty-state' }, '此草稿成员表为空。'),

      el('div', { class: 'card form-stack' },
        el('h3', {}, 'DNS 与签名 STUN 地址设置'),
        el('label', { class: 'checkbox-row' }, dnsEnable, el('span', {}, '启用内嵌 MagicDNS (100.100.100.100)')),
        el('div', { class: 'form-row' },
          el('div', { class: 'field' }, el('label', {}, 'MagicDNS 域名后缀'), dnsSuffix),
          el('div', { class: 'field' }, el('label', {}, '主 STUN (字面量 IP:端口)'), stun1),
          el('div', { class: 'field' }, el('label', {}, '辅助 STUN (字面量 IP:端口)'), stun2),
        ),
        el('div', { class: 'form-actions' },
          el('button', {
             type: 'button', class: 'btn primary sm btn-check icon-start',
             onClick: async () => {
               if (!confirmDiscardACL(workspaceMount)) return;
              const nextPol = structuredClone(pol);
              nextPol.dns = { enableMagicDNS: dnsEnable.checked, magicDNSSuffix: dnsSuffix.value.trim(), nameservers: pol.dns?.nameservers };
              nextPol.stunAddr = stun1.value.trim();
              nextPol.stunAltAddr = stun2.value.trim();
              await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'PUT', body: { policy: nextPol } });
               toast('DNS 与 STUN 设置已更新到草稿');
               reloadSidebar();
               if (seq === workspaceSeq) loadDraftWorkspace('members');
            },
          }, '保存 DNS / STUN 到草稿'),
        ),
      ),
    );

    const exportButtons = [];
    const pendingNotice = el('p', { class: 'callout warn', hidden: true }, 'ACL 有未保存的改动。请返回「ACL 规则」保存后再对比和导出。');
    const diffPreview = el('div', { class: 'form-stack' },
      renderDiffSummary(analysis.diff),
      renderRuleTable(analysis.rules, '待签发包过滤规则表'),
    );
    const aclTab = renderACLEditor(draft,
      analysis.valid
        ? renderRuleTable(analysis.rules, `编译后的包过滤规则（${analysis.rules.length} 条）`)
        : callout('warn', '草稿未通过校验，修正并保存后可查看编译结果。'),
      (saved) => {
        if (seq !== workspaceSeq || !workspaceMount.isConnected) return;
        toast('ACL 草稿已保存，当前授权未改变。');
        loadDraftWorkspace('acl', saved);
        reloadSidebar().catch((err) => toast(err.message));
      },
      (pending) => {
        pendingNotice.hidden = !pending;
        diffPreview.hidden = pending;
        for (const button of exportButtons) button.disabled = pending || !analysis.valid;
      });

    // Full policy.json editor & stateless check
    const fullEditor = el('textarea', { class: 'code-editor', spellcheck: 'false' }, JSON.stringify(pol, null, 2));
    const fullMsg = el('div', { hidden: true });
    const fullTab = el('div', { class: 'form-stack' },
      fullMsg,
      el('div', { class: 'field' },
        el('label', {}, '完整 policy.json 内容（包含 members、acl、dns、stunAddr）'),
        el('div', { class: 'editor-frame' },
          el('div', { class: 'editor-bar' },
            el('span', { class: 'mono' }, `${draft.id}-policy.json`),
            el('button', {
              type: 'button', class: 'btn ghost sm',
              onClick: () => {
                try { fullEditor.value = JSON.stringify(JSON.parse(fullEditor.value), null, 2); } catch (e) { toast('JSON 语法有误：' + e.message); }
              },
            }, '格式化 JSON'),
          ),
          fullEditor,
        ),
      ),
      el('div', { class: 'form-actions' },
        el('button', {
          type: 'button', class: 'btn secondary',
          onClick: async () => {
            try {
              const candidate = parsePolicySource(fullEditor.value);
              const res = await api('policy/validate', { method: 'POST', body: { policy: candidate, baseVersion: draft.baseVersion } });
              fullMsg.className = `callout ${res.valid ? 'ok' : 'error'} icon-start`;
              fullMsg.textContent = res.valid
                ? `预校验通过：将生成 ${res.rules?.length || 0} 条包过滤规则（提示数：${res.issues?.length || 0}）。`
                : '预校验未通过：' + (res.issues?.find((issue) => issue.level === 'error')?.message || '存在错误');
              fullMsg.hidden = false;
            } catch (err) {
              fullMsg.className = 'callout error icon-start';
              fullMsg.textContent = err.message;
              fullMsg.hidden = false;
            }
          },
        }, '仅预校验 JSON'),
        el('button', {
          type: 'button', class: 'btn primary btn-check icon-start',
          onClick: async () => {
             try {
               const candidate = parsePolicySource(fullEditor.value);
               if (!confirmDiscardACL(workspaceMount)) return;
               await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'PUT', body: { policy: candidate } });
               toast('完整策略草稿已保存');
               reloadSidebar();
               if (seq === workspaceSeq) loadDraftWorkspace('json');
            } catch (err) {
              fullMsg.className = 'callout error icon-start';
              fullMsg.textContent = err.message;
              fullMsg.hidden = false;
            }
          },
        }, '保存完整草稿'),
      ),
    );

    // Diff vs Active & Export for offline signing
    const signCmd = `acktier owner sign --dir ./data/owner --policy ./${draft.id}-policy.json --valid-for 168h`;
    const downloadDraft = async () => {
      try {
        await downloadFile(`drafts/${encodeURIComponent(draft.id)}/export`, `${draft.id}-policy.json`);
        toast('已导出待签 policy.json');
      } catch (err) {
        toast(err.message);
      }
    };
    const exportButton = (label, size = '') => {
      const button = el('button', {
        type: 'button', class: `btn primary ${size} btn-download icon-start`, disabled: !analysis.valid, onClick: downloadDraft,
      }, label);
      exportButtons.push(button);
      return button;
    };
    const diffTab = el('div', { class: 'form-stack' },
      pendingNotice,
      diffPreview,
      el('div', { class: 'card form-stack' },
        el('h3', {}, '导出待签文件并在所有者客户端离线签发'),
        el('p', { class: 'muted' }, '网页与中心服务器均无私钥签名能力。请导出下方 JSON，在所有者电脑核对成员公钥与变更后执行签名命令，再前往「签名发布」上传生成的 authorization.json：'),
        terminalSnippet(signCmd, '复制本地签名命令'),
        el('div', { class: 'form-actions' },
          exportButton('导出待签 policy.json'),
          el('button', { type: 'button', class: 'btn secondary btn-upload icon-start', onClick: () => navTo('publish') }, '前往上传 authorization.json'),
        ),
      ),
    );

    const tabs = buildTabs('策略草稿工作区', [
      { id: 'acl', title: 'ACL 规则', content: aclTab },
      { id: 'members', title: `成员与路由 (${pol.members?.length || 0})`, content: membersTab },
      { id: 'diff', title: '差异对比与导出', content: diffTab },
      { id: 'json', title: '完整策略 JSON', content: fullTab },
    ], initialTab);

    workspaceMount.replaceChildren(
      el('section', { class: 'card form-stack' },
        el('div', { class: 'toolbar-row between' },
          el('div', {},
            el('div', { class: 'toolbar-row' },
              el('h2', {}, draft.name),
              analysis.valid ? badge('校验通过', 'ok') : badge('存在错误', 'err'),
            ),
            el('span', { class: 'muted' }, `最后保存：${fmtTime(draft.updatedAt)}`),
          ),
          el('div', { class: 'toolbar-row' },
            exportButton('导出 policy.json', 'sm'),
            el('button', {
               type: 'button', class: 'btn danger sm btn-trash icon-start',
               onClick: async () => {
                 if (!confirmDiscardACL(workspaceMount)) return;
                 await api(`drafts/${encodeURIComponent(draft.id)}`, { method: 'DELETE' });
                selectedId = '';
                toast('草稿已删除');
                await reloadSidebar();
                loadDraftWorkspace();
              },
            }, '删除草稿'),
          ),
        ),
        ...issuesNodes,
        tabs.root,
      ),
    );
    if (afterACLSave) aclTab.querySelector('h3').focus({ preventScroll: true });
  }

  const importFullInput = el('input', {
    type: 'file', accept: '.json,application/json', hidden: true,
    onChange: async () => {
      const f = importFullInput.files?.[0];
      if (!f) return;
      try {
        if (f.size > 512 * 1024) throw new Error('策略文件过大（最多 512 KiB）。');
        const policy = parsePolicySource(await f.text());
        if (importFullInput.files?.[0] !== f) return;
        const created = await api('drafts', {
          method: 'POST',
          body: { name: f.name.replace(/\.json$/i, ''), policy },
        });
        selectedId = created.draft.id;
        toast('已导入完整 policy.json 为新草稿（尚未发布）');
        await reloadSidebar();
        loadDraftWorkspace();
      } catch (err) {
        if (importFullInput.files?.[0] === f) toast('导入失败：' + err.message);
      } finally {
        if (importFullInput.files?.[0] === f) importFullInput.value = '';
      }
    },
  });

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, 'ACL 与策略草稿编排'),
        el('p', {}, '在草稿中编辑访问规则和组网成员，核对差异后导出，交给所有者离线签发。'),
      ),
      el('div', { class: 'toolbar-row' },
        importFullInput,
        el('button', { type: 'button', class: 'btn secondary btn-upload icon-start',
          onClick: () => { if (confirmDiscardACL(workspaceMount)) importFullInput.click(); } }, '导入完整 policy.json'),
        el('button', {
          type: 'button', class: 'btn primary btn-plus icon-start',
          onClick: async () => {
            if (!confirmDiscardACL(workspaceMount)) return;
            try {
              const created = await api('drafts', { method: 'POST', body: { fromActive: true } });
              selectedId = created.draft.id;
              toast('已创建新策略草稿');
              await reloadSidebar();
              await loadDraftWorkspace();
            } catch (err) {
              toast(err.message);
            }
          },
        }, '新建草稿'),
      ),
    ),
    el('div', { class: 'draft-layout' },
      el('aside', { class: 'card form-stack' },
        el('h2', {}, '策略草稿列表'),
        draftSidebarMount,
      ),
      workspaceMount,
    ),
  );

  await reloadSidebar();
  await loadDraftWorkspace();
}

export async function renderPublish(container, navTo, refreshGlobal) {
  const previewMount = el('div', {});
  const uploadAlert = el('div', { id: 'auth-upload-alert', class: 'callout error icon-start', role: 'alert', hidden: true });
  const historyMount = el('div', {});
  let stagedEnvelope = null;
  let previewSeq = 0;

  const publishBtn = el('button', {
    type: 'button', class: 'btn primary btn-check icon-start', disabled: true,
    onClick: async () => {
      if (!stagedEnvelope || publishBtn.disabled) return;
      publishBtn.disabled = true;
      fileInput.disabled = true;
      try {
        const res = await api('authorization', { method: 'POST', body: stagedEnvelope });
        toast(res.idempotent ? '这份授权已发布，无需重复提交。' : '签名授权已发布。');
        stagedEnvelope = null;
        publishBtn.disabled = true;
        previewMount.replaceChildren(callout('ok', '签名授权已持久化，在线节点将收到更新。'));
        refreshGlobal();
        loadHistory();
      } catch (err) {
        previewMount.replaceChildren(callout('error', err.message));
      } finally {
        fileInput.disabled = false;
        publishBtn.disabled = !stagedEnvelope;
      }
    },
  }, '确认验证并发布到全网');

  const uploadTitle = '点击选择或拖拽已签 authorization.json 到此处';
  const uploadHint = '中心校验签名、组网指纹和有效期，拒绝旧快照，原样保存签名文件。';
  const dzTitle = el('span', { class: 'dropzone-title' }, uploadTitle);
  const dzSub = el('span', { class: 'dropzone-sub' }, uploadHint);

  const fileInput = el('input', {
    type: 'file', id: 'auth-upload-input', accept: '.json,application/json', 'aria-describedby': 'auth-upload-alert',
    onChange: async () => {
      const seq = ++previewSeq;
      const f = fileInput.files?.[0];
      stagedEnvelope = null;
      publishBtn.disabled = true;
      previewMount.replaceChildren();
      uploadAlert.hidden = true;
      fileInput.removeAttribute('aria-invalid');
      if (!f) return;
      try {
        const env = await readPublicArtifact(f, 'authorization');
        if (seq !== previewSeq) return;
        const prev = await api('authorization/preview', { method: 'POST', body: env });
        if (seq !== previewSeq) return;
        if (!prev.valid) {
          dropzone.classList.remove('has-file');
          previewMount.replaceChildren(
            callout('error', el('strong', {}, '授权检查未通过：'), prev.reason || '未知错误'),
            ...(prev.authorization ? [renderDiffSummary(prev.diff)] : []),
          );
          return;
        }
        stagedEnvelope = env;
        publishBtn.disabled = false;
        const auth = prev.authorization;
        previewMount.replaceChildren(
          el('div', { class: 'preview-card form-stack' },
            el('div', { class: 'toolbar-row' },
              badge('Ed25519 签名验证通过', 'ok'),
              prev.idempotent ? badge('与已发布授权相同', 'neutral') : null,
            ),
            el('dl', { class: 'kv-grid' },
              el('div', {}, el('dt', {}, '快照摘要'), el('dd', {}, copyableCode(auth.digest, '复制快照摘要', true))),
              el('div', {}, el('dt', {}, '到期时间'), el('dd', {}, fmtTime(auth.expiresAt))),
              el('div', {}, el('dt', {}, '成员数 / 过滤规则数'), el('dd', {}, `${auth.members} 台成员 · ${auth.rules} 条规则`)),
            ),
            renderDiffSummary(prev.diff),
          ),
        );
      } catch (err) {
        if (seq !== previewSeq) return;
        dropzone.classList.remove('has-file');
        fileInput.setAttribute('aria-invalid', 'true');
        uploadAlert.textContent = err.message;
        uploadAlert.hidden = false;
      }
    },
  });

  const dropzone = el('div', { class: 'dropzone' },
    fileInput,
    el('span', { class: 'dropzone-glyph icon', 'aria-hidden': 'true' }),
    el('div', { class: 'dropzone-copy' }, dzTitle, dzSub),
  );
  bindDropzone(dropzone, fileInput, dzTitle, dzSub, uploadTitle, uploadHint);

  async function inspectPublication(version) {
    const detail = await api(`authorization/history/${version}`);
    openModal('签名授权详情', el('div', { class: 'form-stack' },
      callout('', '发布记录仅供核对，不能恢复旧的授权快照。'),
      el('dl', { class: 'kv-grid' },
        el('div', {}, el('dt', {}, '摘要'), el('dd', {}, copyableCode(detail.digest, '复制历史摘要', true))),
        el('div', {}, el('dt', {}, '发布时间'), el('dd', {}, fmtTime(detail.publishedAt))),
        el('div', {}, el('dt', {}, '到期时间'), el('dd', {}, fmtTime(detail.expiresAt))),
      ),
      renderRuleTable(detail.rules, `包过滤规则（${detail.rules?.length || 0} 条）`),
    ));
  }

  async function loadHistory() {
    const list = await api('authorization/history');
    if (!list.length) {
      historyMount.replaceChildren(el('div', { class: 'empty-state' }, '尚无已发布的签名历史记录。'));
      return;
    }
    historyMount.replaceChildren(
      el('div', { class: 'table-wrapper', tabindex: '0', role: 'region', 'aria-labelledby': 'hist-cap' },
        el('table', { class: 'tbl-history' },
          el('caption', { id: 'hist-cap' }, `签名授权记录（共 ${list.length} 条）`),
          el('thead', {}, el('tr', {},
            el('th', { scope: 'col' }, '发布时间'),
            el('th', { scope: 'col' }, '快照摘要'),
            el('th', { scope: 'col' }, '成员 / 规则'),
            el('th', { scope: 'col' }, '到期时间与状态'),
            el('th', { scope: 'col' }, '操作'),
          )),
          el('tbody', {}, list.map((h) => el('tr', {},
            el('th', { scope: 'row' }, el('time', { datetime: h.publishedAt }, fmtTime(h.publishedAt))),
            el('td', {}, copyableCode(h.digest, '复制摘要', true)),
            el('td', {}, `${h.members} 成员 / ${h.rules} 规则`),
            el('td', {},
              el('time', { datetime: h.expiresAt }, fmtTime(h.expiresAt)), ' ',
              h.expired ? badge('已过期', 'err') : h.active ? badge('当前生效', 'ok') : badge('历史记录', 'neutral'),
            ),
            el('td', {}, el('button', {
              type: 'button', class: 'btn secondary sm',
              'aria-label': `查看快照：${fmtTime(h.publishedAt)}发布`,
              onClick: () => inspectPublication(h.version),
            }, '查看快照')),
          ))),
        ),
      ),
    );
  }

  container.replaceChildren(
    el('div', { class: 'page-head' },
      el('div', {},
        el('h1', {}, '签名授权发布'),
        el('p', {}, '上传所有者离线签发的 authorization.json，由中心验签并原样分发。'),
      ),
      el('button', { type: 'button', class: 'btn secondary', onClick: () => navTo('policy') }, '返回策略草稿工作台'),
    ),
    el('section', { class: 'card form-stack' },
      el('h2', {}, '上传并验签 authorization.json'),
      el('div', { class: 'field' },
        el('label', { for: 'auth-upload-input' }, '已签授权封套文件 authorization.json'),
        dropzone,
      ),
      uploadAlert,
      previewMount,
      el('div', { class: 'form-actions' }, publishBtn),
    ),
    el('section', { class: 'card form-stack' },
      el('h2', {}, '发布记录'),
      historyMount,
    ),
  );
  await loadHistory();
}
