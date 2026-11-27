import { translateMessage } from './i18n.js';
import { translateCenterMessage } from './center_messages.js';
import { el, badge, fmtTime } from './api.js';

export function renderAuditRow({ at, actor, action, target = '', result, detail = '' }) {
  // Leave the stored audit intact. Hide only the server-generated snapshot references.
  const subject = action === 'authorization.publish' && /^v\d+$/.test(target) ? translateMessage("Authorization snapshot") : target;
  const note = action.startsWith('draft.') ? detail.replace(/^base=v\d+(?: +|$)/, '') : detail;
  return el('tr', {},
    el('th', { scope: 'row', class: 'mono' }, fmtTime(at)),
    el('td', {}, actor || '—'),
    el('td', {}, el('code', { class: 'chip' }, action)),
    el('td', {}, subject ? el('code', { class: 'breakable' }, subject) : '—'),
    el('td', {}, badge(result === 'success' ? translateMessage("Success") : translateMessage("Failure"), result === 'success' ? 'ok' : 'err'), note ? ` ${translateCenterMessage(note)}` : ''),
  );
}
