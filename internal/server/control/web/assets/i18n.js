import { chineseMessages } from './messages_zh_cn.js';

const storageKey = 'acktier-console-language';
const supported = new Set(['en', 'zh-CN']);

function currentLanguage() {
  if (typeof window === 'undefined') return 'en';
  const requested = new URL(window.location.href).searchParams.get('lang');
  if (supported.has(requested)) return requested;
  try {
    const saved = window.localStorage.getItem(storageKey);
    if (supported.has(saved)) return saved;
  } catch {
    // The language in the URL still works when browser storage is unavailable.
  }
  return 'en';
}

export const language = currentLanguage();

function localized(message) {
  return language === 'zh-CN' && Object.hasOwn(chineseMessages, message)
    ? chineseMessages[message]
    : message;
}

function interpolate(message, values) {
  if (values.length === 0) return message;
  return message.replace(/\{(\d+)\}/g, (slot, index) => values[index] ?? slot);
}

export function translateMessage(message, ...values) {
  return interpolate(localized(message), values);
}

const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function translateHTMLMessage(message, ...escapedValues) {
  // View templates already escape their dynamic values. Escape the catalog text
  // before inserting those values.
  const safeMessage = localized(message).replace(/[&<>"']/g, char => htmlEntities[char]);
  return interpolate(safeMessage, escapedValues);
}

export function applyDocumentLanguage() {
  document.documentElement.lang = language;
  for (const element of document.querySelectorAll('[data-i18n]')) {
    for (const child of element.childNodes) {
      if (child.nodeType !== Node.TEXT_NODE) continue;
      const key = child.data.trim();
      if (key) child.data = child.data.replace(key, () => translateMessage(key));
    }
  }
  for (const element of document.querySelectorAll('[data-i18n-attrs]')) {
    for (const attr of element.dataset.i18nAttrs.split(' ')) {
      element.setAttribute(attr, translateMessage(element.getAttribute(attr)));
    }
  }
  for (const selector of document.querySelectorAll('[data-language-select]')) {
    selector.value = language;
  }
}

export function navigateWithLanguage(next) {
  if (!supported.has(next) || next === language) return;
  try {
    window.localStorage.setItem(storageKey, next);
  } catch {
    // Keep the choice in the URL when storage is unavailable.
  }
  const url = new URL(window.location.href);
  url.searchParams.set('lang', next);
  window.location.replace(url);
}
