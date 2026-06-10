/**
 * The two sanitizers under comparison, plus shared helpers.
 *
 *   oldSanitize — verbatim pre-PR sanitize-html config from PreviewWysiwyg.tsx
 *   newSanitize — verbatim DOMPurify config from utils/sanitizer.ts
 *
 * Run under vitest's jsdom environment, so DOMPurify binds to the global window
 * and `document` is available for output normalization.
 */
import sanitizeHtml from 'sanitize-html';
import DOMPurify from 'dompurify';

// sanitize-html warns on every call about script/style in allowedTags
// (the exact warning the old Field.test.tsx had to suppress).
console.warn = () => {};

/* ── OLD config ─────────────────────────────────────────────────────────── */
export const oldSanitize = (html) =>
  sanitizeHtml(html, {
    ...sanitizeHtml.defaults,
    allowedTags: false,
    allowedAttributes: {
      '*': ['href', 'align', 'alt', 'center', 'width', 'height', 'type', 'controls', 'target'],
      img: ['src', 'alt'],
      source: ['src', 'type'],
    },
  });

/* ── NEW config ─────────────────────────────────────────────────────────── */
const ALLOWED_ATTR = [
  'href', 'src', 'alt', 'align', 'center', 'width', 'height',
  'type', 'controls', 'target', 'class', 'title',
];
const ALLOWED_URI_REGEXP = /^(?:(?:https?|ftp|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;
export const newSanitize = (html) =>
  DOMPurify.sanitize(html, { ALLOWED_ATTR, ALLOWED_URI_REGEXP, ALLOW_DATA_ATTR: false });

/* ── Helpers ────────────────────────────────────────────────────────────── */
const parse = (html) => {
  const el = document.createElement('div');
  el.innerHTML = html;
  return el;
};

// Parse through the DOM serializer so cosmetic-only differences (`<hr/>` vs
// `<hr>`, `controls` vs `controls=""`, `&nbsp;` vs the raw char, redundant
// `</source>`) collapse, leaving only semantic differences.
export const normalize = (html) => parse(html).innerHTML;

// The set of REAL attribute names in the markup — parsed via the DOM, not a
// regex, so `=` characters inside an attribute *value* (e.g. an event handler
// embedded in a `data:` URI string) are never mistaken for attributes.
export const attrSet = (html) => {
  const names = new Set();
  for (const node of parse(html).querySelectorAll('*')) {
    for (const attr of node.attributes) names.add(attr.name.toLowerCase());
  }
  return names;
};

// A LIVE XSS primitive, detected structurally against the parsed DOM:
//   - a <script> element, or
//   - any on* event-handler attribute, or
//   - a script-pseudo-scheme (javascript:/vbscript:/…) in ANY URL attribute, or
//   - data:text/html in a NAVIGABLE attribute (href/action/…). In a resource
//     attribute (`<img src>`) it is inert — non-active context, no execution.
// This is precise: a handler inside a `data:image/svg+xml` URI is inert, and a
// leading-backtick `href` is a relative URL (not a javascript: scheme) — neither
// is flagged.
const URL_ATTRS = new Set([
  'href', 'src', 'xlink:href', 'action', 'formaction', 'data', 'background', 'poster',
]);
const NAVIGABLE_ATTRS = new Set(['href', 'xlink:href', 'action', 'formaction']);
const CONTROL_WS = /[\x00-\x20]+/g;
const SCRIPT_SCHEME = /^(?:javascript|vbscript|livescript|mocha):/;
export const hasLiveXss = (html) => {
  const root = parse(html);
  if (root.querySelector('script')) return true;
  for (const node of root.querySelectorAll('*')) {
    for (const attr of node.attributes) {
      const name = attr.name.toLowerCase();
      if (name.startsWith('on')) return true;
      if (URL_ATTRS.has(name)) {
        const value = attr.value.replace(CONTROL_WS, '').toLowerCase();
        if (SCRIPT_SCHEME.test(value)) return true;
        if (NAVIGABLE_ATTRS.has(name) && value.startsWith('data:text/html')) return true;
      }
    }
  }
  return false;
};

// Attribute names NEW keeps that OLD strips, for a given input. Used to
// characterize where the two configs diverge (class/title, aria-*, data: media).
export const extraAttrsKeptByNew = (html) => {
  const oldAttrs = attrSet(oldSanitize(html));
  return [...attrSet(newSanitize(html))].filter((a) => !oldAttrs.has(a));
};
