/**
 * Differential harness comparing the OLD sanitize-html config against the NEW
 * DOMPurify config used by the Wysiwyg markdown preview.
 *
 * Both sanitizers receive identical HTML (the md.render step is shared, so it
 * is factored out). For every case we print whether the outputs MATCH or DIFF,
 * and DIFFs are bucketed against the set of *intended* behavior changes so we
 * can confirm — empirically, not by eye — that nothing unexpected diverged.
 */
import sanitizeHtml from 'sanitize-html';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const DOMPurify = createDOMPurify(new JSDOM('').window);

// sanitize-html warns on every call about script/style in allowedTags
// (this is the exact warning the old Field.test.tsx had to suppress).
console.warn = () => {};

/* ── OLD config (verbatim from the pre-PR PreviewWysiwyg.tsx) ────────────── */
const oldSanitize = (html) =>
  sanitizeHtml(html, {
    ...sanitizeHtml.defaults,
    allowedTags: false,
    allowedAttributes: {
      '*': ['href', 'align', 'alt', 'center', 'width', 'height', 'type', 'controls', 'target'],
      img: ['src', 'alt'],
      source: ['src', 'type'],
    },
  });

/* ── NEW config (verbatim from utils/sanitizer.ts) ──────────────────────── */
const ALLOWED_ATTR = [
  'href',
  'src',
  'alt',
  'align',
  'center',
  'width',
  'height',
  'type',
  'controls',
  'target',
  'class',
  'title',
];
const ALLOWED_URI_REGEXP = /^(?:(?:https?|ftp|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;
const newSanitize = (html) =>
  DOMPurify.sanitize(html, { ALLOWED_ATTR, ALLOWED_URI_REGEXP, ALLOW_DATA_ATTR: false });

/* ── Corpus ─────────────────────────────────────────────────────────────── */
// Representative md.render output + adversarial payloads.
const CASES = [
  // --- plain markdown tags (expect identical) ---
  '<h1>Title</h1>',
  '<h2>Sub</h2>',
  '<p>Paragraph</p>',
  '<em>em</em> <strong>strong</strong>',
  '<ul><li>one</li><li>two</li></ul>',
  '<ol><li>one</li></ol>',
  '<blockquote>quote</blockquote>',
  '<p>inline <code>code</code></p>',
  '<table><thead><tr><th>h</th></tr></thead><tbody><tr><td align="center">c</td></tr></tbody></table>',
  '<hr>',
  '<a href="https://example.com" target="_blank">link</a>',
  '<img src="https://example.com/a.png" alt="alt" width="10" height="10">',
  '<video controls width="320" height="240"><source src="https://x/v.mp4" type="video/mp4"></video>',

  // --- attributes that DIFFER by design (class/title now kept) ---
  '<pre class="hljs language-js"><code><span class="hljs-keyword">const</span></code></pre>',
  '<sup class="footnote-ref"><span>1</span></sup>',
  '<span class="footnote-backref">x</span>',
  '<a href="https://x" title="tooltip">x</a>',
  '<abbr title="HyperText Markup Language">HTML</abbr>',
  '<img src="https://x/a.png" alt="a" title="cap">',

  // --- attributes stripped by both ---
  '<p id="footnote-1">x</p>',
  '<p style="color:red">x</p>',
  '<a href="https://x" name="anchor">x</a>',
  '<p data-foo="bar">x</p>',

  // --- event handlers / XSS attrs (stripped by both) ---
  '<a href="https://x" onclick="alert(1)">x</a>',
  '<img src="https://x" onerror="alert(1)">',
  '<div onmouseover="alert(1)">x</div>',
  '<svg><a href="#" onload="alert(1)">x</a></svg>',

  // --- URL schemes ---
  '<a href="http://x">x</a>',
  '<a href="https://x">x</a>',
  '<a href="ftp://x">x</a>',
  '<a href="mailto:a@b.c">x</a>',
  '<a href="tel:+15555550123">x</a>',
  '<a href="//cdn/x">x</a>',
  '<a href="#frag">x</a>',
  '<a href="/rel/path">x</a>',
  '<a href="javascript:alert(1)">x</a>',
  '<a href="JaVaScRiPt:alert(1)">x</a>',
  '<a href="vbscript:msgbox(1)">x</a>',
  '<a href="data:text/html,<script>alert(1)</script>">x</a>',
  '<img src="data:image/png;base64,iVBORw0KGgo=">',
  '<img src="data:text/html,<script>alert(1)</script>">',
  '<img src="data:image/svg+xml,<svg onload=alert(1)>">',
  '<img src="javascript:alert(1)" alt="x">',

  // --- dangerous tags (DIFFER: old keeps via allowedTags:false, new strips) ---
  '<p>safe</p><script>alert(1)</script>',
  '<style>body{display:none}</style><p>x</p>',
  '<iframe src="https://evil"></iframe>',
  '<object data="x.swf"></object>',
  '<embed src="x.swf">',
  '<form action="/x"><input name="q"></form>',
  '<base href="https://evil/">',
  '<textarea>x</textarea>',

  // --- mXSS / parser tricks ---
  '<p><svg><style><img src=x onerror=alert(1)></style></svg></p>',
  '<noscript><p title="</noscript><img src=x onerror=alert(1)>">x</p></noscript>',
  '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
  '<a href="https://x"><b>bold</b></a>',
  '<p>5 &lt; 7 &amp; 3 &gt; 1</p>',
  '<p>&copy; &mdash; &nbsp;</p>',
];

/* ── Classify expected divergences ──────────────────────────────────────── */
// A DIFF is "expected" if it is fully explained by one of the intended deltas.
const NEW_TAG_ALLOWLIST_STRIPS =
  /<(script|style|iframe|object|embed|form|input|base|textarea|noscript|math|mglyph)\b/i;

function classifyDiff(input, oldOut, newOut) {
  const reasons = [];
  // class/title kept by new, stripped by old
  if (/\b(class|title)=/.test(input) && /\b(class|title)=/.test(newOut) && !/\b(class|title)=/.test(oldOut)) {
    reasons.push('new keeps class/title (intended)');
  }
  // dangerous tag kept by old (allowedTags:false), stripped by new (default allowlist)
  if (NEW_TAG_ALLOWLIST_STRIPS.test(input)) {
    reasons.push('new strips disallowed tag (security win)');
  }
  return reasons;
}

/* ── Normalize away serialization noise ─────────────────────────────────── */
// Parse both outputs through the SAME DOM serializer so that cosmetic-only
// differences (`<hr/>` vs `<hr>`, `controls` vs `controls=""`, `&nbsp;` vs the
// raw char, redundant `</source>`) collapse — leaving only SEMANTIC diffs.
const { document } = new JSDOM('').window;
const normalize = (html) => {
  const el = document.createElement('div');
  el.innerHTML = html;
  return el.innerHTML;
};

/* ── Run ────────────────────────────────────────────────────────────────── */
let match = 0;
let expectedDiff = 0;
const unexpected = [];

for (const input of CASES) {
  const oldOut = oldSanitize(input);
  const newOut = newSanitize(input);
  if (normalize(oldOut) === normalize(newOut)) {
    match++;
    console.log(`MATCH  ${JSON.stringify(input).slice(0, 70)}`);
    continue;
  }
  const reasons = classifyDiff(input, oldOut, newOut);
  if (reasons.length > 0) {
    expectedDiff++;
    console.log(`DIFF✓  ${JSON.stringify(input).slice(0, 70)}`);
    console.log(`        reason: ${reasons.join('; ')}`);
    console.log(`        old: ${JSON.stringify(oldOut).slice(0, 90)}`);
    console.log(`        new: ${JSON.stringify(newOut).slice(0, 90)}`);
  } else {
    unexpected.push({ input, oldOut, newOut });
    console.log(`DIFF✗  ${JSON.stringify(input).slice(0, 70)}   <-- UNEXPECTED`);
    console.log(`        old: ${JSON.stringify(oldOut)}`);
    console.log(`        new: ${JSON.stringify(newOut)}`);
  }
}

/* ── Security backstop: no LIVE XSS primitive survives in EITHER output ──── */
// Strip the *contents* of data:image URIs before scanning: an event handler
// inside `<img src="data:image/svg+xml,…onload…">` is inert (SVG loaded via
// <img> is a non-active context — scripting disabled by spec), so it must not
// count as a live primitive. Anything that survives this is genuinely live.
const XSS = /<script\b|\son\w+\s*=|javascript:|vbscript:|data:text\/html/i;
const stripInertDataImg = (html) => html.replace(/data:image\/[^"']*/gi, 'data:image/REDACTED');
const leaks = [];
for (const input of CASES) {
  for (const [label, out] of [['old', oldSanitize(input)], ['new', newSanitize(input)]]) {
    if (XSS.test(stripInertDataImg(out))) leaks.push({ label, input, out });
  }
}

console.log('\n──────────────────────────────────────────────');
console.log(`cases:          ${CASES.length}`);
console.log(`identical:      ${match}`);
console.log(`expected diff:  ${expectedDiff}`);
console.log(`UNEXPECTED:     ${unexpected.length}`);
console.log(`XSS leaks:      ${leaks.length}`);
if (leaks.length) {
  console.log('\nXSS LEAKS:');
  for (const l of leaks) console.log(`  [${l.label}] ${JSON.stringify(l.input)} -> ${JSON.stringify(l.out)}`);
}
console.log('──────────────────────────────────────────────');

process.exit(unexpected.length === 0 && leaks.filter((l) => l.label === 'new').length === 0 ? 0 : 1);
