/**
 * Test corpus. `SAFE_MARKDOWN` is the subset the two sanitizers must treat
 * identically (representative markdown-it output). `ALL` is everything,
 * including adversarial payloads, used for the security + permissiveness
 * invariants.
 */

/* ── Safe markdown-it output — must be byte-identical after normalization ── */
export const SAFE_MARKDOWN = [
  '<h1>h1</h1>', '<h2>h2</h2>', '<h3>h3</h3>', '<h4>h4</h4>', '<h5>h5</h5>', '<h6>h6</h6>',
  '<p>paragraph</p>', '<p>a<br>\nb</p>', '<hr>',
  '<blockquote>\n<p>quote</p>\n</blockquote>',
  '<ul>\n<li>one</li>\n<li>two</li>\n</ul>',
  '<ol>\n<li>one</li>\n</ol>',
  '<ul>\n<li>a\n<ul>\n<li>nested</li>\n</ul>\n</li>\n</ul>',
  '<dl>\n<dt>term</dt>\n<dd>def</dd>\n</dl>',
  '<p><em>em</em> <strong>strong</strong> <s>strike</s> <code>code</code></p>',
  '<p><mark>mark</mark> <ins>ins</ins> <sub>sub</sub> <sup>sup</sup></p>',
  '<pre><code>plain\nblock</code></pre>',
  '<table>\n<thead>\n<tr>\n<th>h1</th>\n<th align="right">h2</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>a</td>\n<td align="center">b</td>\n</tr>\n</tbody>\n</table>',
  '<p>“curly” — dashes… ©</p>',
  '<p>plain text only</p>', '', '   ', 'bare text no tags',
  '<a href="https://x" target="_blank">x</a>',
  '<img src="https://x/a.png" alt="a" width="10" height="10">',
  '<video controls width="320" height="240"><source src="https://x/v.mp4" type="video/mp4"></video>',
  '<p align="left">l</p>',
  '<td align="center" width="50" height="20">cell</td>',
  '<a href="https://x?a=1&amp;b=2">x</a>',
  '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>',
  '<p>5 &lt; 7 &amp; 3 &gt; 1</p>',
  '<b><i><u>deep</u></i></b>',
  '<p></p><p></p>', '<br><br><br>',
];

/* ── Attributes NEW keeps over OLD (class/title) — documented diff ────────── */
export const CLASS_TITLE_KEPT = [
  '<pre class="hljs language-js"><code><span class="hljs-keyword">const</span></code></pre>',
  '<sup class="footnote-ref"><span>1</span></sup>',
  '<span class="footnote-backref">x</span>',
  '<a href="https://x" title="t">x</a>',
  '<abbr title="HyperText Markup Language">HTML</abbr>',
  '<img src="https://x/a.png" alt="a" title="cap">',
  '<div class="x y z">multi</div>',
];

/* ── data:image — NEW keeps, OLD strips (documented divergence) ───────────── */
export const DATA_IMAGE_KEPT = [
  '<img src="data:image/png;base64,iVBORw0KGgo=">',
  '<img src="data:image/gif;base64,R0lGOD">',
  '<img src="data:image/svg+xml,<svg onload=alert(1)>">',
  '<img src="data:image/svg+xml;base64,PHN2Zz4=">',
  '<source src="data:video/mp4;base64,AAA" type="video/mp4">',
];

/* ── Disallowed attributes (stripped by BOTH) ─────────────────────────────── */
export const DISALLOWED_ATTRS = [];
for (const [tag, attr] of [
  ['p', 'id="x"'], ['p', 'style="color:red"'], ['a', 'name="n"'], ['p', 'data-foo="b"'],
  ['p', 'role="button"'], ['p', 'tabindex="1"'],
  ['p', 'contenteditable="true"'], ['img', 'srcset="x 1x"'], ['img', 'loading="lazy"'],
  ['a', 'rel="noopener"'], ['a', 'download="f"'], ['a', 'ping="https://t"'],
  ['a', 'referrerpolicy="unsafe-url"'], ['p', 'lang="en"'], ['p', 'dir="rtl"'],
  ['p', 'spellcheck="false"'], ['col', 'span="2"'], ['th', 'scope="col"'],
]) {
  DISALLOWED_ATTRS.push(`<${tag} ${attr}>x</${tag}>`);
}

/* ── aria-* — NEW keeps (ALLOW_ARIA_ATTR defaults true), OLD strips ────────── */
// Finding: DOMPurify lets aria-* through regardless of the ALLOWED_ATTR list.
export const ARIA_KEPT = [
  '<p aria-label="a">x</p>',
  '<a href="https://x" aria-hidden="true">x</a>',
  '<div aria-describedby="d" aria-live="polite">x</div>',
];

/* ── URL schemes ──────────────────────────────────────────────────────────── */
export const SAFE_SCHEMES = [
  'http://x', 'https://x', 'ftp://x', 'mailto:a@b.c', 'tel:+15555550123',
  '//cdn/x', '#frag', '/abs/path', 'rel/path', '?q=1', 'HTTPS://X', 'MailTo:a@b.c',
];
export const BAD_SCHEMES = [
  'javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'javascript&#58;alert(1)',
  '&#106;avascript:alert(1)', '&#x6a;avascript:alert(1)', 'java\tscript:alert(1)',
  'java\nscript:alert(1)', ' javascript:alert(1)', 'java script:alert(1)',
  'vbscript:msgbox(1)', 'livescript:x', 'mocha:x', 'view-source:x', 'jar:x',
  'data:text/html,<script>alert(1)</script>', 'data:text/html;base64,PHNjcmlwdD4=',
  'blob:https://x/uuid', 'file:///etc/passwd', 'about:blank',
];

/* ── Dangerous tags (OLD keeps via allowedTags:false, NEW strips) ─────────── */
export const DANGEROUS_TAGS = [
  '<script>alert(1)</script>', '<script src="https://e/x.js"></script>',
  '<style>body{display:none}</style>', '<style>@import "https://e/x.css"</style>',
  '<iframe src="https://e"></iframe>', '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  '<object data="x.swf"></object>', '<embed src="x.swf">',
  '<form action="/x"><input name="q"><button>go</button></form>',
  '<base href="https://e/">', '<link rel="stylesheet" href="https://e/x.css">',
  '<meta http-equiv="refresh" content="0;url=https://e">',
  '<textarea>x</textarea>', '<select><option>o</option></select>',
  '<details open ontoggle="alert(1)">d</details>',
  '<marquee onstart="alert(1)">m</marquee>',
  '<template><img src=x onerror=alert(1)></template>',
  '<noscript><p>x</p></noscript>', '<noembed><img src=x></noembed>',
  '<title>t</title>', '<head><meta></head>', '<html><body>x</body></html>',
  '<isindex>', '<keygen>', '<frameset><frame></frameset>',
  '<button type="button" onclick="alert(1)">b</button>',
  '<svg><script>alert(1)</script></svg>',
  '<svg><animate onbegin="alert(1)"></animate></svg>',
  '<svg><set onbegin="alert(1)"></set></svg>',
  '<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>',
  '<math><maction actiontype="statusline#https://x" xlink:href="javascript:alert(1)">click</maction></math>',
];

/* ── Event handlers across tags (stripped by both) ────────────────────────── */
const HANDLERS = [
  'onclick', 'onerror', 'onload', 'onmouseover', 'onmouseenter', 'onfocus', 'onblur',
  'oninput', 'onchange', 'onsubmit', 'onanimationstart', 'ontransitionend', 'ontoggle',
  'onpointerover', 'onbeforetoggle', 'oncopy', 'onscroll', 'onwheel',
];
export const EVENT_HANDLERS = [];
for (const h of HANDLERS) {
  EVENT_HANDLERS.push(`<div ${h}="alert(1)">x</div>`, `<img src="https://x" ${h}="alert(1)">`);
}
EVENT_HANDLERS.push(
  '<img src=x onerror=alert(1)>',
  '<img src="x" onerror=alert(1)//>',
  '<input autofocus onfocus=alert(1)>',
  '<body onload=alert(1)>x</body>',
  '<svg onload=alert(1)>',
  '<a href=# onclick=alert(1)>x</a>',
  '<p onclick=alert(1) onmouseover=alert(2)>x</p>',
);

/* ── mXSS / parser-confusion (cure53 classics) ────────────────────────────── */
export const MXSS = [
  '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
  '<noscript><p title="</noscript><img src=x onerror=alert(1)>">x</p></noscript>',
  '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>',
  '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
  '<p><svg><style><img src=x onerror=alert(1)></style></svg></p>',
  '<select><style><img src=x onerror=alert(1)></style></select>',
  '<table><caption><svg><foreignObject><iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>',
  '<xmp><img src=x onerror=alert(1)></xmp>',
  '<![CDATA[<img src=x onerror=alert(1)>]]>',
  '<!-- --><img src=x onerror=alert(1)>',
  '<!--><img src=x onerror=alert(1)>',
  '<!-- --!><img src=x onerror=alert(1)>',
  '<style><!--</style><img src=x onerror=alert(1)>',
  '<title><img src=x onerror=alert(1)></title>',
  '<textarea><img src=x onerror=alert(1)></textarea>',
  '<iframe><img src=x onerror=alert(1)></iframe>',
  '<svg><desc><![CDATA[</desc><img src=x onerror=alert(1)>]]></svg>',
];

/* ── Case / whitespace / quoting tricks ───────────────────────────────────── */
export const OBFUSCATION = [
  '<SCRIPT>alert(1)</SCRIPT>', '<ScRiPt>alert(1)</ScRiPt>',
  '<IMG SRC="https://x">', '<Img Src=https://x>',
  '<a\nhref="https://x"\ntarget="_blank">x</a>',
  '<a href = "https://x" >x</a>',
  '<img src=https://x alt=noquotes>',
  '<a href="javascript:alert(1)" >x</a>',
  '<a href=`javascript:alert(1)`>x</a>',
  '<DIV ONCLICK="alert(1)">x</DIV>',
];

/* ── Everything, for the security + permissiveness invariants ─────────────── */
export const ALL = [
  ...SAFE_MARKDOWN, ...CLASS_TITLE_KEPT, ...DATA_IMAGE_KEPT, ...DISALLOWED_ATTRS, ...ARIA_KEPT,
  ...SAFE_SCHEMES.flatMap((s) => [`<a href="${s}">x</a>`, `<img src="${s}">`]),
  ...BAD_SCHEMES.flatMap((s) => [`<a href="${s}">x</a>`, `<img src="${s}" alt="x">`]),
  ...DANGEROUS_TAGS, ...EVENT_HANDLERS, ...MXSS, ...OBFUSCATION,
];
