import { describe, it, expect } from 'vitest';

import {
  oldSanitize,
  newSanitize,
  normalize,
  hasLiveXss,
  extraAttrsKeptByNew,
} from './sanitizers.mjs';
import {
  SAFE_MARKDOWN,
  CLASS_TITLE_KEPT,
  DATA_IMAGE_KEPT,
  DISALLOWED_ATTRS,
  ARIA_KEPT,
  SAFE_SCHEMES,
  BAD_SCHEMES,
  DANGEROUS_TAGS,
  ALL,
} from './corpus.mjs';

const label = (s) => JSON.stringify(s).slice(0, 80);
const each = (arr) => arr.map((c) => [label(c), c]);

/* ════════════════════════════════════════════════════════════════════════
 * HARD INVARIANTS — these must hold for the migration to be safe.
 * ════════════════════════════════════════════════════════════════════════ */

describe('SECURITY: the new DOMPurify config leaks no live XSS primitive', () => {
  it.each(each(ALL))('clean output for %s', (_l, html) => {
    expect(hasLiveXss(newSanitize(html))).toBe(false);
  });
});

describe('SECURITY: the new config keeps no dangerous attribute the old one stripped', () => {
  // The only attributes new may keep that old removed are inert: class, title,
  // aria-*, and `src` carrying an inline data: media URI. Anything else (an
  // event handler, a navigable script scheme) would be a regression.
  const INERT = (a) => a === 'class' || a === 'title' || a.startsWith('aria-') || a === 'src';
  it.each(each(ALL))('no dangerous extra attr for %s', (_l, html) => {
    expect(extraAttrsKeptByNew(html).filter((a) => !INERT(a))).toEqual([]);
  });
});

/* ════════════════════════════════════════════════════════════════════════
 * PARITY — where the two configs are expected to agree exactly.
 * ════════════════════════════════════════════════════════════════════════ */

describe('PARITY: safe markdown output is byte-identical', () => {
  it.each(each(SAFE_MARKDOWN))('identical for %s', (_l, html) => {
    expect(normalize(newSanitize(html))).toBe(normalize(oldSanitize(html)));
  });
});

describe('PARITY: disallowed attributes stripped by both', () => {
  it.each(each(DISALLOWED_ATTRS))('both strip %s', (_l, html) => {
    expect(normalize(newSanitize(html))).toBe(normalize(oldSanitize(html)));
  });
});

describe('PARITY: URL scheme decisions agree', () => {
  it.each(SAFE_SCHEMES.map((s) => [s, s]))('both keep safe scheme %s', (_l, scheme) => {
    const html = `<a href="${scheme}">x</a>`;
    expect(normalize(newSanitize(html))).toBe(normalize(oldSanitize(html)));
  });

  it.each(each(BAD_SCHEMES))('both strip dangerous scheme %s', (_l, scheme) => {
    const html = `<a href="${scheme}">x</a>`;
    expect(hasLiveXss(newSanitize(html))).toBe(false);
    expect(hasLiveXss(oldSanitize(html))).toBe(false);
  });
});

/* ════════════════════════════════════════════════════════════════════════
 * CHARACTERIZATION — documented, intentional differences between the configs.
 * ════════════════════════════════════════════════════════════════════════ */

describe('DIFF (intended): new keeps class and title, old stripped them', () => {
  it.each(each(CLASS_TITLE_KEPT))('keeps class/title for %s', (_l, html) => {
    const newOut = newSanitize(html);
    const oldOut = oldSanitize(html);
    for (const attr of ['class', 'title']) {
      const re = new RegExp(`\\b${attr}=`);
      if (re.test(html)) {
        expect(re.test(newOut)).toBe(true);
        expect(re.test(oldOut)).toBe(false);
      }
    }
  });
});

describe('DIFF (finding): new lets aria-* through, old stripped it', () => {
  // DOMPurify ALLOW_ARIA_ATTR defaults to true, independent of ALLOWED_ATTR.
  // Inert, but if exact parity is wanted the new config should set
  // ALLOW_ARIA_ATTR: false.
  it.each(each(ARIA_KEPT))('aria kept by new, dropped by old for %s', (_l, html) => {
    expect(/\saria-/.test(newSanitize(html))).toBe(true);
    expect(/\saria-/.test(oldSanitize(html))).toBe(false);
  });
});

describe('DIFF (finding): new keeps data: media URIs, old stripped all data:', () => {
  // DOMPurify permits data: on media tags (img/source/video/audio) regardless
  // of ALLOWED_URI_REGEXP. Inert in those non-active contexts; old stripped all.
  it.each(each(DATA_IMAGE_KEPT))('data: kept by new, dropped by old for %s', (_l, html) => {
    expect(/src="data:/.test(newSanitize(html))).toBe(true);
    expect(/src="data:/.test(oldSanitize(html))).toBe(false);
  });

  it('data:text/html in a NAVIGABLE attr is still blocked by both', () => {
    const html = '<a href="data:text/html,<script>alert(1)</script>">l</a>';
    expect(hasLiveXss(newSanitize(html))).toBe(false);
    expect(hasLiveXss(oldSanitize(html))).toBe(false);
  });
});

describe('DIFF (security win): old config emits executable gadgets new strips', () => {
  // Old's serialized output still carries a <script> element or an on* handler —
  // directly executable, or activatable via browser mXSS mutation for the
  // foreign-content (svg/math) cases. New removes the gadget entirely.
  const GADGET = /<script\b|\son\w+\s*=/i;
  const KNOWN_OLD_HOLES = [
    '<p>safe</p><script>alert(1)</script>',
    '<p><svg><style><img src=x onerror=alert(1)></style></svg></p>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>',
  ];
  it.each(each(KNOWN_OLD_HOLES))('old carries gadget, new strips it: %s', (_l, html) => {
    expect(GADGET.test(oldSanitize(html))).toBe(true);
    expect(GADGET.test(newSanitize(html))).toBe(false);
    expect(hasLiveXss(newSanitize(html))).toBe(false);
  });
});

describe('DIFF (intended): dangerous tags stripped by new (kept by old)', () => {
  it.each(each(DANGEROUS_TAGS))('new yields no live xss for %s', (_l, html) => {
    expect(hasLiveXss(newSanitize(html))).toBe(false);
  });
});
