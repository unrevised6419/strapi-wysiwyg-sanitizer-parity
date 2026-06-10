# Wysiwyg sanitizer parity

Differential test suite comparing the **old `sanitize-html` config** (removed in
[strapi/strapi#26150](https://github.com/strapi/strapi/pull/26150)) against the
**new DOMPurify config** for the Content-Manager Wysiwyg markdown preview.

Self-contained — its own `package.json`, lockfile and git repo, isolated from
the Strapi monorepo. Verification only; nothing here ships.

The goal: prove the two sanitizers behave equivalently **in practice, not at
first glance** — and pin down every place they intentionally differ.

## Run

```bash
npm ci
npm test          # vitest run
```

CI runs the same on every push/PR — see [`.github/workflows/test.yml`](.github/workflows/test.yml).

## Method

`sanitizers.mjs` holds both configs verbatim:

- `oldSanitize` — the exact pre-PR `sanitize-html` options (`allowedTags: false`,
  the `*`/`img`/`source` attribute allowlist, `sanitize-html` defaults for
  schemes).
- `newSanitize` — the exact `utils/sanitizer.ts` DOMPurify options
  (`ALLOWED_ATTR`, `ALLOWED_URI_REGEXP`, `ALLOW_DATA_ATTR: false`).

Both receive **identical HTML** — the shared `md.render` step is factored out, so
only the sanitizer varies. Three precautions keep the comparison honest:

1. **Normalization.** Outputs are re-serialized through a common DOM
   (`normalize`) so cosmetic-only noise — `<hr/>` vs `<hr>`, `controls` vs
   `controls=""`, `&nbsp;` vs the raw char, redundant `</source>` — collapses.
   Only semantic diffs remain.
2. **DOM-based detection.** Attribute extraction and XSS detection parse the DOM
   rather than regex-matching strings, so an `=` inside a `data:` URI value, or a
   `javascript` substring that is not at scheme position, is never miscounted.
3. **Live-primitive definition.** `hasLiveXss` flags a `<script>` element, any
   `on*` handler, a script pseudo-scheme (`javascript:` …) in any URL attribute,
   or `data:text/html` in a **navigable** attribute. A handler embedded in a
   `data:image/svg+xml` URI loaded via `<img>` is treated as inert — correctly,
   since that is a non-active context.

The corpus (`corpus.mjs`, **230 inputs**) covers markdown-it output, every
allowed/disallowed attribute, the full URL-scheme matrix with obfuscations
(mixed case, entities, embedded control chars), a 31-entry dangerous-tag
battery, 43 event-handler placements, and 17 cure53 mXSS/parser-confusion
classics. **593 test cases**, all green.

## Report

### Parity holds where it should
- All safe markdown-it output is **byte-identical** after normalization.
- All disallowed attributes (`id`, `style`, `name`, `data-*`, `role`,
  `tabindex`, `rel`, `srcset`, …) are stripped by **both**.
- The URL-scheme allow/deny decision **agrees** across both for the entire
  scheme matrix, including every obfuscation tried.

### Intended differences (this PR's design)
- **`class` / `title` are now kept** (old stripped them) — restores highlight.js
  code-block styling, footnote styling, and link/abbr tooltips.
- **Dangerous tags are now stripped** — `script`, `style`, `iframe`, `object`,
  `embed`, `form`, `base`, `meta`, `noscript`, plus SVG/MathML script vectors.
  Old kept them all via `allowedTags: false`.

### Security: the migration is an upgrade, empirically
Three inputs leave an **executable gadget** in the old config's output —
directly (`<script>`) or via browser mXSS mutation (the `svg/style` and
`math/mglyph` foreign-content classics). The new config strips all three.
**Zero** live-XSS primitives survive the new config across all 230 inputs.

### Two findings the new config is *more permissive* than the old (both inert)
The suite flags these as documented divergences, not failures — neither is an
XSS vector, but each makes the new config looser than the old and looser than
its own `ALLOWED_ATTR` list implies:

1. **`aria-*` attributes pass through.** DOMPurify's `ALLOW_ARIA_ATTR` defaults
   to `true`, independent of `ALLOWED_ATTR`. Old stripped all `aria-*`.
   → For exact parity, set `ALLOW_ARIA_ATTR: false` in `sanitizer.ts`.
2. **`data:` URIs survive on media tags.** DOMPurify permits `data:` on
   `img`/`source`/`video`/`audio` regardless of `ALLOWED_URI_REGEXP` — this
   includes `data:image/*`, `data:image/svg+xml`, and even
   `data:text/html;base64` on `<img>` (inert there). Old stripped **all**
   `data:`. `data:text/html` in a navigable attribute (`<a href>`) is still
   blocked by both.
   → Accept (inline images are a feature) or block via an
   `uponSanitizeAttribute` hook for strict parity.

## Files

| file | purpose |
| --- | --- |
| `sanitizers.mjs` | the two configs + DOM-based helpers |
| `corpus.mjs` | 230 categorized test inputs |
| `parity.test.mjs` | invariants + parity + characterization tests |
| `vitest.config.mjs` | jsdom environment (DOMPurify needs a DOM) |
