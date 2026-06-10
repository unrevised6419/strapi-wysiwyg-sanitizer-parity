# Sanitizer parity check

Standalone differential harness comparing the **old `sanitize-html` config**
(removed in PR #26150) against the **new DOMPurify config** for the Wysiwyg
markdown preview. Self-contained — own `node_modules`, own git repo, isolated
from the Strapi monorepo lockfile. Throwaway / verification only; not shipped.

## Run

```bash
npm install
npm run compare      # exits non-zero on an unexpected diff or a live XSS leak in the new config
```

Both sanitizers get identical HTML (the shared `md.render` step is factored
out). Outputs are normalized through a common DOM serializer so cosmetic noise
(`<hr/>` vs `<hr>`, `controls` vs `controls=""`, `&nbsp;` vs the raw char)
collapses, leaving only semantic differences.

## Result (57 cases)

| bucket | count | meaning |
| --- | --- | --- |
| identical | 40 | byte-identical after normalization |
| expected diff | 15 | `class`/`title` now kept (intended); dangerous tags now stripped (security win) |
| **unexpected diff** | **2** | `data:image/*` inline images — see below |
| **live XSS in OLD** | **3** | `<script>`, two mXSS payloads — execute under old config, neutralized by new |
| live XSS in NEW | 0 | — |

## The one genuine behavioral divergence: `data:image/*`

DOMPurify special-cases `data:` URIs on media tags (`img`/`video`/`audio`/
`source`) via its internal mimetype-restricted allowlist, **independent of our
`ALLOWED_URI_REGEXP`**. So the new config permits inline images the old config
stripped:

| input | old | new |
| --- | --- | --- |
| `<img src="data:image/png;base64,…">` | stripped | **kept** |
| `<img src="data:image/svg+xml,…onload…">` | stripped | **kept** (inert — SVG via `<img>` can't run script) |
| `<img src="data:text/html,…">` | stripped | stripped (mimetype not in DOMPurify's safe list) |
| `<a href="data:text/html,…">` | stripped | stripped (`<a>` isn't a data-URI tag) |

Not a security regression — `data:text/html` is still blocked everywhere, and
`data:image/svg+xml` in an `<img>` is a non-active context. But it contradicts
the `sanitizer.ts` comment that implies all `data:` is blocked, and the unit
test only exercised `data:text/html`. Decide: accept + document (inline images
are a feature), or block all `data:` via an `uponSanitizeAttribute` hook to
match the old config exactly.

## Headline

The old config was **actively XSS-vulnerable** (raw `<script>` plus two mXSS
gadgets execute); the new config neutralizes all three. The migration is a
security upgrade, not a cosmetic swap.
