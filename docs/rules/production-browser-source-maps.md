# config/production-browser-source-maps

- **Rule ID:** `config/production-browser-source-maps`
- **Severity:** LOW
- **Confidence:** HIGH
- **Category:** config

## What it detects
Detects if `productionBrowserSourceMaps` is set to `true` in `next.config.js`, `next.config.mjs`, `next.config.cjs`, or `next.config.ts`.

## Why it matters
When `productionBrowserSourceMaps` is enabled, the full source code (including comments, logic, and internal structure) is served to browser devtools in production. This exposure:

- Reveals internal application logic and business rules
- Makes reverse engineering significantly easier for attackers
- Can leak hardcoded URLs, API endpoints, or comments with sensitive information
- Increases attack surface by providing detailed knowledge of how your app works

While source maps are essential for debugging in development, exposing them in production is a best-practice security hardening concern.

## Example

**Vulnerable `next.config.js`:**
```javascript
// next.config.js
module.exports = {
  productionBrowserSourceMaps: true, // 🔴 Exposes source maps in production
};
```

**Secure `next.config.js`:**
```javascript
// next.config.js
module.exports = {
  productionBrowserSourceMaps: false, // ✅ Disabled (or simply omitted, as false is the default)
};
```

## Recommendation
Set `productionBrowserSourceMaps: false` in `next.config.js`, or simply omit it (the default is `false`).

Only enable it if you have a deliberate, documented need to allow public inspection of your production frontend source code.

## False positive note
- **Default behavior:** If `productionBrowserSourceMaps` is not explicitly set, this rule will **not** trigger — only explicit `true` declarations are flagged.
- **Deliberate use:** Some projects intentionally expose source maps for transparency or debugging purposes (e.g., open-source apps). In those cases, this finding can be safely ignored.
