# config/next-powered-by-header

- **Rule ID:** `config/next-powered-by-header`
- **Severity:** INFO
- **Confidence:** MEDIUM
- **Category:** config

## What it detects
Detects if `poweredByHeader` is not explicitly set to `false` in `next.config.js` for a Next.js project. By default, Next.js includes an `X-Powered-By: Next.js` header in HTTP responses.

## Why it matters
The `X-Powered-By: Next.js` header advertises which framework your application is built with. While not a vulnerability on its own, this header:

- Helps attackers narrow down the tech stack for targeted exploits
- Provides reconnaissance information that can be used to find framework-specific CVEs
- Violates the security principle of reducing information leakage
- Is unnecessary for normal application functionality

Hiding framework fingerprints is a basic security hardening step recommended by OWASP.

## Example

**Vulnerable `next.config.js`:**
```javascript
// next.config.js
module.exports = {
  // poweredByHeader defaults to true when not set
};
```

**Secure `next.config.js`:**
```javascript
// next.config.js
module.exports = {
  poweredByHeader: false, // ✅ Hides the X-Powered-By header
};
```

## Recommendation
Set `poweredByHeader: false` in your `next.config.js` to remove the `X-Powered-By: Next.js` header from production responses.

```javascript
module.exports = {
  poweredByHeader: false,
};
```

## False positive note
- **Non-Next.js projects:** This rule only fires for projects detected as Next.js. If the project detector misidentifies the framework, the finding may be a false positive.
- **Internal tooling:** For internal applications behind a VPN, this finding is very low priority. The header provides convenience at a minimal security cost.
- **Proxy layer:** If you strip the header at a reverse proxy (Nginx, CDN, etc.), the finding can be safely ignored as it is already mitigated at the infrastructure level.
