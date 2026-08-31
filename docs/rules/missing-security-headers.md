# headers/missing-security-headers

## Rule ID

`headers/missing-security-headers`

## Severity and confidence

- Severity: LOW
- Confidence: LOW

## Description

Detects missing common security-header configuration in recognized Next.js
`headers()` functions and `middleware`/`proxy` response header setters. It
reviews Content-Security-Policy, frame protection, X-Content-Type-Options,
Referrer-Policy, and Permissions-Policy.

## Why is this a problem?
Security headers instruct the browser on how to behave when handling your application's content. Missing headers leave the application vulnerable to various client-side attacks:
- **Clickjacking**: Without `X-Frame-Options` or CSP `frame-ancestors`, attackers can embed your site in an iframe to trick users into clicking things they didn't intend to.
- **MIME Sniffing**: Without `X-Content-Type-Options`, browsers might incorrectly interpret files, leading to XSS.
- **XSS**: Without a Content Security Policy (CSP), it's easier for attackers to execute malicious scripts.

## How to fix
Add a `headers()` function to your `next.config.js`, `.cjs`, `.mjs`, or `.ts`
config, or set headers in a
recognized `middleware.ts`/`proxy.ts` response path. Configure the policy for
your application rather than copying a universal CSP without review.

```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          // Add a Content-Security-Policy (CSP) tailored to your app
        ],
      },
    ];
  },
};
```

## Evidence and limitations

The analyzer records only static header names and bounded evidence paths; it
does not include raw header values in findings. Dynamic header names/values,
reverse-proxy or hosting headers, runtime response behavior, and complete CSP
correctness are outside the check. A finding is a review signal, not proof that
every response omits a header.
