# headers/missing-security-headers

## Description
Detects if standard HTTP security headers are missing from the `next.config.js` or `next.config.mjs` file.

## Why is this a problem?
Security headers instruct the browser on how to behave when handling your application's content. Missing headers leave the application vulnerable to various client-side attacks:
- **Clickjacking**: Without `X-Frame-Options` or CSP `frame-ancestors`, attackers can embed your site in an iframe to trick users into clicking things they didn't intend to.
- **MIME Sniffing**: Without `X-Content-Type-Options`, browsers might incorrectly interpret files, leading to XSS.
- **XSS**: Without a Content Security Policy (CSP), it's easier for attackers to execute malicious scripts.

## How to fix
Add a `headers()` function to your `next.config.js` to apply security headers to all routes.

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