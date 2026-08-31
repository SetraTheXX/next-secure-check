# config/next-image-domains

- **Rule ID:** `config/next-image-domains`
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Category:** config

## What it detects

Flags a static host entry under `images.domains` in a supported Next.js
`next.config.js`, `.cjs`, `.mjs`, or `.ts` file. This is the broad host-only
configuration; `images.remotePatterns` is the constrained alternative.

## Why it matters

`images.domains` does not express protocol, port, or pathname constraints. A
narrower image source policy makes the allowed remote image surface easier to
review and reduces accidental trust in an entire host configuration.

## Example

Broad configuration:

```js
// next.config.js
module.exports = {
  images: {
    domains: ["cdn.example.com"]
  }
};
```

Constrained configuration:

```js
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "cdn.example.com",
        pathname: "/assets/**"
      }
    ]
  }
};
```

## Privacy and limitations

Evidence identifies the static `images.domains` property but omits configured
host values. Dynamic config, computed objects, empty arrays, and runtime image
policy are not resolved. A broad host may be intentional, so this is a
configuration-hardening review signal rather than proof of an exploitable
image vulnerability.

## Recommendation

Replace `images.domains` with `images.remotePatterns` and constrain protocol,
hostname, port, and pathname to the smallest required set.

## References

- [Next.js `remotePatterns`](https://nextjs.org/docs/app/api-reference/components/image#remotepatterns)
- [Next.js unconfigured host guidance](https://nextjs.org/docs/messages/next-image-unconfigured-host)
