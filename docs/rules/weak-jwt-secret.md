# secrets/weak-jwt-secret

## Description
Detects the use of weak, default, or easily guessable values for JWT (JSON Web Token) secrets.

## Why is this a problem?
JWTs are often used for authentication and authorization. If the secret used to sign the token is weak (e.g., "secret", "123456", "test"), an attacker can easily brute-force the secret offline. Once the secret is known, the attacker can forge valid tokens and impersonate any user in the system.

## How to fix
1. Generate a strong, high-entropy secret (at least 32 bytes / 256 bits). You can use `crypto.randomBytes(32).toString('hex')` in Node.js.
2. Store the secret in an environment variable, never in the source code.
3. Rotate the weak secret and invalidate any existing sessions/tokens.