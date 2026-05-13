# auth/login-without-rate-limit

## Description
Detects authentication endpoints (like `/api/login`, `/api/auth`) that do not appear to implement rate limiting.

## Why is this a problem?
Authentication endpoints are prime targets for brute-force and credential stuffing attacks. If an attacker can submit thousands of login requests per minute without being blocked, they have a high chance of guessing weak passwords or using leaked credentials from other breaches to compromise user accounts.

## How to fix
1. Implement rate limiting on all authentication endpoints.
2. Use a library like `@upstash/ratelimit` (with Redis) or a similar robust solution.
3. Limit requests based on the client's IP address and the targeted username/email.
4. Consider implementing account lockout mechanisms after a certain number of failed attempts.