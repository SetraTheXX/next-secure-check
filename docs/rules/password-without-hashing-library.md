# auth/password-without-hashing-library

## Description
Detects password handling logic that does not use a strong, modern hashing library like `bcrypt` or `argon2`.

## Why is this a problem?
Storing passwords in plaintext, or using fast/weak hashing algorithms (like MD5, SHA-1, or even SHA-256 without a salt), allows attackers to easily recover the original passwords if the database is compromised. Modern hardware can crack billions of weak hashes per second.

## How to fix
1. Never store or compare plaintext passwords.
2. Use a purpose-built password hashing library like `bcrypt` or `argon2`.
3. These libraries automatically handle salting and use intentionally slow algorithms to thwart brute-force attacks.