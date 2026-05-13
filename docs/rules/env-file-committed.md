# secrets/env-file-committed

## Description
Detects if `.env`, `.env.local`, `.env.development`, or `.env.production` files are committed to the repository.

## Why is this a problem?
Environment files often contain sensitive information such as database passwords, API keys, and secret tokens. Committing these files to a version control system exposes them to anyone who has access to the repository, leading to potential data breaches and unauthorized access.

## How to fix
1. Remove the `.env` file from git tracking: `git rm --cached .env`
2. Add `.env` and related files to your `.gitignore`.
3. Rotate any secrets that were exposed in the committed file.
4. Use a `.env.example` file to show required variables without actual values.