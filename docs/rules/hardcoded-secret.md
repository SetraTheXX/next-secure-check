# secrets/hardcoded-secret

## Description
Detects hardcoded API keys, tokens, and passwords in source code files.

## Why is this a problem?
Hardcoding secrets directly into source code makes them easily discoverable by anyone who can read the code. If the code is pushed to a public repository or shared, the secrets are compromised. Even in private repositories, it violates the principle of least privilege and makes secret rotation difficult.

## How to fix
1. Move the secret value to an environment variable (e.g., `process.env.MY_SECRET_KEY`).
2. Ensure the environment variable is loaded securely on the server side.
3. Rotate the exposed secret immediately, as it should be considered compromised.