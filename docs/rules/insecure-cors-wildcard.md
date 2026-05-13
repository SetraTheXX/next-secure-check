# config/insecure-cors-wildcard

## Description
Detects the use of a wildcard (`*`) in the `Access-Control-Allow-Origin` CORS header.

## Why is this a problem?
Setting the CORS origin to `*` allows any website on the internet to make cross-origin requests to your API and read the responses. While this might be intended for public APIs, it is highly dangerous for APIs that handle sensitive user data or require authentication. It completely disables the browser's Same-Origin Policy for that endpoint.

## How to fix
1. Replace the wildcard `*` with the specific, trusted domain(s) that need access to the API (e.g., `https://www.my-frontend.com`).
2. If you need to support multiple dynamic origins, validate the incoming `Origin` header against a strict whitelist on the server side before reflecting it back in the `Access-Control-Allow-Origin` header.