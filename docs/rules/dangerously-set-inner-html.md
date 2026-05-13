# xss/dangerously-set-inner-html

## Description
Detects the usage of the `dangerouslySetInnerHTML` prop in React components.

## Why is this a problem?
React normally escapes HTML to prevent Cross-Site Scripting (XSS) attacks. However, `dangerouslySetInnerHTML` bypasses this protection and renders raw HTML directly into the DOM. If the HTML content includes untrusted user input, an attacker can inject malicious JavaScript that will execute in the victim's browser.

## How to fix
1. Avoid using `dangerouslySetInnerHTML` whenever possible. Use standard React components and state to render content.
2. If you must render raw HTML (e.g., from a Markdown parser or rich text editor), you **must** sanitize the HTML string using a proven library like `DOMPurify` before passing it to `dangerouslySetInnerHTML`.