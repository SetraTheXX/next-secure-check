# xss/dangerously-set-inner-html

## Description
Detects the usage of the `dangerouslySetInnerHTML` prop in React components.

The current syntax-aware check focuses on JSX attributes whose `__html` value is a variable or member expression, such as `post.content` or `userInput`. Normal JSX text, unrelated props, and static literal HTML are not treated as the same untrusted-content signal. Recognized sanitizer calls are handled conservatively and should still be reviewed in context.

## Why is this a problem?
React normally escapes HTML to prevent Cross-Site Scripting (XSS) attacks. However, `dangerouslySetInnerHTML` bypasses this protection and renders raw HTML directly into the DOM. If the HTML content includes untrusted user input, an attacker can inject malicious JavaScript that will execute in the victim's browser.

## How to fix
1. Avoid using `dangerouslySetInnerHTML` whenever possible. Use standard React components and state to render content.
2. If you must render raw HTML (e.g., from a Markdown parser or rich text editor), you **must** sanitize the HTML string using a proven library like `DOMPurify` before passing it to `dangerouslySetInnerHTML`.

This refinement reduces metadata and static-literal noise compared with the earlier broad text matcher, while keeping variable/member-expression usage visible. It does not perform source tracking or prove that a value is user-controlled; findings remain review signals rather than proof of exploitation.
