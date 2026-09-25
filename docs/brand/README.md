# SecureCheck brand guide

The primary mark is the checkpoint gate in [`../assets/next-secure-check-mark.svg`](../assets/next-secure-check-mark.svg). Two balanced code boundaries are joined by one scan rail, with a small negative-space checkpoint at the center. The shape communicates “inspect before release” without borrowing the usual shield, padlock, or checkmark silhouette.

## Display name and technical identifiers

Use **SecureCheck** as the display name in public-facing copy. The repository, npm package, CLI command, GitHub Action, and rule IDs retain their existing identifiers, including `next-secure-check` and `@v1`.

The campaign line “AI wrote your Next.js app. Who checks the AI?” is a question about the review workflow. SecureCheck does not detect whether code was written by AI. The same checks apply to AI-generated and human-written code.

The preliminary collision screen below searched the literal name `next-secure-check`. It did not clear the display name SecureCheck and is not legal trademark advice.

## Usage

- Use signal green (`#B7FF63`) on near black (`#090B0D`), or use a single dark version on a plain light background.
- Keep the mark at 24 px or larger and preserve its square view box.
- Keep clear space around the mark equal to the width of one outer rail.
- Pair the mark with the display name **SecureCheck**. Use `next-secure-check` where readers need the exact package or command identifier.
- Use the campaign line **AI wrote your Next.js app. Who checks the AI?** with the supporting description **A deterministic security baseline for AI-generated and human-written Next.js code.**

The SVG is intentionally dependency-free and deterministic, so the same mark renders consistently in the README, CLI-facing material, and campaign video. Do not stretch it, add a gradient, rotate it, or place it inside a stock shield or badge.

The README uses responsive text and the compact mark in its first screen. Keep the wide campaign banner as a supporting asset so its smaller copy is not the only place where the product description appears.

## What the mark avoids

The geometry deliberately avoids a shield, checkmark, padlock, eye, magnifier, lightning bolt, triangle, terminal prompt, mascot, diagonal slash, and decorative gradient. It does not use or modify the Next.js or Vercel marks. `next-secure-check` is an independent tool; Next.js is referenced only to describe the supported project type.

GPT Imagine was used for a three-direction exploration sheet. Generic search, shield, and magnifier directions were rejected; the checkpoint-gate idea was then redrawn as deterministic SVG geometry. This provenance describes the design process and is not a claim of legal ownership or clearance.

## Preliminary collision screen (2026-09-05)

This screen checks public search surfaces for obvious direct collisions. It is evidence for design and naming decisions, not a trademark opinion, registration, or guarantee that no similar mark exists.

| Surface | Query | Observed result | Reading |
| --- | --- | --- | --- |
| [EUIPO eSearch](https://euipo.europa.eu/eSearch/) | `next-secure-check` | 0 trade marks, 0 designs, 0 owners, 0 representatives | No direct EUIPO record was returned for the exact hyphenated form. |
| [EUIPO eSearch](https://euipo.europa.eu/eSearch/) | `nextsecurecheck` | 0 trade marks, 0 designs, 0 owners, 0 representatives | No direct EUIPO record was returned for the closed form. |
| [USPTO Trademark Search](https://tmsearch.uspto.gov/search/search-information), general search | `next-secure-check` | “No results found” | No exact full-string result was returned in the checked general-search view. |
| USPTO Wordmark search | `next-secure-check` | Broad tokenized results, including partial “SECURE” and “NEXT” marks | These are component or semantic neighbors, not proof of an exact collision. |
| Public web and image index | exact product name and the mark’s SVG path | No unrelated exact hit observed; generic code/security imagery is common | The geometry appears independently drawn, while the category language is shared. |

The USPTO Wordmark view expands the query into its component words, so its large result count must not be read as a count of direct conflicts. A full legal clearance should still search the relevant word, design, and phonetic variants in every target market and class. For this developer tool, counsel should confirm the relevant Nice classes; classes 009 and 042 are plausible starting points, not a legal classification decision.

Before paid advertising or a trademark application:

1. Ask trademark counsel to run a full clearance search, including design-mark similarity and phonetic variants.
2. Search the final campaign artwork at the actual display sizes and reserve the matching domains and social handles.
3. Keep this dated screen and the final SVG hash as provenance; repeat the screen before registration or a major rebrand.

## Source asset

- [`next-secure-check-mark.svg`](../assets/next-secure-check-mark.svg): canonical vector mark.
- [`next-secure-check-banner-v3.svg`](../assets/next-secure-check-banner-v3.svg): campaign banner using the mark and current display name.
