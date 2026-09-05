# next-secure-check brand mark

The primary mark is the checkpoint gate in [`../assets/next-secure-check-mark.svg`](../assets/next-secure-check-mark.svg). Two balanced code boundaries are joined by one scan rail, with a small negative-space checkpoint at the center. The shape communicates “inspect before release” without borrowing the usual shield, padlock, or checkmark silhouette.

## Usage

- Use signal green (`#B7FF63`) on near black (`#090B0D`), or use a single dark version on a plain light background.
- Keep the mark at 24 px or larger and preserve its square view box.
- Keep clear space around the mark equal to the width of one outer rail.
- Pair the mark with the lowercase wordmark `next-secure-check`; the wordmark is the primary identifier at small sizes.
- Use the campaign line **One command before deploy.** in launch materials.

The SVG is intentionally dependency-free and deterministic, so the same mark renders consistently in the README, CLI-facing material, and campaign video. Do not stretch it, add a gradient, rotate it, or place it inside a stock shield or badge.

## What the mark avoids

The geometry deliberately avoids a shield, checkmark, padlock, eye, magnifier, lightning bolt, triangle, terminal prompt, mascot, diagonal slash, and decorative gradient. It does not use or modify the Next.js or Vercel marks. `next-secure-check` is an independent tool; Next.js is referenced only to describe the supported project type.

GPT Imagine was used for a three-direction exploration sheet. Generic search, shield, and magnifier directions were rejected; the checkpoint-gate idea was then redrawn as deterministic SVG geometry. This provenance describes the design process and is not a claim of legal ownership or clearance.

## Preliminary collision screen — 2026-09-05

This screen checks public search surfaces for obvious direct collisions. It is evidence for design and naming decisions, not a trademark opinion, registration, or guarantee that no similar mark exists.

| Surface | Query | Observed result | Reading |
| --- | --- | --- | --- |
| [EUIPO eSearch](https://euipo.europa.eu/eSearch/) | `next-secure-check` | 0 trade marks, 0 designs, 0 owners, 0 representatives | No direct EUIPO record was returned for the exact hyphenated form. |
| [EUIPO eSearch](https://euipo.europa.eu/eSearch/) | `nextsecurecheck` | 0 trade marks, 0 designs, 0 owners, 0 representatives | No direct EUIPO record was returned for the closed form. |
| [USPTO Trademark Search](https://tmsearch.uspto.gov/search/search-information) — General search | `next-secure-check` | “No results found” | No exact full-string result was returned in the checked general-search view. |
| USPTO Wordmark search | `next-secure-check` | Broad tokenized results, including partial “SECURE” and “NEXT” marks | These are component or semantic neighbors, not proof of an exact collision. |
| Public web and image index | exact product name and the mark’s SVG path | No unrelated exact hit observed; generic code/security imagery is common | The geometry appears independently drawn, while the category language is shared. |

The USPTO Wordmark view expands the query into its component words, so its large result count must not be read as a count of direct conflicts. A full legal clearance should still search the relevant word, design, and phonetic variants in every target market and class. For this developer tool, counsel should confirm the relevant Nice classes; classes 009 and 042 are plausible starting points, not a legal classification decision.

Before paid advertising or a trademark application:

1. Ask trademark counsel to run a full clearance search, including design-mark similarity and phonetic variants.
2. Search the final campaign artwork at the actual display sizes and reserve the matching domains and social handles.
3. Keep this dated screen and the final SVG hash as provenance; repeat the screen before registration or a major rebrand.

## Source asset

- [`next-secure-check-mark.svg`](../assets/next-secure-check-mark.svg) — canonical vector mark.
- [`next-secure-check-banner-v3.svg`](../assets/next-secure-check-banner-v3.svg) — campaign/README banner using the mark.
