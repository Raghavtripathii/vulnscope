# Locked scope

Decided in Phase 0. Do not expand without team agreement — scope creep is the main risk on a semester timeline.

## Vulnerability classes in scope

- SQL injection
- Cross-site scripting (XSS)
- Hardcoded secrets / credentials
- Broken authentication

## Languages in scope

- Python
- JavaScript

## Explicitly out of scope

- Any other language (C/C++, Java, Go, etc.)
- Binary analysis
- Executing submitted code (static analysis only — this matters for the platform's own security)
- Zero-day discovery claims
- Adversarial robustness testing (considered, rejected — see docs/literature/related-work.md)

## Datasets under evaluation (finalize in Phase 1)

- CVEfixes — multi-language, includes Python/JS subsets
- Big-Vul — C/C++, used for cross-checking against LineVul's and Zou et al.'s reported numbers

## Base paper and implementation reference

- Base paper (cited, research framing): Zou et al. (2025), Scientific Reports 15:39301
- Implementation reference (what the code actually follows): Fu & Tantithamthavorn (2022), LineVul, MSR 2022

## Paper format

Target: IEEE conference paper format, SCOPUS-indexed venue (confirm exact CFP by Week 6).