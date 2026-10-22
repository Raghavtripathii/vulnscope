# VulnScope

Automated Source Code Vulnerability Assessment and Pedagogical Feedback Platform Using Hybrid Static Analysis and Fine-Tuned Transformer Models

BCA Sem 5 Minor Project — School of Computer Application and Technology, Galgotias University, Odd 2026-27
Project ID: BCA3092 | Guide: Mr. Rama Shankar Yadav

## Team

- Raghvendra Tripathi — 24131040520 — dataset, classical ML + CodeBERT fine-tuning, evaluation
- Ayush Mishra — 24131040195 — frontend, pedagogical layer, dashboards
- Deepanshu Rishi — 24131040232 — backend, orchestration, deployment, CI/CD

## What this is 

Most static analyzers only catch known rule patterns, and most AI code assistants explain vulnerabilities without verifying they're real. This project combines three detection layers — rule-based static analysis, a classical ML classifier, and a fine-tuned CodeBERT model — compares them head-to-head on Python/JavaScript web vulnerabilities (SQL injection, XSS, hardcoded secrets, broken authentication), and uses only verified findings to drive a pedagogical layer that teaches the developer why their code is vulnerable and how to fix it.

## Research

- **Outcome:** Project + Research Paper, target SCOPUS conference, IEEE paper format
- **Base paper (cited):** Zou et al. (2025), "Code vulnerability detection based on augmented program dependency graph and optimized CodeBERT," Scientific Reports 15:39301 — https://www.nature.com/articles/s41598-025-23029-4
- **Implementation reference:** Fu & Tantithamthavorn (2022), "LineVul: A Transformer-based Line-Level Vulnerability Prediction," MSR 2022
- **Related work and locked scope:** see [docs/literature/related-work.md](docs/literature/related-work.md) and [docs/scope.md](docs/scope.md)

## Structure

```
vulnscope/
├── backend/       FastAPI service: detection pipeline, auth, API
├── frontend/      Next.js app: editor, findings, learner/teacher dashboards
├── ml/            dataset prep, classical ML baseline, CodeBERT fine-tuning, evaluation
├── docs/          literature review, scope, paper drafts
└── docker-compose.yml
```

## Status

Phase 0 — foundations.

## License

MIT — see [LICENSE](LICENSE).