# Related Work

Built before finalizing scope, so this project's contribution is specific and checkable rather than assumed. Update this table as each team member finishes a reading-notes file in `docs/literature/papers/`.

| Work | Detection method(s) compared | Scope | Teaching layer | Progress tracking | Deployed platform |
|---|---|---|---|---|---|
| LineVul (Fu & Tantithamthavorn, 2022) | Transformer only | C/C++ | No | No | No |
| VulBertCNN (2024) | ML/DL comparison | C/C++ | No | No | No |
| Zou et al. (2025) — base paper | Graph-augmented CodeBERT | C/C++ | No | No | No |
| Python embeddings study (2026) | ML/DL comparison (Word2Vec, CodeBERT, GraphCodeBERT) | Python only | No | No | No |
| SeCodEd | DL detection + labs | TBD — confirm after full read | Yes | TBD | TBD |
| Avatao / Security Journey (commercial) | None published | Multi-language | Yes | Yes | Yes |
| "Secure Coding in Five Steps" | Single static tool (RIPS) | PHP | Yes | No | Yes |
| **VulnScope (this project)** | **Rules + classical ML + fine-tuned transformer** | **Python/JS web vulnerabilities** | **Yes, detector-grounded** | **Yes** | **Yes** |

## Contribution statement

> To the best of our knowledge, no existing work evaluates rule-based, classical machine learning, and fine-tuned transformer detection together in a single comparative study on Python/JavaScript web vulnerabilities, delivered as a deployed platform with detector-grounded pedagogical feedback.

Note on adversarial robustness: this was considered as an additional contribution angle and rejected after checking the literature — it's already a saturated sub-field (HogVul, EaTVul, ArVD, "Shield Broken," multiple 2024-2025 surveys). Not pursuing it here; noted so we don't revisit it later without reason.

## Action items before this table goes in the paper

- [ ] Read SeCodEd in full, confirm or correct its row
- [ ] Verify Avatao/Security Journey don't publish detection metrics (check their public docs directly, don't assume)
- [ ] Add any paper found during Phase 1–2 literature reading to this table

## Papers to read (one reading-notes file each, see template)

- LineVul — Fu & Tantithamthavorn, MSR 2022
- Zou et al., Scientific Reports 2025 (base paper)
- SeCodEd
- VulBertCNN, 2024