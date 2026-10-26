# Phase 1 baseline results (held-out repos)

Train 42056 / Test 3636 rows; split by repo_url, seed 42. Positive class = vulnerable (1).

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|
| majority-class | 0.0 | 0.0 | 0.0 | 0.4274 | 0.5 |
| length-only LR | 0.4647 | 0.1229 | 0.1944 | 0.4394 | 0.5032 |
| TF-IDF + Logistic Regression | 0.4732 | 0.2555 | 0.3318 | 0.4556 | 0.5279 |
| TF-IDF + Random Forest | 0.4965 | 0.0457 | 0.0837 | 0.4544 | 0.5304 |