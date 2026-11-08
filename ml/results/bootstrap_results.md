# Repo-level bootstrap (held-out repos)

192 test repos, 3636 rows, 2000 resamples that resample whole repos with replacement. Intervals are 95% percentile intervals.

| Model | ROC-AUC | ROC-AUC 95% CI | PR-AUC | PR-AUC 95% CI |
|---|---|---|---|---|
| CodeBERT | 0.5495 | [0.5315, 0.5885] | 0.4648 | [0.4371, 0.4848] |
| TF-IDF + Logistic Regression | 0.5279 | [0.5075, 0.5626] | 0.4556 | [0.4327, 0.4752] |
| TF-IDF + Random Forest | 0.5304 | [0.5138, 0.5653] | 0.4544 | [0.4326, 0.4758] |

| Comparison | Metric | Difference | 95% CI of difference | Resamples where CodeBERT is better |
|---|---|---|---|---|
| codebert_minus_lr | roc_auc | 0.0216 | [0.0018, 0.0554] | 98.2% |
| codebert_minus_lr | pr_auc | 0.0091 | [-0.0124, 0.0268] | 86.1% |
| codebert_minus_rf | roc_auc | 0.0191 | [-0.0003, 0.0385] | 97.4% |
| codebert_minus_rf | pr_auc | 0.0104 | [-0.0125, 0.0261] | 85.0% |