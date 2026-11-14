# Hybrid combiner on the cleaned test set

Design fixed before looking at results. Voters: rule tools (flag = any finding), TF-IDF + LR, and CodeBERT (average probability over 5 seeds). ML voters flag their top-k functions, where k is the number of functions the rule tools flag in the same set, so every voter raises the same number of alerts. Soft vote = rule flag (0 or 1) + LR rank percentile + CodeBERT rank percentile, equal weights, nothing tuned. Hard votes count how many voters flag a function. Intervals resample whole repos, 2000 times, 95% percentile.

## All cleaned test functions

3114 functions, 1316 vulnerable, k = 581.

| Method | alerts | precision | recall | f1 | roc_auc | pr_auc |
|---|---|---|---|---|---|---|
| Rules (any finding) | 581 | 0.4423 | 0.1953 | 0.2710 | - | - |
| TF-IDF + LR (top alerts) | 581 | 0.4664 | 0.2059 | 0.2857 | 0.5450 | 0.4601 |
| CodeBERT 5-seed average (top alerts) | 581 | 0.4836 | 0.2135 | 0.2963 | 0.5702 | 0.4687 |
| Soft vote (top alerts) | 581 | 0.4888 | 0.2158 | 0.2994 | 0.5631 | 0.4693 |
| Hard vote, at least 1 of 3 | 1362 | 0.4559 | 0.4719 | 0.4638 | - | - |
| Hard vote, at least 2 of 3 | 327 | 0.4954 | 0.1231 | 0.1972 | - | - |
| Hard vote, at least 3 of 3 | 54 | 0.4815 | 0.0198 | 0.0380 | - | - |
| Random alerts (reference) | 581 | 0.4226 | 0.1866 | 0.2589 | - | - |

Repo-level bootstrap over 188 repos: soft vote minus each part

| Metric | Soft vote minus | difference | 95% CI | resamples where soft vote is better |
|---|---|---|---|---|
| precision at same alert count | Rules | 0.0477 | [0.0158, 0.0917] | 100.0% |
| precision at same alert count | LR | 0.0174 | [-0.0312, 0.0637] | 80.0% |
| precision at same alert count | CodeBERT | 0.0045 | [-0.0287, 0.0438] | 55.8% |
| ROC-AUC | LR | 0.0178 | [0.0016, 0.0337] | 98.5% |
| ROC-AUC | CodeBERT | -0.0066 | [-0.0210, 0.0076] | 15.3% |
| PR-AUC | LR | 0.0082 | [-0.0080, 0.0223] | 86.6% |
| PR-AUC | CodeBERT | 0.0010 | [-0.0108, 0.0141] | 57.4% |

## In-scope classes only (sql_injection, xss, auth)

1437 functions, 631 vulnerable, k = 217.

| Method | alerts | precision | recall | f1 | roc_auc | pr_auc |
|---|---|---|---|---|---|---|
| Rules (any finding) | 217 | 0.4793 | 0.1648 | 0.2453 | - | - |
| TF-IDF + LR (top alerts) | 217 | 0.5069 | 0.1743 | 0.2594 | 0.5426 | 0.4785 |
| CodeBERT 5-seed average (top alerts) | 217 | 0.4885 | 0.1680 | 0.2500 | 0.5649 | 0.4802 |
| Soft vote (top alerts) | 217 | 0.4977 | 0.1712 | 0.2547 | 0.5614 | 0.4852 |
| Hard vote, at least 1 of 3 | 525 | 0.4857 | 0.4041 | 0.4412 | - | - |
| Hard vote, at least 2 of 3 | 106 | 0.5189 | 0.0872 | 0.1493 | - | - |
| Hard vote, at least 3 of 3 | 20 | 0.5000 | 0.0158 | 0.0307 | - | - |
| Random alerts (reference) | 217 | 0.4391 | 0.1510 | 0.2247 | - | - |

Repo-level bootstrap over 61 repos: soft vote minus each part

| Metric | Soft vote minus | difference | 95% CI | resamples where soft vote is better |
|---|---|---|---|---|
| precision at same alert count | Rules | 0.0490 | [-0.0108, 0.1831] | 86.2% |
| precision at same alert count | LR | -0.0023 | [-0.0636, 0.0736] | 36.3% |
| precision at same alert count | CodeBERT | 0.0305 | [-0.0204, 0.1263] | 77.1% |
| ROC-AUC | LR | 0.0158 | [-0.0160, 0.0388] | 88.6% |
| ROC-AUC | CodeBERT | -0.0058 | [-0.0397, 0.0167] | 28.4% |
| PR-AUC | LR | 0.0007 | [-0.0415, 0.0254] | 66.2% |
| PR-AUC | CodeBERT | 0.0048 | [-0.0152, 0.0248] | 82.0% |
