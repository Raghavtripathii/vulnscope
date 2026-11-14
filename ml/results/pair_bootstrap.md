# Pairwise accuracy with repo-level bootstrap

1272 pairs from 156 held-out repos, 2000 resamples of whole repos, 95% percentile intervals. Ties count half.

| Model | pairwise accuracy | 95% CI |
|---|---|---|
| Length only (longer = vulnerable) | 0.1702 | [0.1060, 0.2851] |
| TF-IDF + LR | 0.5413 | [0.4937, 0.6273] |
| TF-IDF + RF | 0.5145 | [0.4901, 0.5442] |
| CodeBERT | 0.5908 | [0.5209, 0.6326] |

| Comparison | difference | 95% CI of difference | resamples where CodeBERT is better |
|---|---|---|---|
| CodeBERT minus Length only (longer = vulnerable) | 0.4206 | [0.2469, 0.5134] | 100.0% |
| CodeBERT minus TF-IDF + LR | 0.0495 | [-0.0903, 0.1223] | 75.6% |
| CodeBERT minus TF-IDF + RF | 0.0763 | [-0.0044, 0.1229] | 96.8% |