# Cleaned test set: CodeBERT (5 seeds) vs classical baselines

3114 test functions from 188 held-out repos. Base rate 0.4226. 2000 resamples of whole repos, 95% percentile intervals.

## Per-seed check (recomputed from the saved predictions)

| Seed column | ROC-AUC | PR-AUC |
|---|---|---|
| codebert_prob_seed42 | 0.5689 | 0.4717 |
| codebert_prob_seed43 | 0.5544 | 0.4549 |
| codebert_prob_seed44 | 0.5673 | 0.4698 |
| codebert_prob_seed45 | 0.5430 | 0.4546 |
| codebert_prob_seed46 | 0.5622 | 0.4628 |

## Point estimates and repo-level intervals

| Model | ROC-AUC | ROC-AUC 95% CI | PR-AUC | PR-AUC 95% CI |
|---|---|---|---|---|
| Length only LR | 0.5009 | [0.4842, 0.5404] | 0.4314 | [0.4026, 0.4604] |
| TF-IDF + LR | 0.5450 | [0.5238, 0.5853] | 0.4601 | [0.4342, 0.4849] |
| TF-IDF + RF | 0.5343 | [0.5158, 0.5668] | 0.4505 | [0.4241, 0.4753] |
| CodeBERT (mean over seeds) | 0.5592 | [0.5393, 0.5902] | 0.4628 | [0.4336, 0.4823] |

Seed-averaged probabilities (an ensemble, point estimate only): ROC-AUC 0.5702, PR-AUC 0.4687.

## CodeBERT minus each baseline

| Comparison | Metric | Difference | 95% CI of difference | Resamples where CodeBERT is better |
|---|---|---|---|---|
| CodeBERT minus Length only LR | roc_auc | 0.0583 | [0.0266, 0.0845] | 99.9% |
| CodeBERT minus Length only LR | pr_auc | 0.0314 | [0.0044, 0.0511] | 98.8% |
| CodeBERT minus TF-IDF + LR | roc_auc | 0.0142 | [-0.0090, 0.0299] | 89.5% |
| CodeBERT minus TF-IDF + LR | pr_auc | 0.0027 | [-0.0176, 0.0145] | 59.8% |
| CodeBERT minus TF-IDF + RF | roc_auc | 0.0249 | [0.0043, 0.0457] | 98.9% |
| CodeBERT minus TF-IDF + RF | pr_auc | 0.0123 | [-0.0137, 0.0285] | 86.4% |