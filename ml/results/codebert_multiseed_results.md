# CodeBERT on the cleaned dataset, multiple seeds (held-out repos)

Fit 10039 / Val 2510 / Test 3114 rows. Validation is GroupKFold fold 0 of 5 by repo. Test base rate 0.4226. Threshold 0.5.

| Seed | Best epoch | Val PR-AUC | ROC-AUC | PR-AUC | Precision | Recall | F1 | Train seconds |
|---|---|---|---|---|---|---|---|---|
| 42 | 3 | 0.2578 | 0.5689 | 0.4717 | 0.4824 | 0.2713 | 0.3473 | 457.4 |
| 43 | 1 | 0.2611 | 0.5544 | 0.4549 | 0.0 | 0.0 | 0.0 | 455.8 |
| 44 | 3 | 0.271 | 0.5673 | 0.4698 | 0.4782 | 0.3078 | 0.3745 | 456.3 |
| 45 | 1 | 0.3007 | 0.543 | 0.4546 | 0.4524 | 0.2204 | 0.2964 | 456.5 |
| 46 | 1 | 0.2877 | 0.5622 | 0.4628 | 0.4306 | 0.0236 | 0.0447 | 455.7 |

| Metric | Mean | Min | Max |
|---|---|---|---|
| roc_auc | 0.5592 | 0.543 | 0.5689 |
| pr_auc | 0.4628 | 0.4546 | 0.4717 |
| precision | 0.3687 | 0.0 | 0.4824 |
| recall | 0.1646 | 0.0 | 0.3078 |
| f1 | 0.2126 | 0.0 | 0.3745 |

Average of the 5 seeds' probabilities (an ensemble, not a single model): ROC-AUC 0.5702, PR-AUC 0.4687.