# CodeBERT run log

Same script (ml/codebert_finetune.py), same settings (seed 42, 3 epochs, max length 256, batch 16, learning rate 2e-5) and the same train and test files in every run. Threshold 0.5.

| Run | Source | ROC-AUC | PR-AUC | Precision | Recall | F1 | Confusion matrix [[TN,FP],[FN,TP]] | Train seconds |
|---|---|---|---|---|---|---|---|---|
| A | Kaggle notebook output (per-function predictions not saved) | 0.5544 | 0.4656 | 0.4713 | 0.2375 | 0.3158 | [[1668, 414], [1185, 369]] | 1782.4 |
| B | ml/results/codebert_results.json and test_predictions_codebert.csv | 0.5495 | 0.4648 | 0.4748 | 0.3636 | 0.4118 | [[1457, 625], [989, 565]] | 1922.8 |

Runs A and B differ even though the settings are identical. ROC-AUC and PR-AUC moved by about 0.005, while recall moved by about 0.13 at the 0.5 threshold, so threshold-free metrics are the headline numbers.