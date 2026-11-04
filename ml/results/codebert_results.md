# Phase 2 CodeBERT results (held-out repos)

Fit 41166 / Val 890 / Test 3636 rows; split by repo_url, seed 42; best epoch 2 by validation PR-AUC. Positive class = vulnerable (1). Threshold 0.5.

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|
| CodeBERT (fine-tuned) | 0.4748 | 0.3636 | 0.4118 | 0.4648 | 0.5495 |
| always-predict-vulnerable (reference) | 0.4274 | 1.0 | 0.5988 | 0.4274 | 0.5 |