# Classical baselines on the cleaned dataset (held-out repos)

Train 12549 / Test 3114 rows, same repo split as before, seed 42. Threshold 0.5 for precision, recall and F1.

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|
| always-predict-vulnerable (reference) | 0.4226 | 1.0 | 0.5941 | 0.4226 | 0.5 |
| length-only LR | 0.4234 | 0.4643 | 0.4429 | 0.4314 | 0.5009 |
| TF-IDF + Logistic Regression | 0.4625 | 0.5289 | 0.4934 | 0.4601 | 0.545 |
| TF-IDF + Random Forest | 0.4706 | 0.1641 | 0.2434 | 0.4505 | 0.5343 |