# Error analysis on the cleaned test set

Point estimates without confidence intervals, so read them as descriptive. Within each group the AUC separates vulnerable from fixed functions of that group only. CodeBERT rows average the AUC over the seeds.

## By vulnerability class

| Group | functions | vulnerable | TF-IDF + LR ROC | TF-IDF + LR PR | TF-IDF + RF ROC | TF-IDF + RF PR | CodeBERT (mean of seeds) ROC | CodeBERT (mean of seeds) PR |
|---|---|---|---|---|---|---|---|---|
| sql_injection | 1069 | 482 | 0.5150 | 0.4706 | 0.5132 | 0.4632 | 0.5271 | 0.4692 |
| xss | 301 | 119 | 0.6357 | 0.5185 | 0.6267 | 0.5158 | 0.6327 | 0.4796 |
| auth | 67 | 30 | 0.5338 | 0.4924 | 0.5054 | 0.4572 | 0.5676 | 0.5367 |
| other | 1677 | 685 | 0.5453 | 0.4435 | 0.5251 | 0.4286 | 0.5576 | 0.4520 |

## By language

| Group | functions | vulnerable | TF-IDF + LR ROC | TF-IDF + LR PR | TF-IDF + RF ROC | TF-IDF + RF PR | CodeBERT (mean of seeds) ROC | CodeBERT (mean of seeds) PR |
|---|---|---|---|---|---|---|---|---|
| python | 1056 | 411 | 0.5947 | 0.4573 | 0.5490 | 0.4282 | 0.6055 | 0.4744 |
| javascript | 2058 | 905 | 0.5261 | 0.4653 | 0.5247 | 0.4608 | 0.5340 | 0.4627 |

## Without the largest repo (https://github.com/semplon/GeniXCMS, 31.0% of rows)

| Group | functions | vulnerable | TF-IDF + LR ROC | TF-IDF + LR PR | TF-IDF + RF ROC | TF-IDF + RF PR | CodeBERT (mean of seeds) ROC | CodeBERT (mean of seeds) PR |
|---|---|---|---|---|---|---|---|---|
| all repos | 3114 | 1316 | 0.5450 | 0.4601 | 0.5343 | 0.4505 | 0.5592 | 0.4628 |
| without the largest repo | 2150 | 877 | 0.5584 | 0.4556 | 0.5422 | 0.4453 | 0.5680 | 0.4542 |
| only the largest repo | 964 | 439 | 0.5133 | 0.4731 | 0.5058 | 0.4593 | 0.5296 | 0.4778 |

## Per-repo ROC-AUC (repos with at least 20 functions and both classes)

| Model | repos | median ROC-AUC | repos above 0.5 | repos below 0.5 |
|---|---|---|---|---|
| TF-IDF + LR | 28 | 0.5290 | 19 | 8 |
| TF-IDF + RF | 28 | 0.5344 | 20 | 7 |
| CodeBERT (mean of seeds) | 28 | 0.5230 | 22 | 6 |