# Before-fix vs after-fix pairs on the held-out test set

- test rows: 3636
- pair groups found (exactly one vulnerable and one fixed row): 1272
- rows covered by pairs: 2544
- pairs where both versions have identical code: 0

## Rule tools: how often do they treat the two versions the same way

| Tool | same answer for both | flags only the vulnerable version | flags only the fixed version | flags both |
|---|---|---|---|---|
| Semgrep | 0.9937 | 0.0063 | 0.0000 | 0.0134 |
| Bandit / ESLint | 0.9796 | 0.0149 | 0.0055 | 0.1824 |
| Rules combined | 0.9764 | 0.0181 | 0.0055 | 0.1934 |

## ML models: how often is the vulnerable version scored higher

| Model | vulnerable scored higher | ties | pairwise accuracy (ties count half) |
|---|---|---|---|
| TF-IDF + LR | 0.3601 | 0.3624 | 0.5413 |
| TF-IDF + RF | 0.2995 | 0.4300 | 0.5145 |
| CodeBERT | 0.5204 | 0.1407 | 0.5908 |