# Three-way comparison on the cleaned test set

Rule tools flag a function if they report any finding. ML models are shown at the same alert count as 'Rules combined' in each view (their top-scoring functions), so threshold choice does not matter. Ties in score are broken by row order. CodeBERT rows average the 5 seeds. AUCs use the raw scores. The random-alerts row shows what flagging the same number of functions at random would give.

## All cleaned test functions

3114 functions, 1316 vulnerable, rule tools flag 581 in total.

| Model | flagged | precision | recall | f1 | balanced_acc | roc_auc | pr_auc |
|---|---|---|---|---|---|---|---|
| Semgrep | 45 | 0.5778 | 0.0198 | 0.0382 | 0.5046 | - | - |
| Bandit / ESLint | 548 | 0.4343 | 0.1809 | 0.2554 | 0.5042 | - | - |
| Rules combined | 581 | 0.4423 | 0.1953 | 0.2710 | 0.5075 | - | - |
| Random alerts (reference) | 581 | 0.4226 | 0.1866 | 0.2589 | 0.5000 | - | - |
| Length only LR | 581 | 0.4441 | 0.1960 | 0.2720 | 0.5082 | 0.5009 | 0.4314 |
| TF-IDF + LR | 581 | 0.4664 | 0.2059 | 0.2857 | 0.5168 | 0.5450 | 0.4601 |
| TF-IDF + RF | 581 | 0.4596 | 0.2029 | 0.2815 | 0.5141 | 0.5343 | 0.4505 |
| CodeBERT (5 seeds, averaged) | 581 | 0.4706 | 0.2078 | 0.2882 | 0.5183 | 0.5592 | 0.4628 |

## Parsed by every applicable rule tool

2249 functions, 945 vulnerable, rule tools flag 555 in total.

| Model | flagged | precision | recall | f1 | balanced_acc | roc_auc | pr_auc |
|---|---|---|---|---|---|---|---|
| Semgrep | 19 | 0.5789 | 0.0116 | 0.0228 | 0.5028 | - | - |
| Bandit / ESLint | 548 | 0.4343 | 0.2519 | 0.3188 | 0.5071 | - | - |
| Rules combined | 555 | 0.4360 | 0.2561 | 0.3227 | 0.5080 | - | - |
| Random alerts (reference) | 555 | 0.4202 | 0.2468 | 0.3109 | 0.5000 | - | - |
| Length only LR | 555 | 0.4270 | 0.2508 | 0.3160 | 0.5035 | 0.4932 | 0.4249 |
| TF-IDF + LR | 555 | 0.4955 | 0.2910 | 0.3667 | 0.5381 | 0.5539 | 0.4634 |
| TF-IDF + RF | 555 | 0.4541 | 0.2667 | 0.3360 | 0.5172 | 0.5453 | 0.4547 |
| CodeBERT (5 seeds, averaged) | 555 | 0.4699 | 0.2760 | 0.3477 | 0.5252 | 0.5674 | 0.4656 |

## In-scope classes only (sql_injection, xss, auth)

1437 functions, 631 vulnerable, rule tools flag 217 in total.

| Model | flagged | precision | recall | f1 | balanced_acc | roc_auc | pr_auc |
|---|---|---|---|---|---|---|---|
| Semgrep | 5 | 0.8000 | 0.0063 | 0.0126 | 0.5025 | - | - |
| Bandit / ESLint | 214 | 0.4720 | 0.1601 | 0.2391 | 0.5099 | - | - |
| Rules combined | 217 | 0.4793 | 0.1648 | 0.2453 | 0.5123 | - | - |
| Random alerts (reference) | 217 | 0.4391 | 0.1510 | 0.2247 | 0.5000 | - | - |
| Length only LR | 217 | 0.4470 | 0.1537 | 0.2288 | 0.5024 | 0.4940 | 0.4399 |
| TF-IDF + LR | 217 | 0.5069 | 0.1743 | 0.2594 | 0.5208 | 0.5426 | 0.4785 |
| TF-IDF + RF | 217 | 0.4977 | 0.1712 | 0.2547 | 0.5180 | 0.5388 | 0.4708 |
| CodeBERT (5 seeds, averaged) | 217 | 0.4793 | 0.1648 | 0.2453 | 0.5123 | 0.5535 | 0.4725 |

## In-scope and parsed

902 functions, 403 vulnerable, rule tools flag 214 in total.

| Model | flagged | precision | recall | f1 | balanced_acc | roc_auc | pr_auc |
|---|---|---|---|---|---|---|---|
| Semgrep | 2 | 0.5000 | 0.0025 | 0.0049 | 0.5002 | - | - |
| Bandit / ESLint | 214 | 0.4720 | 0.2506 | 0.3274 | 0.5121 | - | - |
| Rules combined | 214 | 0.4720 | 0.2506 | 0.3274 | 0.5121 | - | - |
| Random alerts (reference) | 214 | 0.4468 | 0.2373 | 0.3099 | 0.5000 | - | - |
| Length only LR | 214 | 0.4393 | 0.2333 | 0.3047 | 0.4964 | 0.4853 | 0.4417 |
| TF-IDF + LR | 214 | 0.5000 | 0.2655 | 0.3468 | 0.5255 | 0.5515 | 0.4920 |
| TF-IDF + RF | 214 | 0.4953 | 0.2630 | 0.3436 | 0.5233 | 0.5575 | 0.4889 |
| CodeBERT (5 seeds, averaged) | 214 | 0.4766 | 0.2531 | 0.3306 | 0.5143 | 0.5577 | 0.4821 |

## Per class (all cleaned rows): recall on vulnerable functions / false-alarm rate on fixed functions

ML models flag their top 581 functions overall, the same count as the rule tools.

| Model | sql_injection recall | sql_injection false alarms | xss recall | xss false alarms | auth recall | auth false alarms |
|---|---|---|---|---|---|---|
| Semgrep | 0.0062 | 0.0000 | 0.0084 | 0.0055 | 0.0000 | 0.0000 |
| Bandit / ESLint | 0.1556 | 0.1261 | 0.1429 | 0.1538 | 0.3000 | 0.2973 |
| Rules combined | 0.1618 | 0.1261 | 0.1429 | 0.1538 | 0.3000 | 0.2973 |
| Length only LR | 0.1037 | 0.1090 | 0.2521 | 0.2143 | 0.5000 | 0.4595 |
| TF-IDF + LR | 0.2386 | 0.2198 | 0.3193 | 0.1758 | 0.3333 | 0.2973 |
| TF-IDF + RF | 0.2780 | 0.2589 | 0.3025 | 0.1813 | 0.2000 | 0.2162 |
| CodeBERT (5 seeds, averaged) | 0.2627 | 0.2388 | 0.3798 | 0.2758 | 0.2400 | 0.1730 |

- sql_injection: 482 vulnerable, 587 fixed
- xss: 119 vulnerable, 182 fixed
- auth: 30 vulnerable, 37 fixed

## Parse coverage on the cleaned set

- python: 1056 functions, parsed by every applicable rule tool: 992
- javascript: 2058 functions, parsed by every applicable rule tool: 1257