# Three-way comparison on held-out test functions

Rule tools give a yes/no flag per function (any finding = vulnerable), so they have no AUC. ML models use threshold 0.5 for the flag columns; AUCs use the raw probability.

## All test functions

| Model | n | vulnerable | flagged | precision | recall | f1 | balanced_acc | pr_auc | roc_auc |
|---|---|---|---|---|---|---|---|---|---|
| Semgrep | 3636 | 1554 | 45 | 0.5778 | 0.0167 | 0.0325 | 0.5038 | - | - |
| Bandit / ESLint | 3636 | 1554 | 656 | 0.4360 | 0.1840 | 0.2588 | 0.5032 | - | - |
| Rules combined (any finding) | 3636 | 1554 | 689 | 0.4427 | 0.1963 | 0.2720 | 0.5059 | - | - |
| TF-IDF + LR | 3636 | 1554 | 839 | 0.4732 | 0.2555 | 0.3318 | 0.5216 | 0.4556 | 0.5279 |
| TF-IDF + RF | 3636 | 1554 | 143 | 0.4965 | 0.0457 | 0.0837 | 0.5056 | 0.4544 | 0.5304 |
| CodeBERT | 3636 | 1554 | 1190 | 0.4748 | 0.3636 | 0.4118 | 0.5317 | 0.4648 | 0.5495 |

## Parsed by every applicable rule tool

| Model | n | vulnerable | flagged | precision | recall | f1 | balanced_acc | pr_auc | roc_auc |
|---|---|---|---|---|---|---|---|---|---|
| Semgrep | 2541 | 1079 | 19 | 0.5789 | 0.0102 | 0.0200 | 0.5024 | - | - |
| Bandit / ESLint | 2541 | 1079 | 656 | 0.4360 | 0.2651 | 0.3297 | 0.5060 | - | - |
| Rules combined (any finding) | 2541 | 1079 | 663 | 0.4374 | 0.2688 | 0.3330 | 0.5068 | - | - |
| TF-IDF + LR | 2541 | 1079 | 553 | 0.4882 | 0.2502 | 0.3309 | 0.5283 | 0.4608 | 0.5359 |
| TF-IDF + RF | 2541 | 1079 | 95 | 0.4947 | 0.0436 | 0.0801 | 0.5054 | 0.4586 | 0.5438 |
| CodeBERT | 2541 | 1079 | 875 | 0.4811 | 0.3902 | 0.4309 | 0.5398 | 0.4705 | 0.5605 |

## In-scope classes only (sql_injection, xss, auth)

| Model | n | vulnerable | flagged | precision | recall | f1 | balanced_acc | pr_auc | roc_auc |
|---|---|---|---|---|---|---|---|---|---|
| Semgrep | 1679 | 733 | 5 | 0.8000 | 0.0055 | 0.0108 | 0.5022 | - | - |
| Bandit / ESLint | 1679 | 733 | 257 | 0.4553 | 0.1596 | 0.2364 | 0.5058 | - | - |
| Rules combined (any finding) | 1679 | 733 | 260 | 0.4615 | 0.1637 | 0.2417 | 0.5079 | - | - |
| TF-IDF + LR | 1679 | 733 | 502 | 0.4681 | 0.3206 | 0.3806 | 0.5192 | 0.4707 | 0.5369 |
| TF-IDF + RF | 1679 | 733 | 100 | 0.5000 | 0.0682 | 0.1200 | 0.5077 | 0.4656 | 0.5290 |
| CodeBERT | 1679 | 733 | 681 | 0.4728 | 0.4393 | 0.4554 | 0.5299 | 0.4735 | 0.5459 |

## In-scope and parsed

| Model | n | vulnerable | flagged | precision | recall | f1 | balanced_acc | pr_auc | roc_auc |
|---|---|---|---|---|---|---|---|---|---|
| Semgrep | 968 | 426 | 2 | 0.5000 | 0.0023 | 0.0047 | 0.5003 | - | - |
| Bandit / ESLint | 968 | 426 | 257 | 0.4553 | 0.2746 | 0.3426 | 0.5082 | - | - |
| Rules combined (any finding) | 968 | 426 | 257 | 0.4553 | 0.2746 | 0.3426 | 0.5082 | - | - |
| TF-IDF + LR | 968 | 426 | 282 | 0.4929 | 0.3263 | 0.3927 | 0.5312 | 0.4894 | 0.5576 |
| TF-IDF + RF | 968 | 426 | 63 | 0.4921 | 0.0728 | 0.1268 | 0.5069 | 0.4814 | 0.5554 |
| CodeBERT | 968 | 426 | 454 | 0.4890 | 0.5211 | 0.5045 | 0.5465 | 0.4907 | 0.5621 |

## Per class: recall on vulnerable functions and false-alarm rate on fixed functions

| Model | sql_injection recall | sql_injection false alarms | xss recall | xss false alarms | auth recall | auth false alarms |
|---|---|---|---|---|---|---|
| Semgrep | 0.0052 | 0.0000 | 0.0079 | 0.0052 | 0.0000 | 0.0000 |
| Bandit / ESLint | 0.1510 | 0.1337 | 0.1654 | 0.1728 | 0.3000 | 0.2973 |
| Rules combined (any finding) | 0.1562 | 0.1337 | 0.1654 | 0.1728 | 0.3000 | 0.2973 |
| TF-IDF + LR | 0.2986 | 0.2813 | 0.4094 | 0.2723 | 0.3667 | 0.3514 |
| TF-IDF + RF | 0.0694 | 0.0557 | 0.0787 | 0.0471 | 0.0000 | 0.0270 |
| CodeBERT | 0.4549 | 0.4164 | 0.4094 | 0.2723 | 0.2667 | 0.2162 |

## Parse coverage

- python: 1066 functions, parsed by every applicable rule tool: 1002
- javascript: 2570 functions, parsed by every applicable rule tool: 1539