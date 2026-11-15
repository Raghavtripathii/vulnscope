# Effect of rule configuration changes on the CVEfixes test set

## All 3636 test functions

3636 functions, 1554 vulnerable.

| Rule configuration | flagged | precision | recall |
|---|---|---|---|
| original rulesets (v1) | 689 | 0.4427 | 0.1963 |
| v1 + p/secrets + secret and XSS rules (v2) | 722 | 0.4432 | 0.2059 |
| v2 + SQL injection rules (v3) | 732 | 0.4454 | 0.2098 |
| only newly flagged by v3 | 10 | 0.6000 | 0.0039 |

## Cleaned test set

3114 functions, 1316 vulnerable.

| Rule configuration | flagged | precision | recall |
|---|---|---|---|
| original rulesets (v1) | 581 | 0.4423 | 0.1953 |
| v1 + p/secrets + secret and XSS rules (v2) | 610 | 0.4426 | 0.2052 |
| v2 + SQL injection rules (v3) | 619 | 0.4443 | 0.2090 |
| only newly flagged by v3 | 9 | 0.5556 | 0.0038 |

## By vulnerability class, all test functions

| Class | functions | vulnerable | base rate | v1 recall | v2 recall | v3 recall | v3 flagged | v3 precision |
|---|---|---|---|---|---|---|---|---|
| sql_injection | 1294 | 576 | 0.4451 | 0.1562 | 0.1684 | 0.1753 | 212 | 0.4764 |
| xss | 318 | 127 | 0.3994 | 0.1654 | 0.2205 | 0.2205 | 66 | 0.4242 |
| auth | 67 | 30 | 0.4478 | 0.3000 | 0.3000 | 0.3000 | 20 | 0.4500 |
| other | 1957 | 821 | 0.4195 | 0.2253 | 0.2266 | 0.2290 | 434 | 0.4332 |

## By vulnerability class, cleaned test set

| Class | functions | vulnerable | base rate | v1 recall | v2 recall | v3 recall | v3 flagged | v3 precision |
|---|---|---|---|---|---|---|---|---|
| sql_injection | 1069 | 482 | 0.4509 | 0.1618 | 0.1743 | 0.1826 | 176 | 0.5000 |
| xss | 301 | 119 | 0.3953 | 0.1429 | 0.2017 | 0.2017 | 57 | 0.4211 |
| auth | 67 | 30 | 0.4478 | 0.3000 | 0.3000 | 0.3000 | 20 | 0.4500 |
| other | 1677 | 685 | 0.4085 | 0.2234 | 0.2234 | 0.2248 | 366 | 0.4208 |

## Rule ids that appear only in v2 (not in v1)

| rule id | functions flagged | of which vulnerable |
|---|---|---|
| app.detectors.semgrep-rules.vulnscope-xss-html-sink | 38 | 17 |
| app.detectors.semgrep-rules.vulnscope-hardcoded-secret-python | 5 | 1 |

## Rule ids that appear only in v3 (not in v2)

| rule id | functions flagged | of which vulnerable |
|---|---|---|
| app.detectors.semgrep-rules.vulnscope-sqli-javascript | 14 | 8 |
| app.detectors.semgrep-rules.vulnscope-sqli-python | 1 | 1 |
