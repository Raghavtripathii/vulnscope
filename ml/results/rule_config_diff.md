# Effect of adding p/secrets and the custom rules on the CVEfixes test set

## All 3636 test functions

3636 functions, 1554 vulnerable.

| Rule configuration | flagged | precision | recall |
|---|---|---|---|
| original rulesets (v1) | 689 | 0.4427 | 0.1963 |
| original + p/secrets + custom rules (v2) | 722 | 0.4432 | 0.2059 |
| only newly flagged by v2 | 33 | 0.4545 | 0.0097 |

## Cleaned test set

3114 functions, 1316 vulnerable.

| Rule configuration | flagged | precision | recall |
|---|---|---|---|
| original rulesets (v1) | 581 | 0.4423 | 0.1953 |
| original + p/secrets + custom rules (v2) | 610 | 0.4426 | 0.2052 |
| only newly flagged by v2 | 29 | 0.4483 | 0.0099 |

## Rule ids that appear only in v2

| rule id | functions flagged | of which vulnerable |
|---|---|---|
| app.detectors.semgrep-rules.vulnscope-xss-html-sink | 38 | 17 |
| app.detectors.semgrep-rules.vulnscope-hardcoded-secret-python | 5 | 1 |