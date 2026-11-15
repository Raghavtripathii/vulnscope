# Phase 2 decisions and findings

## Data

- CVEfixes functions, label 1 = before-fix, label 0 = after-fix. Split by repository (seed 42), unchanged throughout.
- The original training set was dominated by one repository: jgraph/drawio supplied 28,905 of 42,056 rows (68.7%), about 97% of them minified or bundled JavaScript.
- A fixed text-rule filter (quality_filters.py) removes minified, wrong-language and fragment functions. If either side of a before/after pair is flagged, the whole pair is removed. The rule was set from the audit of train and test, not from model performance.
- After cleaning: train 12,549 rows, test 3,114 rows (from 3,636). Both the original and cleaned results are reported.
- Vulnerable functions per class, cleaned train / test: sql_injection 156 / 482, xss 897 / 119, auth 105 / 30, secrets 0 / 0.

## Decisions on the locked classes

- Secrets: rule-based only. CVEfixes has no secrets positives in train or test, so the ML models never saw this class and it cannot be evaluated on this data. Coverage was probed with hand-written snippets only. Bandit catches password-named variables, Semgrep p/secrets caught an AWS key id, and two custom rules match credential-like variable names assigned long string literals. These rules are name-based heuristics: they miss secrets in oddly named variables and can flag harmless strings in variables named token or key.
- Broken authentication: 30 vulnerable and 37 fixed functions in the test set. Results for this class are reported as low-n and no conclusion is drawn. Semgrep JWT rules caught the probed Python and JavaScript JWT cases.
- XSS: one custom rule flags non-literal values written with innerHTML, outerHTML, document.write, document.writeln and insertAdjacentHTML. It has no data-flow tracking and will raise false alarms. On the CVEfixes test set it flagged 38 functions, 17 of them vulnerable.
- Deployed rule layer: Semgrep (p/security-audit, p/owasp-top-ten, p/secrets, custom rules), Bandit for Python, ESLint with eslint-plugin-security for JavaScript. The CVEfixes tables use the original two Semgrep rulesets. Adding p/secrets and the custom rules changed flagged functions from 689 to 722 and precision from 0.4427 to 0.4432.

## Findings to report honestly

- Every detector family is close to chance on this benchmark. On the cleaned test set, ROC-AUC: length-only 0.5009, TF-IDF + LR 0.5450, TF-IDF + RF 0.5343, CodeBERT 0.5592 (mean of 5 seeds, range 0.543 to 0.569).
- Repo-level bootstrap, CodeBERT minus baseline, ROC-AUC: minus length-only +0.058 (CI 0.027 to 0.085), minus RF +0.025 (CI 0.004 to 0.046), minus LR +0.014 (CI -0.009 to 0.030, not significant). PR-AUC differences against LR and RF are not significant.
- Precision, recall and F1 at threshold 0.5 are unstable between runs and seeds, so AUCs and same-alert-count comparisons are used instead.
- Rule tools give the same answer for both versions of a before/after pair in 97.6% of pairs and flag both versions in 19.3%. At the same alert count they are not clearly better than random flagging. This is a property of the before/after-fix benchmark, not a measure of their value on real code.
- In test pairs the vulnerable version is shorter in 78.0% of pairs; in train pairs, 28.9% (55.3% have equal length). Pairwise accuracy on test pairs is therefore inflated by a length effect and is not used as a headline.
- A simple hybrid (rule flag + LR + CodeBERT, equal weights) did not improve on CodeBERT alone at the same alert count.
- Parse coverage on the cleaned test set: Python 992 of 1,056 functions parsed by every rule tool, JavaScript 1,257 of 2,058. Unparsed functions count as not flagged.

## Known limitations

- All CodeBERT seeds share one train/validation split, so seed variation reflects training randomness only.
- The test set is still dominated by one repository (31% of rows); intervals resample whole repositories.
- Several comparisons were made without multiple-comparison correction.
- The length filter in the original dataset build dropped about 48% of Python and JavaScript methods; the effect on label balance has not been checked.