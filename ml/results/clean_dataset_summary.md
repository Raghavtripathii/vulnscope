# Cleaned dataset summary

Rule: a function is suspect if it is minified, looks like another language, or is a fragment (see quality_filters.py). If any row sharing the same file_change_id and function name is suspect, the whole group is removed so before and after versions stay together. The repo split is unchanged.

| split | rows before | rows after | vulnerable rate before | vulnerable rate after | repos before | repos after | largest repo share after |
|---|---|---|---|---|---|---|---|
| train | 42056 | 12549 | 43.8% | 34.1% | 764 | 752 | 6.3% |
| test | 3636 | 3114 | 42.7% | 42.3% | 192 | 188 | 31.0% |

## Vulnerable functions per class, before -> after cleaning

| split | sql_injection | xss | secrets | auth | other |
|---|---|---|---|---|---|
| train | 158 -> 156 | 11567 -> 897 | 0 -> 0 | 105 -> 105 | 6609 -> 3118 |
| test | 576 -> 482 | 127 -> 119 | 0 -> 0 | 30 -> 30 | 821 -> 685 |