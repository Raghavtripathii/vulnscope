from pathlib import Path

import pandas as pd

from quality_filters import flag_rows, pair_keys

PROC = Path("data/processed")
RES = Path("results")
CATEGORIES = ["sql_injection", "xss", "secrets", "auth", "other"]

lines = ["# Cleaned dataset summary", ""]
lines.append("Rule: a function is suspect if it is minified, looks like another language, or is a fragment (see quality_filters.py). If any row sharing the same file_change_id and function name is suspect, the whole group is removed so before and after versions stay together. The repo split is unchanged.")
lines.append("")
lines.append("| split | rows before | rows after | vulnerable rate before | vulnerable rate after | repos before | repos after | largest repo share after |")
lines.append("|---|---|---|---|---|---|---|---|")

category_rows = []
for split in ["train", "test"]:
    frame = pd.read_csv(PROC / f"{split}.csv")
    flags = flag_rows(frame)
    keys = pair_keys(frame)
    bad_keys = set(keys[flags["suspect"]])
    clean = frame[~keys.isin(bad_keys)]
    clean.to_csv(PROC / f"{split}_clean.csv", index=False)

    top_share = clean["repo_url"].value_counts(normalize=True).iloc[0]
    lines.append(
        f"| {split} | {len(frame)} | {len(clean)} | {frame['label'].mean() * 100:.1f}% | "
        f"{clean['label'].mean() * 100:.1f}% | {frame['repo_url'].nunique()} | "
        f"{clean['repo_url'].nunique()} | {top_share * 100:.1f}% |"
    )

    before = frame[frame["label"] == 1]["category"].fillna("other").value_counts()
    after = clean[clean["label"] == 1]["category"].fillna("other").value_counts()
    category_rows.append(
        f"| {split} | " + " | ".join(f"{int(before.get(c, 0))} -> {int(after.get(c, 0))}" for c in CATEGORIES) + " |"
    )

lines.append("")
lines.append("## Vulnerable functions per class, before -> after cleaning")
lines.append("")
lines.append("| split | " + " | ".join(CATEGORIES) + " |")
lines.append("|---|" + "---|" * len(CATEGORIES))
lines += category_rows

text = "\n".join(lines)
(RES / "clean_dataset_summary.md").write_text(text, encoding="utf-8")
print(text)