from pathlib import Path

import numpy as np
import pandas as pd

from quality_filters import flag_rows, pair_keys

RES = Path("results")
PROC = Path("data/processed")
CLASSES = ["sql_injection", "xss", "auth", "other"]

test = pd.read_csv(
    PROC / "test.csv",
    usecols=["code_hash", "lang", "file_change_id", "name", "category", "label", "code"],
)
versions = {
    "v1": pd.read_csv(RES / "rule_detector_predictions.csv"),
    "v2": pd.read_csv(RES / "rule_detector_predictions_v2.csv"),
    "v3": pd.read_csv(RES / "rule_detector_predictions_v3.csv"),
}
for version_name, frame in versions.items():
    assert len(test) == len(frame), f"{version_name} length differs"
    assert (test["code_hash"].values == frame["code_hash"].values).all(), f"{version_name} order differs"

flags = flag_rows(test)
keys = pair_keys(test)
keep = ~keys.isin(set(keys[flags["suspect"]])).values

y = test["label"].values.astype(int)
category = test["category"].fillna("other").values


def any_flag(frame):
    for col in ["semgrep_n", "bandit_n", "eslint_n"]:
        frame[col] = frame[col].fillna(0).astype(int)
    linter_n = np.where(test["lang"].values == "python", frame["bandit_n"].values, frame["eslint_n"].values)
    return (frame["semgrep_n"].values > 0) | (linter_n > 0)


flagged = {name: any_flag(frame) for name, frame in versions.items()}


def rule_id_sets(series):
    return [set(v for v in str(value).split(";") if v and v != "nan") for value in series]


rule_ids = {name: rule_id_sets(frame["semgrep_rules"]) for name, frame in versions.items()}


def recall_of(flag, mask):
    positives = int(y[mask].sum())
    if positives == 0:
        return float("nan")
    return float((flag[mask] & (y[mask] == 1)).sum() / positives)


def precision_of(flag, mask):
    chosen = mask & flag
    if int(chosen.sum()) == 0:
        return float("nan")
    return float(y[chosen].mean())


def describe(title, mask):
    positives = int(y[mask].sum())
    lines = [f"## {title}", "", f"{int(mask.sum())} functions, {positives} vulnerable.", ""]
    lines.append("| Rule configuration | flagged | precision | recall |")
    lines.append("|---|---|---|---|")
    labels = {
        "v1": "original rulesets (v1)",
        "v2": "v1 + p/secrets + secret and XSS rules (v2)",
        "v3": "v2 + SQL injection rules (v3)",
    }
    for name in ["v1", "v2", "v3"]:
        f = flagged[name]
        lines.append(
            f"| {labels[name]} | {int((f & mask).sum())} | {precision_of(f, mask):.4f} | {recall_of(f, mask):.4f} |"
        )
    new = flagged["v3"] & ~flagged["v2"]
    lines.append(
        f"| only newly flagged by v3 | {int((new & mask).sum())} | {precision_of(new, mask):.4f} | {recall_of(new, mask):.4f} |"
    )
    lines.append("")
    return lines


def class_table(title, mask):
    lines = [f"## {title}", ""]
    lines.append("| Class | functions | vulnerable | base rate | v1 recall | v2 recall | v3 recall | v3 flagged | v3 precision |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for cls in CLASSES:
        m = mask & (category == cls)
        n = int(m.sum())
        if n == 0:
            continue
        positives = int(y[m].sum())
        lines.append(
            f"| {cls} | {n} | {positives} | {positives / n:.4f} | "
            f"{recall_of(flagged['v1'], m):.4f} | {recall_of(flagged['v2'], m):.4f} | {recall_of(flagged['v3'], m):.4f} | "
            f"{int((flagged['v3'] & m).sum())} | {precision_of(flagged['v3'], m):.4f} |"
        )
    lines.append("")
    return lines


def new_rule_table(title, previous, current):
    new_ids = set().union(*rule_ids[current]) - set().union(*rule_ids[previous])
    lines = [f"## {title}", "", "| rule id | functions flagged | of which vulnerable |", "|---|---|---|"]
    rows = []
    for rule in new_ids:
        hit = np.array([rule in s for s in rule_ids[current]])
        rows.append((rule, int(hit.sum()), int(y[hit].sum())))
    for rule, n, vulnerable in sorted(rows, key=lambda r: -r[1]):
        lines.append(f"| {rule} | {n} | {vulnerable} |")
    lines.append("")
    return lines


everything = np.ones(len(y), dtype=bool)

lines = ["# Effect of rule configuration changes on the CVEfixes test set", ""]
lines += describe("All 3636 test functions", everything)
lines += describe("Cleaned test set", keep)
lines += class_table("By vulnerability class, all test functions", everything)
lines += class_table("By vulnerability class, cleaned test set", keep)
lines += new_rule_table("Rule ids that appear only in v2 (not in v1)", "v1", "v2")
lines += new_rule_table("Rule ids that appear only in v3 (not in v2)", "v2", "v3")

text = "\n".join(lines)
(RES / "rule_config_diff.md").write_text(text, encoding="utf-8")
print(text)