from pathlib import Path

import numpy as np
import pandas as pd

from quality_filters import flag_rows, pair_keys

RES = Path("results")
PROC = Path("data/processed")

test = pd.read_csv(PROC / "test.csv", usecols=["code_hash", "lang", "file_change_id", "name", "label", "code"])
v1 = pd.read_csv(RES / "rule_detector_predictions.csv")
v2 = pd.read_csv(RES / "rule_detector_predictions_v2.csv")

assert len(test) == len(v1) == len(v2)
assert (test["code_hash"].values == v1["code_hash"].values).all(), "v1 order differs"
assert (test["code_hash"].values == v2["code_hash"].values).all(), "v2 order differs"

flags = flag_rows(test)
keys = pair_keys(test)
keep = ~keys.isin(set(keys[flags["suspect"]])).values

y = v1["label"].values.astype(int)


def any_flag(frame):
    for col in ["semgrep_n", "bandit_n", "eslint_n"]:
        frame[col] = frame[col].fillna(0).astype(int)
    linter_n = np.where(frame["lang"].values == "python", frame["bandit_n"].values, frame["eslint_n"].values)
    return (frame["semgrep_n"].values > 0) | (linter_n > 0)


f1 = any_flag(v1)
f2 = any_flag(v2)


def rule_id_sets(series):
    return [set(v for v in str(value).split(";") if v and v != "nan") for value in series]


ids1 = rule_id_sets(v1["semgrep_rules"])
ids2 = rule_id_sets(v2["semgrep_rules"])
new_ids = set().union(*ids2) - set().union(*ids1)


def describe(name, mask):
    yy = y[mask]
    a = f1[mask]
    b = f2[mask]
    new = b & ~a
    positives = int(yy.sum())

    def row(label, flagged):
        n = int(flagged.sum())
        precision = float(yy[flagged].mean()) if n else float("nan")
        recall = float(yy[flagged].sum() / positives)
        return f"| {label} | {n} | {precision:.4f} | {recall:.4f} |"

    lines = [f"## {name}", "", f"{int(mask.sum())} functions, {positives} vulnerable.", ""]
    lines.append("| Rule configuration | flagged | precision | recall |")
    lines.append("|---|---|---|---|")
    lines.append(row("original rulesets (v1)", a))
    lines.append(row("original + p/secrets + custom rules (v2)", b))
    lines.append(row("only newly flagged by v2", new))
    lines.append("")
    return lines


lines = ["# Effect of adding p/secrets and the custom rules on the CVEfixes test set", ""]
lines += describe("All 3636 test functions", np.ones(len(y), dtype=bool))
lines += describe("Cleaned test set", keep)

lines.append("## Rule ids that appear only in v2")
lines.append("")
lines.append("| rule id | functions flagged | of which vulnerable |")
lines.append("|---|---|---|")
rows = []
for rule in new_ids:
    hit = np.array([rule in s for s in ids2])
    rows.append((rule, int(hit.sum()), int(y[hit].sum())))
for rule, n, vulnerable in sorted(rows, key=lambda r: -r[1]):
    lines.append(f"| {rule} | {n} | {vulnerable} |")

text = "\n".join(lines)
(RES / "rule_config_diff.md").write_text(text, encoding="utf-8")
print(text)