from pathlib import Path

import numpy as np
import pandas as pd

RES = Path("results")

test = pd.read_csv("data/processed/test.csv", usecols=["code_hash", "file_change_id", "name", "label"])
rules = pd.read_csv(RES / "rule_detector_predictions.csv")
base = pd.read_csv(RES / "test_predictions_baseline.csv")
bert = pd.read_csv(RES / "test_predictions_codebert.csv")

assert len(test) == len(rules) == len(base) == len(bert)
for other in (rules, base, bert):
    assert (test["code_hash"].values == other["code_hash"].values).all(), "row order differs"

for col in ["semgrep_n", "bandit_n", "eslint_n"]:
    rules[col] = rules[col].fillna(0).astype(int)

is_python = (rules["lang"] == "python").values
linter_n = np.where(is_python, rules["bandit_n"], rules["eslint_n"])
semgrep_flag = (rules["semgrep_n"] > 0).values
linter_flag = linter_n > 0

frame = pd.DataFrame(
    {
        "pair_key": test["file_change_id"].astype(str) + "|" + test["name"].astype(str),
        "label": test["label"].values,
        "code_hash": test["code_hash"].values,
        "Semgrep": semgrep_flag.astype(int),
        "Bandit / ESLint": linter_flag.astype(int),
        "Rules combined": (semgrep_flag | linter_flag).astype(int),
        "TF-IDF + LR": base["lr_prob"].values,
        "TF-IDF + RF": base["rf_prob"].values,
        "CodeBERT": bert["codebert_prob"].values,
    }
)

sizes = frame.groupby("pair_key")["label"].agg(["size", "sum"])
valid = sizes[(sizes["size"] == 2) & (sizes["sum"] == 1)].index
paired = frame[frame["pair_key"].isin(valid)]

before = paired[paired["label"] == 1].set_index("pair_key")
after = paired[paired["label"] == 0].set_index("pair_key")
joined = before.join(after, lsuffix="_before", rsuffix="_after")

lines = ["# Before-fix vs after-fix pairs on the held-out test set", ""]
lines.append(f"- test rows: {len(frame)}")
lines.append(f"- pair groups found (exactly one vulnerable and one fixed row): {len(joined)}")
lines.append(f"- rows covered by pairs: {2 * len(joined)}")
lines.append(f"- pairs where both versions have identical code: {int((joined['code_hash_before'] == joined['code_hash_after']).sum())}")
lines.append("")

lines.append("## Rule tools: how often do they treat the two versions the same way")
lines.append("")
lines.append("| Tool | same answer for both | flags only the vulnerable version | flags only the fixed version | flags both |")
lines.append("|---|---|---|---|---|")
for tool in ["Semgrep", "Bandit / ESLint", "Rules combined"]:
    b = joined[f"{tool}_before"].values
    a = joined[f"{tool}_after"].values
    lines.append(
        f"| {tool} | {(b == a).mean():.4f} | {((b == 1) & (a == 0)).mean():.4f} | "
        f"{((b == 0) & (a == 1)).mean():.4f} | {((b == 1) & (a == 1)).mean():.4f} |"
    )
lines.append("")

lines.append("## ML models: how often is the vulnerable version scored higher")
lines.append("")
lines.append("| Model | vulnerable scored higher | ties | pairwise accuracy (ties count half) |")
lines.append("|---|---|---|---|")
for model in ["TF-IDF + LR", "TF-IDF + RF", "CodeBERT"]:
    b = joined[f"{model}_before"].values
    a = joined[f"{model}_after"].values
    wins = (b > a).mean()
    ties = (b == a).mean()
    lines.append(f"| {model} | {wins:.4f} | {ties:.4f} | {wins + 0.5 * ties:.4f} |")

text = "\n".join(lines)
(RES / "pair_agreement.md").write_text(text, encoding="utf-8")
print(text)