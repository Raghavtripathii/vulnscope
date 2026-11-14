import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

RES = Path("results")
IN_SCOPE = ["sql_injection", "xss", "auth"]

rules = pd.read_csv(RES / "rule_detector_predictions.csv")
base = pd.read_csv(RES / "test_predictions_baseline.csv")
bert = pd.read_csv(RES / "test_predictions_codebert.csv")

assert len(rules) == len(base) == len(bert)
for other in (base, bert):
    assert (rules["code_hash"].values == other["code_hash"].values).all(), "row order differs"
    assert (rules["label"].values == other["label"].values).all(), "labels differ"

for col in ["semgrep_scanned", "semgrep_n", "bandit_scanned", "bandit_n", "eslint_scanned", "eslint_n"]:
    rules[col] = rules[col].fillna(0).astype(int)

is_python = (rules["lang"] == "python").values
linter_n = np.where(is_python, rules["bandit_n"], rules["eslint_n"])
linter_scanned = np.where(is_python, rules["bandit_scanned"], rules["eslint_scanned"])

semgrep_flag = (rules["semgrep_n"] > 0).values
linter_flag = linter_n > 0
parsed = (rules["semgrep_scanned"].values == 1) & (linter_scanned == 1)

y = rules["label"].values.astype(int)
category = rules["category"].fillna("other").values

models = {
    "Semgrep": (semgrep_flag.astype(int), None),
    "Bandit / ESLint": (linter_flag.astype(int), None),
    "Rules combined (any finding)": ((semgrep_flag | linter_flag).astype(int), None),
    "TF-IDF + LR": ((base["lr_prob"].values >= 0.5).astype(int), base["lr_prob"].values),
    "TF-IDF + RF": ((base["rf_prob"].values >= 0.5).astype(int), base["rf_prob"].values),
    "CodeBERT": ((bert["codebert_prob"].values >= 0.5).astype(int), bert["codebert_prob"].values),
}

views = {
    "All test functions": np.ones(len(y), dtype=bool),
    "Parsed by every applicable rule tool": parsed,
    "In-scope classes only (sql_injection, xss, auth)": np.isin(category, IN_SCOPE),
    "In-scope and parsed": np.isin(category, IN_SCOPE) & parsed,
}


def summarize(y_true, pred, score):
    if len(y_true) == 0:
        return None
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", pos_label=1, zero_division=0
    )
    both_classes = len(set(y_true)) > 1
    out = {
        "n": int(len(y_true)),
        "vulnerable": int(y_true.sum()),
        "flagged": int(pred.sum()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "balanced_acc": float(balanced_accuracy_score(y_true, pred)) if both_classes else None,
        "pr_auc": None,
        "roc_auc": None,
    }
    if score is not None and both_classes:
        out["pr_auc"] = float(average_precision_score(y_true, score))
        out["roc_auc"] = float(roc_auc_score(y_true, score))
    return out


def fmt(value):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


results = {"views": {}, "per_category": {}}
lines = ["# Three-way comparison on held-out test functions", ""]
lines.append("Rule tools give a yes/no flag per function (any finding = vulnerable), so they have no AUC. ML models use threshold 0.5 for the flag columns; AUCs use the raw probability.")
lines.append("")

columns = ["n", "vulnerable", "flagged", "precision", "recall", "f1", "balanced_acc", "pr_auc", "roc_auc"]
for view_name, mask in views.items():
    lines.append(f"## {view_name}")
    lines.append("")
    lines.append("| Model | " + " | ".join(columns) + " |")
    lines.append("|---|" + "---|" * len(columns))
    results["views"][view_name] = {}
    for model_name, (pred, score) in models.items():
        summary = summarize(y[mask], pred[mask], score[mask] if score is not None else None)
        results["views"][view_name][model_name] = summary
        if summary is None:
            continue
        lines.append(f"| {model_name} | " + " | ".join(fmt(summary[c]) for c in columns) + " |")
    lines.append("")

lines.append("## Per class: recall on vulnerable functions and false-alarm rate on fixed functions")
lines.append("")
header = ["Model"]
for c in IN_SCOPE:
    header += [f"{c} recall", f"{c} false alarms"]
lines.append("| " + " | ".join(header) + " |")
lines.append("|---|" + "---|" * (len(header) - 1))
for model_name, (pred, _) in models.items():
    row = [model_name]
    results["per_category"][model_name] = {}
    for c in IN_SCOPE:
        positives = (y == 1) & (category == c)
        negatives = (y == 0) & (category == c)
        recall = float(pred[positives].mean()) if positives.any() else None
        false_alarm = float(pred[negatives].mean()) if negatives.any() else None
        results["per_category"][model_name][c] = {
            "vulnerable": int(positives.sum()),
            "fixed": int(negatives.sum()),
            "recall": recall,
            "false_alarm_rate": false_alarm,
        }
        row += [fmt(recall), fmt(false_alarm)]
    lines.append("| " + " | ".join(row) + " |")
lines.append("")

lines.append("## Parse coverage")
lines.append("")
for lang in ["python", "javascript"]:
    lang_mask = rules["lang"].values == lang
    lines.append(f"- {lang}: {int(lang_mask.sum())} functions, parsed by every applicable rule tool: {int((parsed & lang_mask).sum())}")

text = "\n".join(lines)
(RES / "three_way_table.md").write_text(text, encoding="utf-8")
(RES / "three_way_table.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print(text)