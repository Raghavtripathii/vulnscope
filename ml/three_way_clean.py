from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

from quality_filters import flag_rows, pair_keys

RES = Path("results")
PROC = Path("data/processed")
IN_SCOPE = ["sql_injection", "xss", "auth"]

test = pd.read_csv(PROC / "test.csv", usecols=["code_hash", "lang", "file_change_id", "name", "label", "code"])
rules_all = pd.read_csv(RES / "rule_detector_predictions.csv")
base = pd.read_csv(RES / "clean_baseline_predictions.csv")
bert = pd.read_csv(RES / "test_predictions_codebert_clean_seeds.csv")

assert len(test) == len(rules_all)
assert (test["code_hash"].values == rules_all["code_hash"].values).all(), "rule results do not match test.csv order"

flags = flag_rows(test)
keys = pair_keys(test)
keep = ~keys.isin(set(keys[flags["suspect"]]))
rules = rules_all[keep.values].reset_index(drop=True)

assert len(rules) == len(base) == len(bert), "cleaned row counts differ"
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
category = base["category"].fillna("other").values

rule_models = {
    "Semgrep": semgrep_flag.astype(int),
    "Bandit / ESLint": linter_flag.astype(int),
    "Rules combined": (semgrep_flag | linter_flag).astype(int),
}
seed_cols = [c for c in bert.columns if c.startswith("codebert_prob_seed")]
ml_scores = {
    "Length only LR": [base["length_prob"].values],
    "TF-IDF + LR": [base["lr_prob"].values],
    "TF-IDF + RF": [base["rf_prob"].values],
    "CodeBERT (5 seeds, averaged)": [bert[c].values for c in seed_cols],
}

views = {
    "All cleaned test functions": np.ones(len(y), dtype=bool),
    "Parsed by every applicable rule tool": parsed,
    "In-scope classes only (sql_injection, xss, auth)": np.isin(category, IN_SCOPE),
    "In-scope and parsed": np.isin(category, IN_SCOPE) & parsed,
}


def prf(y_true, pred):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", pos_label=1, zero_division=0
    )
    both = len(set(y_true)) > 1
    balanced = balanced_accuracy_score(y_true, pred) if both else float("nan")
    return np.array([precision, recall, f1, balanced])


def top_k(score, k):
    pred = np.zeros(len(score), dtype=int)
    if k > 0:
        pred[np.argsort(-score, kind="stable")[:k]] = 1
    return pred


def fmt(value):
    if value is None:
        return "-"
    return f"{value:.4f}"


lines = ["# Three-way comparison on the cleaned test set", ""]
lines.append("Rule tools flag a function if they report any finding. ML models are shown at the same alert count as 'Rules combined' in each view (their top-scoring functions), so threshold choice does not matter. Ties in score are broken by row order. CodeBERT rows average the 5 seeds. AUCs use the raw scores. The random-alerts row shows what flagging the same number of functions at random would give.")
lines.append("")

for view_name, mask in views.items():
    yv = y[mask]
    k = int(rule_models["Rules combined"][mask].sum())
    lines.append(f"## {view_name}")
    lines.append("")
    lines.append(f"{len(yv)} functions, {int(yv.sum())} vulnerable, rule tools flag {k} in total.")
    lines.append("")
    lines.append("| Model | flagged | precision | recall | f1 | balanced_acc | roc_auc | pr_auc |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for name, pred in rule_models.items():
        vals = prf(yv, pred[mask])
        lines.append(f"| {name} | {int(pred[mask].sum())} | " + " | ".join(fmt(v) for v in vals) + " | - | - |")
    base_rate = float(yv.mean())
    chance_recall = k / len(yv)
    chance_f1 = 2 * base_rate * chance_recall / (base_rate + chance_recall) if (base_rate + chance_recall) > 0 else 0.0
    lines.append(f"| Random alerts (reference) | {k} | {fmt(base_rate)} | {fmt(chance_recall)} | {fmt(chance_f1)} | 0.5000 | - | - |")
    for name, arrays in ml_scores.items():
        vals, rocs, prs = [], [], []
        for s in arrays:
            sv = s[mask]
            vals.append(prf(yv, top_k(sv, k)))
            rocs.append(roc_auc_score(yv, sv))
            prs.append(average_precision_score(yv, sv))
        mean_vals = np.mean(vals, axis=0)
        lines.append(
            f"| {name} | {k} | " + " | ".join(fmt(v) for v in mean_vals)
            + f" | {fmt(float(np.mean(rocs)))} | {fmt(float(np.mean(prs)))} |"
        )
    lines.append("")

k_all = int(rule_models["Rules combined"].sum())
lines.append("## Per class (all cleaned rows): recall on vulnerable functions / false-alarm rate on fixed functions")
lines.append("")
lines.append(f"ML models flag their top {k_all} functions overall, the same count as the rule tools.")
lines.append("")
header = ["Model"]
for c in IN_SCOPE:
    header += [f"{c} recall", f"{c} false alarms"]
lines.append("| " + " | ".join(header) + " |")
lines.append("|---|" + "---|" * (len(header) - 1))


def class_cells(pred_list):
    cells = []
    for c in IN_SCOPE:
        positives = (y == 1) & (category == c)
        negatives = (y == 0) & (category == c)
        recall = np.mean([p[positives].mean() for p in pred_list]) if positives.any() else None
        false_alarm = np.mean([p[negatives].mean() for p in pred_list]) if negatives.any() else None
        cells += [fmt(recall), fmt(false_alarm)]
    return cells


for name, pred in rule_models.items():
    lines.append("| " + " | ".join([name] + class_cells([pred])) + " |")
for name, arrays in ml_scores.items():
    preds = [top_k(s, k_all) for s in arrays]
    lines.append("| " + " | ".join([name] + class_cells(preds)) + " |")
lines.append("")
for c in IN_SCOPE:
    lines.append(f"- {c}: {int(((y == 1) & (category == c)).sum())} vulnerable, {int(((y == 0) & (category == c)).sum())} fixed")
lines.append("")
lines.append("## Parse coverage on the cleaned set")
lines.append("")
for lang in ["python", "javascript"]:
    lang_mask = rules["lang"].values == lang
    lines.append(f"- {lang}: {int(lang_mask.sum())} functions, parsed by every applicable rule tool: {int((parsed & lang_mask).sum())}")

text = "\n".join(lines)
(RES / "three_way_clean.md").write_text(text, encoding="utf-8")
print(text)