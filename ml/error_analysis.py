from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

RES = Path("results")
PROC = Path("data/processed")
MIN_REPO_ROWS = 20
CLASSES = ["sql_injection", "xss", "auth", "other"]

clean = pd.read_csv(PROC / "test_clean.csv", usecols=["code_hash", "lang", "label"])
base = pd.read_csv(RES / "clean_baseline_predictions.csv")
bert = pd.read_csv(RES / "test_predictions_codebert_clean_seeds.csv")

assert len(clean) == len(base) == len(bert)
for other in (base, bert):
    assert (clean["code_hash"].values == other["code_hash"].values).all(), "row order differs"
    assert (clean["label"].values == other["label"].values).all(), "labels differ"

y = base["label"].values.astype(int)
category = base["category"].fillna("other").values
repos = base["repo_url"].values
lang = clean["lang"].values
seed_cols = [c for c in bert.columns if c.startswith("codebert_prob_seed")]

models = {
    "TF-IDF + LR": [base["lr_prob"].values],
    "TF-IDF + RF": [base["rf_prob"].values],
    "CodeBERT (mean of seeds)": [bert[c].values for c in seed_cols],
}


def aucs(mask, arrays):
    yy = y[mask]
    if len(set(yy)) < 2:
        return None, None
    roc = float(np.mean([roc_auc_score(yy, a[mask]) for a in arrays]))
    pr = float(np.mean([average_precision_score(yy, a[mask]) for a in arrays]))
    return roc, pr


def fmt(value):
    return "-" if value is None else f"{value:.4f}"


def table(title, groups):
    lines = [f"## {title}", ""]
    header = ["Group", "functions", "vulnerable"]
    for name in models:
        header += [f"{name} ROC", f"{name} PR"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|---|---|---|" + "---|---|" * len(models))
    for label, mask in groups:
        row = [label, str(int(mask.sum())), str(int(y[mask].sum()))]
        for arrays in models.values():
            roc, pr = aucs(mask, arrays)
            row += [fmt(roc), fmt(pr)]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return lines


counts = pd.Series(repos).value_counts()
top_repo = counts.index[0]
top_share = counts.iloc[0] / len(y)

lines = ["# Error analysis on the cleaned test set", ""]
lines.append("Point estimates without confidence intervals, so read them as descriptive. Within each group the AUC separates vulnerable from fixed functions of that group only. CodeBERT rows average the AUC over the seeds.")
lines.append("")
lines += table("By vulnerability class", [(c, category == c) for c in CLASSES])
lines += table("By language", [(l, lang == l) for l in ["python", "javascript"]])
lines += table(
    f"Without the largest repo ({top_repo}, {top_share * 100:.1f}% of rows)",
    [
        ("all repos", np.ones(len(y), dtype=bool)),
        ("without the largest repo", repos != top_repo),
        ("only the largest repo", repos == top_repo),
    ],
)

lines.append(f"## Per-repo ROC-AUC (repos with at least {MIN_REPO_ROWS} functions and both classes)")
lines.append("")
lines.append("| Model | repos | median ROC-AUC | repos above 0.5 | repos below 0.5 |")
lines.append("|---|---|---|---|---|")
eligible = []
for repo, n in counts.items():
    mask = repos == repo
    if n >= MIN_REPO_ROWS and len(set(y[mask])) == 2:
        eligible.append(mask)
for name, arrays in models.items():
    values = np.array([aucs(m, arrays)[0] for m in eligible])
    if len(values) == 0:
        lines.append(f"| {name} | 0 | - | - | - |")
        continue
    lines.append(
        f"| {name} | {len(values)} | {np.median(values):.4f} | {int((values > 0.5).sum())} | {int((values < 0.5).sum())} |"
    )

text = "\n".join(lines)
(RES / "error_analysis.md").write_text(text, encoding="utf-8")
print(text)