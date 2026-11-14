from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

RES = Path("results")
SEED = 42
RESAMPLES = 2000
CODEBERT = "CodeBERT (mean over seeds)"
NAMES = ["Length only LR", "TF-IDF + LR", "TF-IDF + RF", CODEBERT]

base = pd.read_csv(RES / "clean_baseline_predictions.csv")
bert = pd.read_csv(RES / "test_predictions_codebert_clean_seeds.csv")
assert len(base) == len(bert)
assert (base["code_hash"].values == bert["code_hash"].values).all(), "row order differs"
assert (base["label"].values == bert["label"].values).all(), "labels differ"

y = base["label"].values.astype(int)
repos = base["repo_url"].values
seed_cols = [c for c in bert.columns if c.startswith("codebert_prob_seed")]
seed_scores = [bert[c].values for c in seed_cols]
singles = {
    "Length only LR": base["length_prob"].values,
    "TF-IDF + LR": base["lr_prob"].values,
    "TF-IDF + RF": base["rf_prob"].values,
}


def metrics_on(idx):
    yy = y[idx]
    out = {}
    for name, s in singles.items():
        out[name] = (roc_auc_score(yy, s[idx]), average_precision_score(yy, s[idx]))
    rocs = [roc_auc_score(yy, s[idx]) for s in seed_scores]
    prs = [average_precision_score(yy, s[idx]) for s in seed_scores]
    out[CODEBERT] = (float(np.mean(rocs)), float(np.mean(prs)))
    return out, rocs, prs


all_idx = np.arange(len(y))
point, seed_rocs, seed_prs = metrics_on(all_idx)
ensemble = np.mean(seed_scores, axis=0)
ensemble_point = (roc_auc_score(y, ensemble), average_precision_score(y, ensemble))

repo_names, inverse = np.unique(repos, return_inverse=True)
n_repos = len(repo_names)
rows_by_repo = [np.where(inverse == k)[0] for k in range(n_repos)]

rng = np.random.default_rng(SEED)
boot = {name: np.zeros((RESAMPLES, 2)) for name in NAMES}
for r in range(RESAMPLES):
    picks = rng.integers(0, n_repos, n_repos)
    idx = np.concatenate([rows_by_repo[k] for k in picks])
    result, _, _ = metrics_on(idx)
    for name in NAMES:
        boot[name][r] = result[name]

lines = ["# Cleaned test set: CodeBERT (5 seeds) vs classical baselines", ""]
lines.append(f"{len(y)} test functions from {n_repos} held-out repos. Base rate {y.mean():.4f}. {RESAMPLES} resamples of whole repos, 95% percentile intervals.")
lines.append("")
lines.append("## Per-seed check (recomputed from the saved predictions)")
lines.append("")
lines.append("| Seed column | ROC-AUC | PR-AUC |")
lines.append("|---|---|---|")
for col, roc, pr in zip(seed_cols, seed_rocs, seed_prs):
    lines.append(f"| {col} | {roc:.4f} | {pr:.4f} |")
lines.append("")
lines.append("## Point estimates and repo-level intervals")
lines.append("")
lines.append("| Model | ROC-AUC | ROC-AUC 95% CI | PR-AUC | PR-AUC 95% CI |")
lines.append("|---|---|---|---|---|")
for name in NAMES:
    roc_low, roc_high = np.percentile(boot[name][:, 0], [2.5, 97.5])
    pr_low, pr_high = np.percentile(boot[name][:, 1], [2.5, 97.5])
    lines.append(
        f"| {name} | {point[name][0]:.4f} | [{roc_low:.4f}, {roc_high:.4f}] | "
        f"{point[name][1]:.4f} | [{pr_low:.4f}, {pr_high:.4f}] |"
    )
lines.append("")
lines.append(f"Seed-averaged probabilities (an ensemble, point estimate only): ROC-AUC {ensemble_point[0]:.4f}, PR-AUC {ensemble_point[1]:.4f}.")
lines.append("")
lines.append("## CodeBERT minus each baseline")
lines.append("")
lines.append("| Comparison | Metric | Difference | 95% CI of difference | Resamples where CodeBERT is better |")
lines.append("|---|---|---|---|---|")
for name in NAMES[:-1]:
    for column, metric in [(0, "roc_auc"), (1, "pr_auc")]:
        diff = boot[CODEBERT][:, column] - boot[name][:, column]
        low, high = np.percentile(diff, [2.5, 97.5])
        lines.append(
            f"| CodeBERT minus {name} | {metric} | {point[CODEBERT][column] - point[name][column]:.4f} | "
            f"[{low:.4f}, {high:.4f}] | {(diff > 0).mean() * 100:.1f}% |"
        )

text = "\n".join(lines)
(RES / "clean_compare.md").write_text(text, encoding="utf-8")
print(text)