import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

SEED = 42
N_RESAMPLES = 2000
CODEBERT_PATH = Path("results/test_predictions_codebert.csv")
BASELINE_PATH = Path("results/test_predictions_baseline.csv")
OUT_JSON = Path("results/bootstrap_results.json")
OUT_MD = Path("results/bootstrap_results.md")
MODELS = ["codebert", "lr", "rf"]
LABELS = {"codebert": "CodeBERT", "lr": "TF-IDF + Logistic Regression", "rf": "TF-IDF + Random Forest"}


def load_predictions():
    codebert = pd.read_csv(CODEBERT_PATH)
    baseline = pd.read_csv(BASELINE_PATH)
    assert len(codebert) == len(baseline), "prediction files have different lengths"
    assert (codebert["code_hash"].values == baseline["code_hash"].values).all(), "rows are not in the same order"
    assert (codebert["label"].values == baseline["label"].values).all(), "labels differ between files"
    frame = codebert[["code_hash", "repo_url", "label"]].copy()
    frame["codebert"] = codebert["codebert_prob"].values
    frame["lr"] = baseline["lr_prob"].values
    frame["rf"] = baseline["rf_prob"].values
    return frame


def interval(values):
    low, high = np.percentile(values, [2.5, 97.5])
    return [round(float(low), 4), round(float(high), 4)]


def main():
    frame = load_predictions()
    y = frame["label"].values
    scores = {m: frame[m].values for m in MODELS}

    groups = list(frame.groupby("repo_url").indices.values())
    sizes = sorted((len(g) for g in groups), reverse=True)
    top_share = round(sum(sizes[:3]) / len(frame), 3)
    print(f"{len(groups)} test repos, {len(frame)} rows. Largest repos hold {sizes[:5]} rows; top 3 = {top_share:.1%} of the test set.")

    full = {
        m: {
            "roc_auc": float(roc_auc_score(y, scores[m])),
            "pr_auc": float(average_precision_score(y, scores[m])),
        }
        for m in MODELS
    }

    rng = np.random.default_rng(SEED)
    draws = {m: {"roc_auc": [], "pr_auc": []} for m in MODELS}
    used = 0
    for _ in range(N_RESAMPLES):
        picks = rng.integers(0, len(groups), size=len(groups))
        index = np.concatenate([groups[i] for i in picks])
        y_boot = y[index]
        if y_boot.min() == y_boot.max():
            continue
        used += 1
        for m in MODELS:
            draws[m]["roc_auc"].append(roc_auc_score(y_boot, scores[m][index]))
            draws[m]["pr_auc"].append(average_precision_score(y_boot, scores[m][index]))
    draws = {m: {k: np.array(v) for k, v in d.items()} for m, d in draws.items()}
    print(f"Used {used} of {N_RESAMPLES} resamples.")

    summary = {"n_repos": len(groups), "n_rows": int(len(frame)), "resamples_used": used, "models": {}, "paired": {}}
    for m in MODELS:
        summary["models"][m] = {
            "roc_auc": round(full[m]["roc_auc"], 4),
            "roc_auc_ci95": interval(draws[m]["roc_auc"]),
            "share_of_resamples_roc_auc_at_or_below_0.5": round(float((draws[m]["roc_auc"] <= 0.5).mean()), 4),
            "pr_auc": round(full[m]["pr_auc"], 4),
            "pr_auc_ci95": interval(draws[m]["pr_auc"]),
        }

    for other in ("lr", "rf"):
        entry = {}
        for metric in ("roc_auc", "pr_auc"):
            diff = draws["codebert"][metric] - draws[other][metric]
            entry[metric] = {
                "difference": round(full["codebert"][metric] - full[other][metric], 4),
                "ci95": interval(diff),
                "share_of_resamples_codebert_better": round(float((diff > 0).mean()), 4),
            }
        summary["paired"][f"codebert_minus_{other}"] = entry

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(summary, indent=2))

    lines = [
        "# Repo-level bootstrap (held-out repos)",
        "",
        f"{len(groups)} test repos, {len(frame)} rows, {used} resamples that resample whole repos with replacement. Intervals are 95% percentile intervals.",
        "",
        "| Model | ROC-AUC | ROC-AUC 95% CI | PR-AUC | PR-AUC 95% CI |",
        "|---|---|---|---|---|",
    ]
    for m in MODELS:
        s = summary["models"][m]
        lines.append(f"| {LABELS[m]} | {s['roc_auc']} | {s['roc_auc_ci95']} | {s['pr_auc']} | {s['pr_auc_ci95']} |")
    lines += [
        "",
        "| Comparison | Metric | Difference | 95% CI of difference | Resamples where CodeBERT is better |",
        "|---|---|---|---|---|",
    ]
    for key, entry in summary["paired"].items():
        for metric, values in entry.items():
            lines.append(
                f"| {key} | {metric} | {values['difference']} | {values['ci95']} | {values['share_of_resamples_codebert_better']:.1%} |"
            )
    OUT_MD.write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()