from pathlib import Path

import numpy as np
import pandas as pd

RES = Path("results")
SEED = 42
RESAMPLES = 2000
LENGTH = "Length only (longer = vulnerable)"
MODELS = [LENGTH, "TF-IDF + LR", "TF-IDF + RF", "CodeBERT"]

test = pd.read_csv(
    "data/processed/test.csv",
    usecols=["code_hash", "repo_url", "file_change_id", "name", "label", "code"],
)
base = pd.read_csv(RES / "test_predictions_baseline.csv")
bert = pd.read_csv(RES / "test_predictions_codebert.csv")

assert len(test) == len(base) == len(bert)
for other in (base, bert):
    assert (test["code_hash"].values == other["code_hash"].values).all(), "row order differs"

frame = pd.DataFrame(
    {
        "pair_key": test["file_change_id"].astype(str) + "|" + test["name"].astype(str),
        "repo_url": test["repo_url"].values,
        "label": test["label"].values,
        LENGTH: test["code"].str.len().values.astype(float),
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

repos, repo_index = np.unique(joined["repo_url_before"].values, return_inverse=True)
n_repos = len(repos)
pair_counts = np.bincount(repo_index, minlength=n_repos).astype(float)

repo_sums = []
point = []
for model in MODELS:
    b = joined[f"{model}_before"].values
    a = joined[f"{model}_after"].values
    per_pair = np.where(b > a, 1.0, np.where(b == a, 0.5, 0.0))
    repo_sums.append(np.bincount(repo_index, weights=per_pair, minlength=n_repos))
    point.append(per_pair.mean())
repo_sums = np.array(repo_sums)

rng = np.random.default_rng(SEED)
draws = rng.integers(0, n_repos, size=(RESAMPLES, n_repos))
numerators = repo_sums[:, draws].sum(axis=2)
denominators = pair_counts[draws].sum(axis=1)
accuracy = numerators / denominators

lines = ["# Pairwise accuracy with repo-level bootstrap", ""]
lines.append(f"{len(joined)} pairs from {n_repos} held-out repos, {RESAMPLES} resamples of whole repos, 95% percentile intervals. Ties count half.")
lines.append("")
lines.append("| Model | pairwise accuracy | 95% CI |")
lines.append("|---|---|---|")
for i, model in enumerate(MODELS):
    low, high = np.percentile(accuracy[i], [2.5, 97.5])
    lines.append(f"| {model} | {point[i]:.4f} | [{low:.4f}, {high:.4f}] |")
lines.append("")
lines.append("| Comparison | difference | 95% CI of difference | resamples where CodeBERT is better |")
lines.append("|---|---|---|---|")
bert_i = MODELS.index("CodeBERT")
for i, model in enumerate(MODELS):
    if i == bert_i:
        continue
    diff = accuracy[bert_i] - accuracy[i]
    low, high = np.percentile(diff, [2.5, 97.5])
    lines.append(f"| CodeBERT minus {model} | {point[bert_i] - point[i]:.4f} | [{low:.4f}, {high:.4f}] | {(diff > 0).mean() * 100:.1f}% |")

text = "\n".join(lines)
(RES / "pair_bootstrap.md").write_text(text, encoding="utf-8")
print(text)