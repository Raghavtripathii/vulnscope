from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from quality_filters import flag_rows, pair_keys

RES = Path("results")
PROC = Path("data/processed")
IN_SCOPE = ["sql_injection", "xss", "auth"]
SEED = 42
RESAMPLES = 2000

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

for col in ["semgrep_n", "bandit_n", "eslint_n"]:
    rules[col] = rules[col].fillna(0).astype(int)

is_python = (rules["lang"] == "python").values
linter_n = np.where(is_python, rules["bandit_n"], rules["eslint_n"])
rules_flag = ((rules["semgrep_n"].values > 0) | (linter_n > 0)).astype(int)

y = rules["label"].values.astype(int)
repos = base["repo_url"].values
category = base["category"].fillna("other").values
lr_score = base["lr_prob"].values
seed_cols = [c for c in bert.columns if c.startswith("codebert_prob_seed")]
cb_score = np.mean([bert[c].values for c in seed_cols], axis=0)


def top_k(score, k):
    pred = np.zeros(len(score), dtype=int)
    if k > 0:
        pred[np.argsort(-score, kind="stable")[:k]] = 1
    return pred


def pct_rank(score):
    ranks = np.argsort(np.argsort(score, kind="stable"), kind="stable")
    return ranks / (len(score) - 1)


def precision_of(yy, pred):
    n = int(pred.sum())
    return float(yy[pred == 1].mean()) if n else float("nan")


def eval_rows(idx):
    yy = y[idx]
    r = rules_flag[idx]
    lr = lr_score[idx]
    cb = cb_score[idx]
    k = int(r.sum())
    soft = r + pct_rank(lr) + pct_rank(cb)
    out = {"k": k, "Rules": precision_of(yy, r)}
    for name, s in {"LR": lr, "CodeBERT": cb, "Soft vote": soft}.items():
        out[name] = precision_of(yy, top_k(s, k))
        out[name + " roc"] = roc_auc_score(yy, s)
        out[name + " pr"] = average_precision_score(yy, s)
    return out


def point_table(idx):
    yy = y[idx]
    r = rules_flag[idx]
    lr = lr_score[idx]
    cb = cb_score[idx]
    k = int(r.sum())
    soft = r + pct_rank(lr) + pct_rank(cb)
    positives = int(yy.sum())
    rows = []

    def add(name, pred, roc=None, pr=None):
        n = int(pred.sum())
        precision = float(yy[pred == 1].mean()) if n else float("nan")
        recall = float(yy[pred == 1].sum() / positives)
        f1 = 2 * precision * recall / (precision + recall) if n and (precision + recall) > 0 else 0.0
        rows.append((name, n, precision, recall, f1, roc, pr))

    add("Rules (any finding)", r)
    add("TF-IDF + LR (top alerts)", top_k(lr, k), roc_auc_score(yy, lr), average_precision_score(yy, lr))
    add("CodeBERT 5-seed average (top alerts)", top_k(cb, k), roc_auc_score(yy, cb), average_precision_score(yy, cb))
    add("Soft vote (top alerts)", top_k(soft, k), roc_auc_score(yy, soft), average_precision_score(yy, soft))
    votes = r + top_k(lr, k) + top_k(cb, k)
    for t in (1, 2, 3):
        add(f"Hard vote, at least {t} of 3", (votes >= t).astype(int))
    base_rate = float(yy.mean())
    recall_random = k / len(yy)
    f1_random = 2 * base_rate * recall_random / (base_rate + recall_random)
    rows.append(("Random alerts (reference)", k, base_rate, recall_random, f1_random, None, None))
    return k, rows


def fmt(value):
    if value is None:
        return "-"
    return f"{value:.4f}"


def bootstrap(view_idx):
    names, inverse = np.unique(repos[view_idx], return_inverse=True)
    groups = [view_idx[inverse == j] for j in range(len(names))]
    rng = np.random.default_rng(SEED)
    comparisons = [
        ("precision at same alert count", "Soft vote", other, None) for other in ["Rules", "LR", "CodeBERT"]
    ] + [
        (metric_name, "Soft vote", other, suffix)
        for metric_name, suffix in [("ROC-AUC", " roc"), ("PR-AUC", " pr")]
        for other in ["LR", "CodeBERT"]
    ]
    draws = {c: [] for c in comparisons}
    for _ in range(RESAMPLES):
        picks = rng.integers(0, len(groups), len(groups))
        idx = np.concatenate([groups[j] for j in picks])
        m = eval_rows(idx)
        for c in comparisons:
            metric, first, second, suffix = c
            key_a = first if suffix is None else first + suffix
            key_b = second if suffix is None else second + suffix
            draws[c].append(m[key_a] - m[key_b])
    return names, draws


lines = ["# Hybrid combiner on the cleaned test set", ""]
lines.append("Design fixed before looking at results. Voters: rule tools (flag = any finding), TF-IDF + LR, and CodeBERT (average probability over 5 seeds). ML voters flag their top-k functions, where k is the number of functions the rule tools flag in the same set, so every voter raises the same number of alerts. Soft vote = rule flag (0 or 1) + LR rank percentile + CodeBERT rank percentile, equal weights, nothing tuned. Hard votes count how many voters flag a function. Intervals resample whole repos, 2000 times, 95% percentile.")
lines.append("")

views = {
    "All cleaned test functions": np.arange(len(y)),
    "In-scope classes only (sql_injection, xss, auth)": np.where(np.isin(category, IN_SCOPE))[0],
}
for view_name, view_idx in views.items():
    k, rows = point_table(view_idx)
    lines.append(f"## {view_name}")
    lines.append("")
    lines.append(f"{len(view_idx)} functions, {int(y[view_idx].sum())} vulnerable, k = {k}.")
    lines.append("")
    lines.append("| Method | alerts | precision | recall | f1 | roc_auc | pr_auc |")
    lines.append("|---|---|---|---|---|---|---|")
    for name, n, precision, recall, f1, roc, pr in rows:
        lines.append(f"| {name} | {n} | {fmt(precision)} | {fmt(recall)} | {fmt(f1)} | {fmt(roc)} | {fmt(pr)} |")
    lines.append("")
    names, draws = bootstrap(view_idx)
    lines.append(f"Repo-level bootstrap over {len(names)} repos: soft vote minus each part")
    lines.append("")
    lines.append("| Metric | Soft vote minus | difference | 95% CI | resamples where soft vote is better |")
    lines.append("|---|---|---|---|---|")
    for (metric, first, second, suffix), values in draws.items():
        arr = np.array(values)
        low, high = np.nanpercentile(arr, [2.5, 97.5])
        lines.append(
            f"| {metric} | {second} | {np.nanmean(arr):.4f} | [{low:.4f}, {high:.4f}] | {np.nanmean(arr > 0) * 100:.1f}% |"
        )
    lines.append("")

text = "\n".join(lines)
(RES / "hybrid_combiner.md").write_text(text, encoding="utf-8")
print(text)