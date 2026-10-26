import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

SEED = 42
RF_TREES = 100   # lower to 40 if it runs too long
IN = Path("data/processed/dataset.csv")
RES = Path("results")
RES.mkdir(exist_ok=True)

df = pd.read_csv(IN)
df["category"] = df["category"].fillna("other")

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
tr_idx, te_idx = next(gss.split(df, df["label"], groups=df["repo_url"]))
train, test = df.iloc[tr_idx].copy(), df.iloc[te_idx].copy()
assert set(train["repo_url"]).isdisjoint(set(test["repo_url"])), "repo leakage!"
train.to_csv("data/processed/train.csv", index=False)
test.to_csv("data/processed/test.csv", index=False)

print(f"train: {len(train)} rows, {train['repo_url'].nunique()} repos, vulnerable rate {train['label'].mean():.3f}")
print(f"test : {len(test)} rows, {test['repo_url'].nunique()} repos, vulnerable rate {test['label'].mean():.3f}")

ytr, yte = train["label"].values, test["label"].values


def evaluate(name, pred, score):
    p, r, f1, _ = precision_recall_fscore_support(
        yte, pred, average="binary", pos_label=1, zero_division=0
    )
    out = {
        "model": name,
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "pr_auc": round(float(average_precision_score(yte, score)), 4),
        "roc_auc": round(float(roc_auc_score(yte, score)), 4) if len(set(score)) > 1 else 0.5,
        "confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(yte, pred, labels=[0, 1]).tolist(),
    }
    per_cat = {}
    for cat in ["sql_injection", "xss", "secrets", "auth"]:
        mask = (yte == 1) & (test["category"].values == cat)
        n = int(mask.sum())
        per_cat[cat] = {
            "n_vulnerable_in_test": n,
            "recall": round(float((pred[mask] == 1).mean()), 4) if n else None,
        }
    out["per_category_recall"] = per_cat
    return out


results = []

dummy = DummyClassifier(strategy="most_frequent").fit(np.zeros((len(ytr), 1)), ytr)
Xd = np.zeros((len(yte), 1))
dp = dummy.predict_proba(Xd)
score_d = dp[:, list(dummy.classes_).index(1)] if 1 in dummy.classes_ else np.zeros(len(yte))
results.append(evaluate("majority-class", dummy.predict(Xd), score_d))


def length_feats(d):
    c = d["code"].astype(str)
    return np.column_stack([np.log1p(c.str.len()), np.log1p(c.str.count("\n") + 1)])


len_lr = LogisticRegression(class_weight="balanced", max_iter=1000).fit(length_feats(train), ytr)
Xl = length_feats(test)
results.append(evaluate("length-only LR", len_lr.predict(Xl), len_lr.predict_proba(Xl)[:, 1]))

vec = TfidfVectorizer(
    lowercase=False,
    token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]",
    ngram_range=(1, 2),
    max_features=20000,
    min_df=3,
    sublinear_tf=True,
)
Xtr = vec.fit_transform(train["code"])
Xte = vec.transform(test["code"])

lr = LogisticRegression(class_weight="balanced", max_iter=1000, solver="liblinear").fit(Xtr, ytr)
results.append(evaluate("TF-IDF + Logistic Regression", lr.predict(Xte), lr.predict_proba(Xte)[:, 1]))

print(f"Training Random Forest with {RF_TREES} trees (can take 5-20 min) ...")
rf = RandomForestClassifier(
    n_estimators=RF_TREES,
    min_samples_leaf=2,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=SEED,
).fit(Xtr, ytr)
results.append(evaluate("TF-IDF + Random Forest", rf.predict(Xte), rf.predict_proba(Xte)[:, 1]))

(RES / "phase1_results.json").write_text(json.dumps(results, indent=2))

lines = [
    "# Phase 1 baseline results (held-out repos)",
    "",
    f"Train {len(train)} / Test {len(test)} rows; split by repo_url, seed {SEED}. Positive class = vulnerable (1).",
    "",
    "| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |",
    "|---|---|---|---|---|---|",
]
for r in results:
    lines.append(
        f"| {r['model']} | {r['precision']} | {r['recall']} | {r['f1']} | {r['pr_auc']} | {r['roc_auc']} |"
    )
(RES / "phase1_results.md").write_text("\n".join(lines))

print("\n".join(lines))
print("\nPer-category recall (test set):")
for r in results[2:]:
    print(r["model"], json.dumps(r["per_category_recall"]))
print("\nSaved results/phase1_results.json and results/phase1_results.md")