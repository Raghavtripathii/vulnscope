from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

SEED = 42
RF_TREES = 100
PROC = Path("data/processed")
RES = Path("results")

train = pd.read_csv(PROC / "train_clean.csv")
test = pd.read_csv(PROC / "test_clean.csv")
assert set(train["repo_url"]).isdisjoint(set(test["repo_url"])), "repo leakage between train and test"
y_train = train["label"].values
y_test = test["label"].values
print(f"train {len(train)} rows, test {len(test)} rows, test vulnerable rate {y_test.mean():.4f}")


def length_features(frame):
    code = frame["code"].astype(str)
    return np.column_stack([np.log1p(code.str.len()), np.log1p(code.str.count("\n") + 1)])


def summarize(name, prob):
    pred = (prob >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="binary", pos_label=1, zero_division=0
    )
    return {
        "model": name,
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "pr_auc": round(float(average_precision_score(y_test, prob)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, prob)), 4),
    }


length_model = LogisticRegression(class_weight="balanced", max_iter=1000).fit(length_features(train), y_train)
length_prob = length_model.predict_proba(length_features(test))[:, 1]

vectorizer = TfidfVectorizer(
    lowercase=False,
    token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]",
    ngram_range=(1, 2),
    max_features=20000,
    min_df=3,
    sublinear_tf=True,
)
x_train = vectorizer.fit_transform(train["code"].astype(str))
x_test = vectorizer.transform(test["code"].astype(str))

logistic = LogisticRegression(class_weight="balanced", max_iter=1000, solver="liblinear").fit(x_train, y_train)
lr_prob = logistic.predict_proba(x_test)[:, 1]

print(f"Training the random forest with {RF_TREES} trees. Please wait and do not interrupt.")
forest = RandomForestClassifier(
    n_estimators=RF_TREES,
    min_samples_leaf=2,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=SEED,
).fit(x_train, y_train)
rf_prob = forest.predict_proba(x_test)[:, 1]

base_rate = float(y_test.mean())
reference = {
    "model": "always-predict-vulnerable (reference)",
    "precision": round(base_rate, 4),
    "recall": 1.0,
    "f1": round(2 * base_rate / (base_rate + 1), 4),
    "pr_auc": round(base_rate, 4),
    "roc_auc": 0.5,
}
results = [
    reference,
    summarize("length-only LR", length_prob),
    summarize("TF-IDF + Logistic Regression", lr_prob),
    summarize("TF-IDF + Random Forest", rf_prob),
]

predictions = test[["code_hash", "repo_url", "category", "label"]].copy()
predictions["length_prob"] = length_prob
predictions["lr_prob"] = lr_prob
predictions["rf_prob"] = rf_prob
predictions.to_csv(RES / "clean_baseline_predictions.csv", index=False)

lines = [
    "# Classical baselines on the cleaned dataset (held-out repos)",
    "",
    f"Train {len(train)} / Test {len(test)} rows, same repo split as before, seed {SEED}. Threshold 0.5 for precision, recall and F1.",
    "",
    "| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |",
    "|---|---|---|---|---|---|",
]
for r in results:
    lines.append(f"| {r['model']} | {r['precision']} | {r['recall']} | {r['f1']} | {r['pr_auc']} | {r['roc_auc']} |")
text = "\n".join(lines)
(RES / "clean_baseline_results.md").write_text(text, encoding="utf-8")
print(text)