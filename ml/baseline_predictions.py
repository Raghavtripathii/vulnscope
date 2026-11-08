from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

SEED = 42
RF_TREES = 100
EXPECTED_TRAIN_ROWS = 42056
EXPECTED_TEST_ROWS = 3636
TRAIN_PATH = Path("data/processed/train.csv")
TEST_PATH = Path("data/processed/test.csv")
OUT_PATH = Path("results/test_predictions_baseline.csv")
EARLIER_RUN = {
    "lr": {"pr_auc": 0.4556, "roc_auc": 0.5279},
    "rf": {"pr_auc": 0.4544, "roc_auc": 0.5304},
}


def main():
    train = pd.read_csv(TRAIN_PATH)
    test = pd.read_csv(TEST_PATH)
    assert len(train) == EXPECTED_TRAIN_ROWS, f"train rows {len(train)} != {EXPECTED_TRAIN_ROWS}"
    assert len(test) == EXPECTED_TEST_ROWS, f"test rows {len(test)} != {EXPECTED_TEST_ROWS}"
    assert set(train["repo_url"]).isdisjoint(set(test["repo_url"])), "repo leakage between train and test"

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
    y_train = train["label"].values
    y_test = test["label"].values

    logistic = LogisticRegression(class_weight="balanced", max_iter=1000, solver="liblinear")
    logistic.fit(x_train, y_train)
    lr_prob = logistic.predict_proba(x_test)[:, 1]

    print(f"Training the random forest with {RF_TREES} trees. This can take 5 to 20 minutes...")
    forest = RandomForestClassifier(
        n_estimators=RF_TREES,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=SEED,
    )
    forest.fit(x_train, y_train)
    rf_prob = forest.predict_proba(x_test)[:, 1]

    for name, prob in (("lr", lr_prob), ("rf", rf_prob)):
        pr_auc = round(float(average_precision_score(y_test, prob)), 4)
        roc_auc = round(float(roc_auc_score(y_test, prob)), 4)
        earlier = EARLIER_RUN[name]
        close = abs(pr_auc - earlier["pr_auc"]) < 0.005 and abs(roc_auc - earlier["roc_auc"]) < 0.005
        verdict = "close to" if close else "DIFFERENT from"
        print(
            f"{name}: PR-AUC {pr_auc}, ROC-AUC {roc_auc} | {verdict} the earlier run "
            f"({earlier['pr_auc']} / {earlier['roc_auc']})"
        )

    predictions = test[["code_hash", "repo_url", "category", "label"]].copy()
    predictions["lr_prob"] = lr_prob
    predictions["rf_prob"] = rf_prob
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(OUT_PATH, index=False)
    print(f"Saved {len(predictions)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()