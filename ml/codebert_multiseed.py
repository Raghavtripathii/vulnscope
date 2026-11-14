import os
import json
import time
import random
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from sklearn.model_selection import GroupKFold
from sklearn.metrics import precision_recall_fscore_support, average_precision_score, roc_auc_score

os.environ["TOKENIZERS_PARALLELISM"] = "false"

SEEDS = [42, 43, 44, 45, 46]
MODEL_NAME = "microsoft/codebert-base"
MAX_LEN = 256
BATCH_SIZE = 16
EPOCHS = 3
LEARNING_RATE = 2e-5
WARMUP_RATIO = 0.1
VAL_FOLDS = 5
EXPECTED_TRAIN_ROWS = 12549
EXPECTED_TEST_ROWS = 3114
OUT_DIR = Path("/kaggle/working")


def set_seed(value):
    random.seed(value)
    np.random.seed(value)
    torch.manual_seed(value)
    torch.cuda.manual_seed_all(value)


def find_file(name):
    for root, _, files in os.walk("/kaggle/input"):
        if name in files:
            return Path(root) / name
    raise FileNotFoundError(f"{name} not found under /kaggle/input")


class CodeDataset(Dataset):
    def __init__(self, frame):
        self.codes = frame["code"].astype(str).tolist()
        self.labels = frame["label"].astype(int).tolist()

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, index):
        return self.codes[index], self.labels[index]


def make_collate(tokenizer):
    def collate(batch):
        texts, labels = zip(*batch)
        encoded = tokenizer(
            list(texts),
            truncation=True,
            max_length=MAX_LEN,
            padding=True,
            return_tensors="pt",
        )
        out = dict(encoded)
        out["labels"] = torch.tensor(labels, dtype=torch.long)
        return out

    return collate


@torch.no_grad()
def predict_proba(model, loader, device):
    model.eval()
    chunks = []
    for batch in loader:
        inputs = {k: v.to(device) for k, v in batch.items() if k != "labels"}
        with torch.cuda.amp.autocast():
            logits = model(**inputs).logits
        chunks.append(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(chunks)


def score(y_true, probs):
    pred = (probs >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", pos_label=1, zero_division=0
    )
    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "pr_auc": round(float(average_precision_score(y_true, probs)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probs)), 4),
    }


def run_seed(seed, fit_df, val_df, test_df, tokenizer, collate, device):
    set_seed(seed)
    generator = torch.Generator()
    generator.manual_seed(seed)
    fit_loader = DataLoader(CodeDataset(fit_df), batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate, generator=generator)
    val_loader = DataLoader(CodeDataset(val_df), batch_size=BATCH_SIZE * 2, shuffle=False, collate_fn=collate)
    test_loader = DataLoader(CodeDataset(test_df), batch_size=BATCH_SIZE * 2, shuffle=False, collate_fn=collate)

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    total_steps = len(fit_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(optimizer, int(WARMUP_RATIO * total_steps), total_steps)
    scaler = torch.cuda.amp.GradScaler()

    y_val = val_df["label"].values
    best_val_pr_auc = -1.0
    best_epoch = 0
    best_state = None
    started = time.time()

    for epoch in range(1, EPOCHS + 1):
        model.train()
        losses = []
        for step, batch in enumerate(fit_loader, 1):
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad(set_to_none=True)
            with torch.cuda.amp.autocast():
                loss = model(**batch).loss
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            losses.append(loss.item())
            if step % 200 == 0:
                print(f"seed {seed} epoch {epoch} step {step}/{len(fit_loader)} loss(last200) {np.mean(losses[-200:]):.4f}")

        val_probs = predict_proba(model, val_loader, device)
        val_pr_auc = float(average_precision_score(y_val, val_probs))
        val_roc_auc = float(roc_auc_score(y_val, val_probs))
        print(f"=== seed {seed} epoch {epoch} | train loss {np.mean(losses):.4f} | val PR-AUC {val_pr_auc:.4f} | val ROC-AUC {val_roc_auc:.4f}")
        if val_pr_auc > best_val_pr_auc:
            best_val_pr_auc = val_pr_auc
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    train_seconds = round(time.time() - started, 1)
    model.load_state_dict(best_state)
    test_probs = predict_proba(model, test_loader, device)
    summary = {
        "seed": seed,
        "best_epoch": best_epoch,
        "val_pr_auc": round(best_val_pr_auc, 4),
        "train_seconds": train_seconds,
    }
    summary.update(score(test_df["label"].values, test_probs))
    return summary, test_probs, model


def write_outputs(summaries, prob_columns, test_df, meta):
    y_test = test_df["label"].values
    base_rate = float(y_test.mean())
    metrics = ["roc_auc", "pr_auc", "precision", "recall", "f1"]

    aggregate = {}
    for metric in metrics:
        values = [s[metric] for s in summaries]
        aggregate[metric] = {
            "mean": round(float(np.mean(values)), 4),
            "min": round(float(np.min(values)), 4),
            "max": round(float(np.max(values)), 4),
        }

    ensemble = None
    if len(prob_columns) >= 2:
        ensemble = score(y_test, np.mean(list(prob_columns.values()), axis=0))

    payload = {"meta": meta, "per_seed": summaries, "aggregate": aggregate, "seed_ensemble": ensemble, "test_base_rate": round(base_rate, 4)}
    (OUT_DIR / "codebert_multiseed_results.json").write_text(json.dumps(payload, indent=2))

    predictions = test_df[["code_hash", "repo_url", "category", "label"]].copy()
    for seed, probs in prob_columns.items():
        predictions[f"codebert_prob_seed{seed}"] = probs
    predictions.to_csv(OUT_DIR / "test_predictions_codebert_clean_seeds.csv", index=False)

    lines = [
        "# CodeBERT on the cleaned dataset, multiple seeds (held-out repos)",
        "",
        f"Fit {meta['n_fit']} / Val {meta['n_val']} / Test {meta['n_test']} rows. Validation is GroupKFold fold 0 of {VAL_FOLDS} by repo. Test base rate {base_rate:.4f}. Threshold 0.5.",
        "",
        "| Seed | Best epoch | Val PR-AUC | ROC-AUC | PR-AUC | Precision | Recall | F1 | Train seconds |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        lines.append(
            f"| {s['seed']} | {s['best_epoch']} | {s['val_pr_auc']} | {s['roc_auc']} | {s['pr_auc']} | "
            f"{s['precision']} | {s['recall']} | {s['f1']} | {s['train_seconds']} |"
        )
    lines += ["", "| Metric | Mean | Min | Max |", "|---|---|---|---|"]
    for metric in metrics:
        a = aggregate[metric]
        lines.append(f"| {metric} | {a['mean']} | {a['min']} | {a['max']} |")
    if ensemble is not None:
        lines += [
            "",
            f"Average of the {len(prob_columns)} seeds' probabilities (an ensemble, not a single model): "
            f"ROC-AUC {ensemble['roc_auc']}, PR-AUC {ensemble['pr_auc']}.",
        ]
    text = "\n".join(lines)
    (OUT_DIR / "codebert_multiseed_results.md").write_text(text)
    return text


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type != "cuda":
        raise SystemExit("No GPU found. Turn on a GPU accelerator in the notebook settings.")
    print("GPU:", torch.cuda.get_device_name(0))

    train_df = pd.read_csv(find_file("train_clean.csv"))
    test_df = pd.read_csv(find_file("test_clean.csv"))
    train_df["category"] = train_df["category"].fillna("other")
    test_df["category"] = test_df["category"].fillna("other")

    assert len(train_df) == EXPECTED_TRAIN_ROWS, f"train rows {len(train_df)} != {EXPECTED_TRAIN_ROWS}"
    assert len(test_df) == EXPECTED_TEST_ROWS, f"test rows {len(test_df)} != {EXPECTED_TEST_ROWS}"
    assert set(train_df["repo_url"]).isdisjoint(set(test_df["repo_url"])), "repo leakage between train and test"

    folds = GroupKFold(n_splits=VAL_FOLDS)
    fit_idx, val_idx = next(folds.split(train_df, train_df["label"], groups=train_df["repo_url"]))
    fit_df = train_df.iloc[fit_idx].reset_index(drop=True)
    val_df = train_df.iloc[val_idx].reset_index(drop=True)
    assert set(fit_df["repo_url"]).isdisjoint(set(val_df["repo_url"]))
    print(f"fit {len(fit_df)} rows | val {len(val_df)} rows | test {len(test_df)} rows")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    collate = make_collate(tokenizer)

    meta = {
        "model_name": MODEL_NAME,
        "max_len": MAX_LEN,
        "batch_size": BATCH_SIZE,
        "epochs": EPOCHS,
        "learning_rate": LEARNING_RATE,
        "seeds": SEEDS,
        "val_folds": VAL_FOLDS,
        "n_fit": len(fit_df),
        "n_val": len(val_df),
        "n_test": len(test_df),
        "gpu": torch.cuda.get_device_name(0),
    }

    summaries = []
    prob_columns = {}
    best_val_overall = -1.0

    for seed in SEEDS:
        summary, test_probs, model = run_seed(seed, fit_df, val_df, test_df, tokenizer, collate, device)
        summaries.append(summary)
        prob_columns[seed] = test_probs
        print(f"seed {seed} test: {summary}")

        if summary["val_pr_auc"] > best_val_overall:
            best_val_overall = summary["val_pr_auc"]
            meta["best_seed_by_validation"] = seed
            model.save_pretrained(OUT_DIR / "codebert_vulnscope_best_val")
            tokenizer.save_pretrained(OUT_DIR / "codebert_vulnscope_best_val")

        del model
        torch.cuda.empty_cache()
        text = write_outputs(summaries, prob_columns, test_df, meta)

    print(text)


if __name__ == "__main__":
    main()