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
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    precision_recall_fscore_support,
    average_precision_score,
    roc_auc_score,
    confusion_matrix,
)

os.environ["TOKENIZERS_PARALLELISM"] = "false"

SEED = 42
MODEL_NAME = "microsoft/codebert-base"
MAX_LEN = 256
BATCH_SIZE = 16
EPOCHS = 3
LEARNING_RATE = 2e-5
WARMUP_RATIO = 0.1
EXPECTED_TRAIN_ROWS = 42056
EXPECTED_TEST_ROWS = 3636
OUT_DIR = Path("/kaggle/working")
CATEGORIES = ["sql_injection", "xss", "secrets", "auth"]


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


def evaluate(name, y_true, probs, frame, threshold=0.5):
    pred = (probs >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", pos_label=1, zero_division=0
    )
    result = {
        "model": name,
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "pr_auc": round(float(average_precision_score(y_true, probs)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probs)), 4),
        "confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(y_true, pred, labels=[0, 1]).tolist(),
    }
    per_category = {}
    for category in CATEGORIES:
        mask = (y_true == 1) & (frame["category"].values == category)
        count = int(mask.sum())
        per_category[category] = {
            "n_vulnerable_in_test": count,
            "recall": round(float((pred[mask] == 1).mean()), 4) if count else None,
        }
    result["per_category_recall"] = per_category
    return result


def main():
    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type != "cuda":
        raise SystemExit("No GPU found. Turn on a GPU accelerator in the notebook settings.")
    print("GPU:", torch.cuda.get_device_name(0))

    train_df = pd.read_csv(find_file("train.csv"))
    test_df = pd.read_csv(find_file("test.csv"))
    train_df["category"] = train_df["category"].fillna("other")
    test_df["category"] = test_df["category"].fillna("other")

    assert len(train_df) == EXPECTED_TRAIN_ROWS, f"train rows {len(train_df)} != {EXPECTED_TRAIN_ROWS}"
    assert len(test_df) == EXPECTED_TEST_ROWS, f"test rows {len(test_df)} != {EXPECTED_TEST_ROWS}"
    assert set(train_df["repo_url"]).isdisjoint(set(test_df["repo_url"])), "repo leakage between train and test"

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.1, random_state=SEED)
    fit_idx, val_idx = next(splitter.split(train_df, train_df["label"], groups=train_df["repo_url"]))
    fit_df = train_df.iloc[fit_idx].reset_index(drop=True)
    val_df = train_df.iloc[val_idx].reset_index(drop=True)
    assert set(fit_df["repo_url"]).isdisjoint(set(val_df["repo_url"]))
    print(f"fit {len(fit_df)} rows | val {len(val_df)} rows | test {len(test_df)} rows")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    collate = make_collate(tokenizer)
    generator = torch.Generator()
    generator.manual_seed(SEED)
    fit_loader = DataLoader(CodeDataset(fit_df), batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate, generator=generator)
    val_loader = DataLoader(CodeDataset(val_df), batch_size=BATCH_SIZE * 2, shuffle=False, collate_fn=collate)
    test_loader = DataLoader(CodeDataset(test_df), batch_size=BATCH_SIZE * 2, shuffle=False, collate_fn=collate)

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    total_steps = len(fit_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(optimizer, int(WARMUP_RATIO * total_steps), total_steps)
    scaler = torch.cuda.amp.GradScaler()

    y_val = val_df["label"].values
    best_pr_auc = -1.0
    best_state = None
    best_epoch = 0
    history = []
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
                print(f"epoch {epoch} step {step}/{len(fit_loader)} loss(last200) {np.mean(losses[-200:]):.4f}")

        val_probs = predict_proba(model, val_loader, device)
        val_pr_auc = float(average_precision_score(y_val, val_probs))
        val_roc_auc = float(roc_auc_score(y_val, val_probs))
        history.append({
            "epoch": epoch,
            "train_loss": round(float(np.mean(losses)), 4),
            "val_pr_auc": round(val_pr_auc, 4),
            "val_roc_auc": round(val_roc_auc, 4),
        })
        print(f"=== epoch {epoch} done | train loss {np.mean(losses):.4f} | val PR-AUC {val_pr_auc:.4f} | val ROC-AUC {val_roc_auc:.4f}")
        if val_pr_auc > best_pr_auc:
            best_pr_auc = val_pr_auc
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    train_seconds = round(time.time() - started, 1)
    model.load_state_dict(best_state)
    print(f"best epoch by validation PR-AUC: {best_epoch}")

    test_probs = predict_proba(model, test_loader, device)
    y_test = test_df["label"].values
    base_rate = float(y_test.mean())

    results = [
        evaluate("CodeBERT (fine-tuned)", y_test, test_probs, test_df),
        {
            "model": "always-predict-vulnerable (reference)",
            "precision": round(base_rate, 4),
            "recall": 1.0,
            "f1": round(2 * base_rate / (1 + base_rate), 4),
            "pr_auc": round(base_rate, 4),
            "roc_auc": 0.5,
        },
    ]
    meta = {
        "model_name": MODEL_NAME,
        "max_len": MAX_LEN,
        "batch_size": BATCH_SIZE,
        "epochs": EPOCHS,
        "learning_rate": LEARNING_RATE,
        "seed": SEED,
        "best_epoch": best_epoch,
        "train_seconds": train_seconds,
        "n_fit": len(fit_df),
        "n_val": len(val_df),
        "n_test": len(test_df),
        "test_base_rate": round(base_rate, 4),
        "gpu": torch.cuda.get_device_name(0),
        "history": history,
    }
    (OUT_DIR / "codebert_results.json").write_text(json.dumps({"meta": meta, "results": results}, indent=2))

    predictions = test_df[["code_hash", "repo_url", "category", "label"]].copy()
    predictions["codebert_prob"] = test_probs
    predictions.to_csv(OUT_DIR / "test_predictions_codebert.csv", index=False)

    model.save_pretrained(OUT_DIR / "codebert_vulnscope")
    tokenizer.save_pretrained(OUT_DIR / "codebert_vulnscope")

    lines = [
        "# Phase 2 CodeBERT results (held-out repos)",
        "",
        f"Fit {len(fit_df)} / Val {len(val_df)} / Test {len(test_df)} rows; split by repo_url, seed {SEED}; best epoch {best_epoch} by validation PR-AUC. Positive class = vulnerable (1). Threshold 0.5.",
        "",
        "| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r['model']} | {r['precision']} | {r['recall']} | {r['f1']} | {r['pr_auc']} | {r['roc_auc']} |")
    (OUT_DIR / "codebert_results.md").write_text("\n".join(lines))

    print("\n".join(lines))
    print("\nConfusion matrix [[TN,FP],[FN,TP]]:", results[0]["confusion_matrix [[TN,FP],[FN,TP]]"])
    print("Per-category recall:")
    for category, info in results[0]["per_category_recall"].items():
        print(f"  {category}: {info}")
    print(f"\nTraining took {train_seconds} seconds.")


if __name__ == "__main__":
    main()