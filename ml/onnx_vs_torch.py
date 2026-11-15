import json
import random
import sys
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from export_onnx import (
    BATCH,
    MAX_LEN,
    META_PATH,
    PRED_PATH,
    SAMPLE,
    SEED,
    TEST_PATH,
    TOKENIZER_NAME,
    compare,
    make_session,
    positive_prob,
    read_rows,
    run_batches,
)

REPORT_PATH = Path("results/onnx_vs_torch.md")


def torch_probs(model, tokenizer, texts):
    chunks = []
    with torch.no_grad():
        for start in range(0, len(texts), BATCH):
            encoded = tokenizer(
                texts[start:start + BATCH],
                truncation=True,
                max_length=MAX_LEN,
                padding=True,
                return_tensors="pt",
            )
            logits = model(input_ids=encoded["input_ids"], attention_mask=encoded["attention_mask"]).logits
            chunks.append(positive_prob(logits.numpy()))
    return np.concatenate(chunks)


def roc_auc(y, scores):
    order = np.argsort(scores)
    sorted_scores = scores[order]
    ranks = np.empty(len(scores))
    i = 0
    while i < len(scores):
        j = i
        while j + 1 < len(scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    positives = y == 1
    n_pos = int(positives.sum())
    n_neg = int((~positives).sum())
    return float((ranks[positives].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def main(model_dir, onnx_dir, tokenizer_name):
    onnx_dir = Path(onnx_dir)
    rows = read_rows(TEST_PATH)
    preds = read_rows(PRED_PATH)
    best_seed = json.loads(META_PATH.read_text(encoding="utf-8"))["meta"]["best_seed_by_validation"]
    column = f"codebert_prob_seed{best_seed}"

    indices = sorted(random.Random(SEED).sample(range(len(rows)), min(SAMPLE, len(rows))))
    texts = [rows[i]["code"] for i in indices]
    labels = np.array([int(rows[i]["label"]) for i in indices])
    kaggle = np.array([float(preds[i][column]) for i in indices])

    tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, attn_implementation="eager")
    model.eval()

    results = {
        "Kaggle GPU (half precision)": kaggle,
        "PyTorch fp32 on CPU": torch_probs(model, tokenizer, texts),
        "ONNX fp32": run_batches(make_session(onnx_dir / "codebert_fp32.onnx"), tokenizer, texts),
        "ONNX int8": run_batches(make_session(onnx_dir / "codebert_int8.onnx"), tokenizer, texts),
    }

    lines = ["# Is the ONNX export faithful?", ""]
    lines.append(f"Same {len(texts)} random cleaned test functions as the benchmark, seed {best_seed} model.")
    lines.append("")
    lines.append("## Probability agreement")
    lines.append("")
    lines.append("| Comparison | mean abs diff | max abs diff | same side of 0.5 |")
    lines.append("|---|---|---|---|")
    torch_p = results["PyTorch fp32 on CPU"]
    lines.append(compare("PyTorch fp32 CPU vs Kaggle", torch_p, kaggle))
    lines.append(compare("ONNX fp32 vs PyTorch fp32 CPU", results["ONNX fp32"], torch_p))
    lines.append(compare("ONNX int8 vs PyTorch fp32 CPU", results["ONNX int8"], torch_p))
    lines.append(compare("ONNX fp32 vs Kaggle", results["ONNX fp32"], kaggle))
    lines.append("")
    lines.append("## Spread of the probabilities")
    lines.append("")
    lines.append("| Source | min | max | std | share >= 0.5 |")
    lines.append("|---|---|---|---|---|")
    for name, p in results.items():
        lines.append(f"| {name} | {p.min():.3f} | {p.max():.3f} | {p.std():.3f} | {np.mean(p >= 0.5):.3f} |")
    lines.append("")
    lines.append(f"## ROC-AUC on these {len(texts)} functions (a rough check only, the sample is small)")
    lines.append("")
    lines.append("| Source | ROC-AUC |")
    lines.append("|---|---|")
    for name, p in results.items():
        lines.append(f"| {name} | {roc_auc(labels, p):.4f} |")
    text = "\n".join(lines)
    REPORT_PATH.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else TOKENIZER_NAME)