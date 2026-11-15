import csv
import json
import os
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
import transformers
from onnxruntime.quantization import QuantType, quantize_dynamic
from transformers import AutoModelForSequenceClassification, AutoTokenizer

csv.field_size_limit(2**31 - 1)

TOKENIZER_NAME = "microsoft/codebert-base"
MAX_LEN = 256
SAMPLE = 200
BATCH = 8
SINGLE_RUNS = 100
WARMUP = 5
SEED = 42
TEST_PATH = Path("data/processed/test_clean.csv")
PRED_PATH = Path("results/test_predictions_codebert_clean_seeds.csv")
META_PATH = Path("results/codebert_multiseed_results.json")
REPORT_PATH = Path("results/onnx_cpu_benchmark.md")


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def positive_prob(logits):
    shifted = logits - logits.max(axis=1, keepdims=True)
    weights = np.exp(shifted)
    return (weights / weights.sum(axis=1, keepdims=True))[:, 1]


def export_fp32(model_dir, onnx_path):
    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, attn_implementation="eager")
    model.eval()
    model.config.return_dict = False
    sample = tokenizer(
        "def example(value):\n    return value",
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=MAX_LEN,
    )
    with torch.no_grad():
        torch.onnx.export(
            model,
            (sample["input_ids"], sample["attention_mask"]),
            str(onnx_path),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "sequence"},
                "attention_mask": {0: "batch", 1: "sequence"},
                "logits": {0: "batch"},
            },
            opset_version=14,
            do_constant_folding=True,
            dynamo=False,
        )
    return tokenizer


def make_session(path):
    return ort.InferenceSession(str(path), ort.SessionOptions(), providers=["CPUExecutionProvider"])


def encode(tokenizer, texts):
    encoded = tokenizer(texts, truncation=True, max_length=MAX_LEN, padding=True, return_tensors="np")
    return {
        "input_ids": encoded["input_ids"].astype(np.int64),
        "attention_mask": encoded["attention_mask"].astype(np.int64),
    }


def run_batches(session, tokenizer, texts):
    probs = []
    for start in range(0, len(texts), BATCH):
        feeds = encode(tokenizer, texts[start:start + BATCH])
        probs.append(positive_prob(session.run(["logits"], feeds)[0]))
    return np.concatenate(probs)


def single_latency(session, tokenizer, texts):
    for text in texts[:WARMUP]:
        session.run(["logits"], encode(tokenizer, [text]))
    token_times, model_times = [], []
    for text in texts[:SINGLE_RUNS]:
        started = time.perf_counter()
        feeds = encode(tokenizer, [text])
        token_times.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        session.run(["logits"], feeds)
        model_times.append((time.perf_counter() - started) * 1000)
    ordered = sorted(model_times)
    return {
        "tokenize_median_ms": statistics.median(token_times),
        "model_median_ms": statistics.median(model_times),
        "model_p95_ms": ordered[int(0.95 * (len(ordered) - 1))],
    }


def batch_throughput(session, tokenizer, texts):
    run_batches(session, tokenizer, texts[:BATCH * 2])
    started = time.perf_counter()
    run_batches(session, tokenizer, texts)
    return len(texts) / (time.perf_counter() - started)


def compare(name, probs, reference):
    diff = np.abs(probs - reference)
    same_side = float(np.mean((probs >= 0.5) == (reference >= 0.5)))
    return f"| {name} | {diff.mean():.5f} | {diff.max():.5f} | {same_side:.4f} |"


def main(model_dir, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fp32_path = out_dir / "codebert_fp32.onnx"
    int8_path = out_dir / "codebert_int8.onnx"

    rows = read_rows(TEST_PATH)
    preds = read_rows(PRED_PATH)
    assert len(rows) == len(preds), "test and prediction rows differ"
    assert all(a["code_hash"] == b["code_hash"] for a, b in zip(rows, preds)), "row order differs"
    best_seed = json.loads(META_PATH.read_text(encoding="utf-8"))["meta"]["best_seed_by_validation"]
    column = f"codebert_prob_seed{best_seed}"

    indices = sorted(random.Random(SEED).sample(range(len(rows)), min(SAMPLE, len(rows))))
    texts = [rows[i]["code"] for i in indices]
    reference = np.array([float(preds[i][column]) for i in indices])

    print("exporting fp32 model ...")
    tokenizer = export_fp32(model_dir, fp32_path)
    print("quantizing to int8 ...")
    quantize_dynamic(str(fp32_path), str(int8_path), weight_type=QuantType.QInt8)

    sessions = {"fp32": make_session(fp32_path), "int8": make_session(int8_path)}
    probs = {name: run_batches(session, tokenizer, texts) for name, session in sessions.items()}
    latency = {name: single_latency(session, tokenizer, texts) for name, session in sessions.items()}
    throughput = {name: batch_throughput(session, tokenizer, texts) for name, session in sessions.items()}

    lines = ["# ONNX export and CPU inference check", ""]
    lines.append(f"Model: seed {best_seed} (best validation score), max length {MAX_LEN}. {len(texts)} random cleaned test functions.")
    lines.append(f"Machine: {platform.processor() or platform.machine()}, {os.cpu_count()} logical cores, onnxruntime {ort.__version__}, torch {torch.__version__}, transformers {transformers.__version__}. Default thread settings.")
    lines.append("")
    lines.append("## Probability agreement")
    lines.append("")
    lines.append("The Kaggle probabilities were computed on a GPU with half-precision autocast, so small differences are expected.")
    lines.append("")
    lines.append("| Comparison | mean abs diff | max abs diff | same side of 0.5 |")
    lines.append("|---|---|---|---|")
    lines.append(compare("fp32 ONNX vs Kaggle probabilities", probs["fp32"], reference))
    lines.append(compare("int8 ONNX vs Kaggle probabilities", probs["int8"], reference))
    lines.append(compare("int8 ONNX vs fp32 ONNX", probs["int8"], probs["fp32"]))
    lines.append("")
    lines.append("## Speed on this CPU")
    lines.append("")
    lines.append(f"Single function = batch of 1 over {SINGLE_RUNS} functions. Throughput = batches of {BATCH}.")
    lines.append("")
    lines.append("| Model | file size MB | tokenize median ms | model median ms | model p95 ms | functions per second (batches) |")
    lines.append("|---|---|---|---|---|---|")
    for name, path in [("fp32", fp32_path), ("int8", int8_path)]:
        info = latency[name]
        lines.append(
            f"| {name} | {path.stat().st_size / 1e6:.0f} | {info['tokenize_median_ms']:.1f} | "
            f"{info['model_median_ms']:.1f} | {info['model_p95_ms']:.1f} | {throughput[name]:.1f} |"
        )
    text = "\n".join(lines)
    REPORT_PATH.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])