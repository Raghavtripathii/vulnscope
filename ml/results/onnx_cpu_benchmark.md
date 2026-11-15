# ONNX export and CPU inference check

Model: seed 45 (best validation score), max length 256. 200 random cleaned test functions.
Machine: Intel64 Family 6 Model 154 Stepping 3, GenuineIntel, 12 logical cores, onnxruntime 1.20.1, torch 2.5.1+cpu, transformers 4.46.3. Default thread settings.

## Probability agreement

The Kaggle probabilities were computed on a GPU with half-precision autocast, so small differences are expected.

| Comparison | mean abs diff | max abs diff | same side of 0.5 |
|---|---|---|---|
| fp32 ONNX vs Kaggle probabilities | 0.02272 | 0.11970 | 0.8300 |
| int8 ONNX vs Kaggle probabilities | 0.03292 | 0.14831 | 0.7650 |
| int8 ONNX vs fp32 ONNX | 0.01174 | 0.04791 | 0.9250 |

## Speed on this CPU

Single function = batch of 1 over 100 functions. Throughput = batches of 8.

| Model | file size MB | tokenize median ms | model median ms | model p95 ms | functions per second (batches) |
|---|---|---|---|---|---|
| fp32 | 499 | 1.4 | 246.9 | 348.3 | 3.7 |
| int8 | 126 | 1.2 | 98.6 | 130.2 | 9.2 |