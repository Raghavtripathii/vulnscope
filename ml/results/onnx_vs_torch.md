# Is the ONNX export faithful?

Same 200 random cleaned test functions as the benchmark, seed 45 model.

## Probability agreement

| Comparison | mean abs diff | max abs diff | same side of 0.5 |
|---|---|---|---|
| PyTorch fp32 CPU vs Kaggle | 0.02272 | 0.11970 | 0.8300 |
| ONNX fp32 vs PyTorch fp32 CPU | 0.00000 | 0.00000 | 1.0000 |
| ONNX int8 vs PyTorch fp32 CPU | 0.01174 | 0.04791 | 0.9250 |
| ONNX fp32 vs Kaggle | 0.02272 | 0.11970 | 0.8300 |

## Spread of the probabilities

| Source | min | max | std | share >= 0.5 |
|---|---|---|---|---|
| Kaggle GPU (half precision) | 0.206 | 0.541 | 0.071 | 0.225 |
| PyTorch fp32 on CPU | 0.189 | 0.547 | 0.065 | 0.385 |
| ONNX fp32 | 0.189 | 0.547 | 0.065 | 0.385 |
| ONNX int8 | 0.214 | 0.555 | 0.060 | 0.460 |

## ROC-AUC on these 200 functions (a rough check only, the sample is small)

| Source | ROC-AUC |
|---|---|
| Kaggle GPU (half precision) | 0.5062 |
| PyTorch fp32 on CPU | 0.5100 |
| ONNX fp32 | 0.5099 |
| ONNX int8 | 0.5009 |