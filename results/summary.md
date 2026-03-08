# Evaluation Results Summary

**Date:** 2026-03-08 16:38:00
**Test data:** /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/dataset/TEST_Traffic.csv (50000 rows)

## Per-Model Results

| Model | Accuracy | Precision | Recall | F1 | FPR | Time/flow |
|-------|----------|-----------|--------|-----|-----|-----------|
| BCC v2 | 0.8324 | 0.8750 | 0.2125 | 0.3419 | 0.0078 | 0.05 us |
| DDL-40 | 0.8481 | 0.6994 | 0.4537 | 0.5504 | 0.0503 | 133.35 us |
| IF | 0.8206 | 0.6259 | 0.3100 | 0.4146 | 0.0477 | 2.83 us |
| Full Pipeline | 0.8219 | 0.9363 | 0.1405 | 0.2444 | 0.0025 | N/A us |
| BCC v2 (Sandaru data) | 0.9865 | 0.9631 | 0.9989 | 0.9807 | 0.0200 | N/A |

## Confusion Matrices

### BCC v2

```
               Predicted
            FORWARD    DROP
Normal       39,443     311
Attack        8,069   2,177
```

### DDL-40

```
               Predicted
            FORWARD    DROP
Normal       37,756   1,998
Attack        5,597   4,649
```

### IF

```
               Predicted
            FORWARD    DROP
Normal       37,856   1,898
Attack        7,070   3,176
```

### Full Pipeline

```
               Predicted
            FORWARD    DROP
Normal       39,656      98
Attack        8,806   1,440
```

## Pipeline Flow Routing

- BCC passed as BENIGN: 47,512
- BCC flagged to DDL+IF: 2,488
- DDL+IF → FORWARD: 950
- DDL+IF → DROP: 1,538

## Timing Summary

| Stage | Total Time | Per Flow |
|-------|-----------|----------|
| BCC v2 | 0.0027s | 0.05 us |
| DDL-40 | 6.6675s | 133.35 us |
| IF | 0.1414s | 2.83 us |
| Full Pipeline | 0.3942s | N/A us |