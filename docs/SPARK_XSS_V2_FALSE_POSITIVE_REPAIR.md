# Spark XSS v2: false-positive repair and reproducible evaluation

The 2026-10-12 independent Kaggle baseline-vs-LoRA v1 comparison found:

| Metric (48 static synthetic challenges) | Spark base | LoRA v1 |
|---|---:|---:|
| Accuracy | 79.17% | 64.58% |
| False-positive rate | 29.17% (7/24 safe) | 70.83% (17/24 safe) |
| Recall | 87.5% | 100% |
| Free-generation FPR (16 challenges) | 37.5% | 87.5% |

**V1 stays rejected and saved unchanged.** Better recall alone does not
justify promoting an alarm-heavy XSS detector. Synthetic code classification
cannot establish a real-world browser-confirmed vulnerability.

## Root cause addressed

The first SFT source had 359 examples (210 positives, 149 safe). Its
speculative unknown-sanitizer/near-miss examples included 85 positives and
16 safe examples. Unknown or typo function names are not automatically
exploit paths: they may throw before unsafe HTML or JS executes.

New source: training/spark_xss_v2_data.py:
- exclude 101 speculative examples;
- deduplicate 50 identical old prompts; uniquely identify surviving legacy
  rows sharing a case ID;
- retain 208 distinct original training prompts;
- generate 144 matched source-to-safe/unsafe-sink pairs (288 records)
  covering 18 code-path families, unrelated to the evaluation labels;
- total **496 records: 237 vulnerable / 259 safe**;
- keep the same full reporting format, with explicit NOT_ESTABLISHED
  runtime execution;
- fail on duplicated new training prompts, class imbalance, wrong source
  version, or mismatched data generation.

Training uses separate Kaggle notebook:
https://www.kaggle.com/code/dody2004/spark-xss-balanced-v2-candidate

The source and new checkpoint are isolated from previous successful adapter:
https://www.kaggle.com/code/dody2004/spark-xss-qlora-kaggle

V2 uses Spark-X2.5-4B, 4-bit QLoRA FP16 computation, LoRA rank 8,
one epoch and a reduced LR of 2e-5 (vs 5e-5 in v1).

## Current and next steps

GitHub workflow Train Spark XSS Balanced V2 on Kaggle performs CPU
preflight checks and submits the dedicated private Kaggle notebook, but
successful GitHub submission does **not** prove GPU training actually ran.

Read-only status workflow Monitor Spark XSS Balanced V2 Kaggle queries
Kaggle's **actual kernel slug** dody2004/spark-xss-balanced-v2-candidate
without launching a second GPU run. It verifies the saved candidate's
run_status.json and archives relevant logs.

After the candidate completes, compare **base vs v1 vs v2** on new
independently curated safe/unsafe examples and browser-confirmed fixtures
in a controlled authorized environment. The prior exposed 48-case benchmark
can serve as regression evidence but NOT a new untouched acceptance test.
Measure FPR, recall, F1, paired safe/vulnerable contrasts, unsupported
execution claims, and rationale correctness. Do not choose thresholds using
the final held-out evaluation cases.

**Never auto-promote** any version to MyHunt/PentesterFlow.
