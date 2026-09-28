# XSS-SLM v0.4

Three-way classifier for HTML/JavaScript snippets: `SAFE`, `POSSIBLE_XSS`, `XSS`.
v0.4 is the first version to clear the 0.90 promotion gate on the locked
Hard Test set.

## Contract

- Input: one HTML or JavaScript snippet.
- Output: `SAFE`, `POSSIBLE_XSS`, or `XSS`.
- `XSS` = recognizable untrusted-source-to-executable-sink flow.
- `POSSIBLE_XSS` = safety of a custom sanitizer / trust boundary cannot be
  decided from the snippet alone.
- This classifier is triage, not proof of browser execution.

## Pipeline

```
prepare_data.py   build_dataset(...)        # group-disjoint synthetic base
                  hard_test_cases(...)      # held-out template challenge (v1)
fetch_external_sources.py  curated samples   # OWASP / CWE / Semgrep-inspired
                  with provenance & license
adversarial_hard_test.py   adversarial.jsonl  # CVE-style patterns never trained on
build_v3_dataset.py       v4 train/val/test  # mixes everything; locks hard test
train.py          FP32 bert-tiny 5 epochs    # 40 min on CPU, 11M params
compare_rounds.py standard_test + hard_test  # reports promotion gate
```

## Round-4 dataset (v0.4)

| Split              | Count | SAFE | POSSIBLE_XSS | XSS |
| ------------------ | ----: | ---: | -----------: | --: |
| train              | 12046 | 4404 | 2360         | 5282 |
| validation         | 1023  | 408  | 205          | 410 |
| test (locked v0.1) | 1000  | 400  | 200          | 400 |
| **hard_test_v4**   | 465   | 155  | 80           | 230 |

Hard Test v4 provenance (never seen by training):

| Bucket                  | Count | Macro F1 |
| ----------------------- | ----: | -------: |
| external-shape (synthetic-but-real) | 250  | ~0.88 |
| external-curated (real-world refs)   | 63   | 0.92 |
| adversarial (CVE-style, never trained)| 152  | 0.75 |

## Round-4 results

| Set                        | Count | Macro F1 | SAFE F1 | POSSIBLE_XSS F1 | XSS F1 | XSS FPR | XSS FNR | Promotion gate (>=0.90) |
| -------------------------- | ----: | -------: | ------: | --------------: | -----: | ------: | ------: | :---------------------: |
| Standard test (locked v0.1) | 1000 | **1.000** | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | PASS |
| **Hard Test v4 (locked)**   | 465   | **0.909** | 0.930  | 0.876           | 0.922  | 0.081  | 0.074  | **PASS** |

Confusion matrix on Hard Test v4:

```
           SAFE  POSS  XSS
SAFE        139    3   13
POSSIBLE      0   74    6
XSS           5   12  213
```

The remaining 8.1 % XSS false-positive rate comes from the adversarial bucket
(Reflect.set, createContextualFragment, DOMParser, customElements, etc.).
The 7.4 % XSS false-negative rate is dominated by the same bucket — cases
where the sink is hidden behind two aliases the encoder has not been taught.

## Reproduce

```bash
uv sync --group slm

# 1. Curated external samples with license + provenance
uv run --group slm python security-models/xss/scripts/fetch_external_sources.py

# 2. Adversarial hard test
uv run --group slm python security-models/xss/scripts/adversarial_hard_test.py --copies 2

# 3. Build v0.4 train / val / test / hard_test splits
uv run --group slm python security-models/xss/scripts/build_v3_dataset.py \
  --shape-train 4000 --shape-hard 250

# 4. Train (≈40 min CPU, 5 epochs, bert-tiny)
uv run --group slm python security-models/xss/scripts/train.py \
  --epochs 5 --batch-size 32 --output-dir security-models/xss/model

# 5. Evaluate
uv run --group slm python security-models/xss/scripts/compare_rounds.py
uv run --group slm python security-models/xss/scripts/partition_eval.py
```

## Inference

```bash
uv run --group slm python security-models/xss/inference/predict.py \
  "element.innerHTML = userInput"
```

## What v0.4 still cannot do

The 152-case adversarial bucket is where most remaining errors live. The
model was not trained on Reflect / DOMParser / createContextualFragment /
Worker / TrustedTypes-bypass patterns, so it falls back to surface-token
heuristics for them. Future revisions need either (a) adversarial training
samples, or (b) a second-stage model that resolves data-flow through
helper functions.

The encoder remains the same 11 M parameter `google/bert_uncased_L-4_H-256_A-4`.
Quantization is intentionally not attempted until the FP32 report is frozen.
