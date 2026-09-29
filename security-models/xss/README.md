# XSS-SLM v0.4

Three-way classifier for HTML/JavaScript snippets: `SAFE`, `POSSIBLE_XSS`, `XSS`.
v0.4 is the first version to clear the 0.90 promotion gate on the locked
Hard Test set.

> **External validity update:** v0.4 does not pass the newer official-fixture
> benchmark described below, so it remains a research candidate rather than a
> production release.

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
| train              | 13564 | 5237 | 2619         | 5708 |
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

## External Test v5

`import_official_fixtures.py` imports labels directly from upstream test
annotations instead of assigning labels from local templates:

- GitHub CodeQL (`$ Alert`, `BAD`, `OK`, and `GOOD` annotations), commit-pinned,
  MIT licensed.
- Semgrep Rules (`ruleid` and `ok` annotations), commit-pinned, under the
  Semgrep Rules License v1.0.

Each row records repository, commit, path, line, source URL, license, annotation,
and content hash. The resulting `external_test_v5.jsonl` contains 473 locked,
test-only records from 2 upstream projects and 70 fixture files. It must never
be added to training.

| Metric | External Test v5 |
| --- | ---: |
| Cases | 473 |
| Decided macro F1 | 0.478 |
| Coverage | 0.903 |
| XSS false-positive rate | 0.545 |
| XSS false-negative rate | 0.291 |
| Promotion | **FAIL** |

This result supersedes the v4 promotion decision for production-readiness. It
shows that the synthetic and curated-shape benchmarks substantially overestimate
generalization. The next training corpus must come from separate upstream
projects; tuning against External Test v5 would invalidate it.

```bash
uv run python security-models/xss/scripts/import_official_fixtures.py
uv run --group slm python security-models/xss/evaluation/evaluate_external_v5.py
```

## MiniLM-L6 LoRA specialist

The official v0.5 training path uses a MiniLM-L6 encoder with a PEFT LoRA
sequence-classification adapter for `SAFE`, `POSSIBLE_XSS`, and `XSS`:

```text
snippet -> v0.4 bert-tiny fallback (active)
        -> xss-v0.5 MiniLM-L6 + LoRA candidate
        -> uncertain/high-risk result -> browser oracle
```

Training uses `training/train_peft.py`. The fixed base is
`nreimers/MiniLM-L6-H384-uncased`; the base weights remain frozen and only LoRA
parameters plus the classifier head are trained. External Test v5 is forbidden
from training. The earlier Qwen causal-LM experiment is preserved separately in
`training/train_peft_generative_experimental.py` and is not a release path.

```bash
# Small pipeline smoke training
uv run --group lora python training/train_peft.py \
  --train-limit 12 --validation-limit 6 --epochs 0.1 \
  --output-dir security-models/xss/adapters/xss-v05-smoke

# Candidate training
uv run --group lora python training/train_peft.py \
  --epochs 2 --max-length 256 \
  --output-dir security-models/xss/adapters/xss-v06

# Hybrid inference
uv run --group lora python security-models/xss/inference/hybrid_predict.py \
  --adapter xss-v0.5 \
  "element.innerHTML = userInput"
```

The existing xss-v0.5 adapter scored `0.8359` macro F1 on locked Hard Test v4,
below the v0.4 baseline of `0.9092`. It is therefore rejected for promotion and
v0.4 remains active. A newly trained adapter must pass the same locked benchmark
and generalization gate before activation.
