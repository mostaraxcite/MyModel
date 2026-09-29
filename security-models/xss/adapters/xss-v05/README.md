---
base_model: nreimers/MiniLM-L6-H384-uncased
library_name: peft
pipeline_tag: text-classification
tags:
- lora
- transformers
- xss
- research
---

# XSS Specialist xss-v0.5

Experimental three-class XSS classifier for JavaScript and HTML snippets. This
adapter predicts `SAFE`, `POSSIBLE_XSS`, or `XSS` and must be loaded on top of
`nreimers/MiniLM-L6-H384-uncased`.

## Release status

**Rejected candidate. Do not activate as the default model.** The adapter
regressed against the promoted v0.4 bert-tiny baseline, so the registry keeps
`v0.4-baseline` active as the fallback.

| Evaluation | xss-v0.5 | v0.4 baseline |
| --- | ---: | ---: |
| Hard Test v4 macro F1 | 0.8359 | 0.9092 |
| External Test v5 decided macro F1 | 0.4697 | 0.4777 |
| External Test v5 coverage | 0.9239 | 0.9027 |
| External Test v5 XSS false-positive rate | 0.5909 | 0.5455 |

External Test v5 was held out from training. Its official-fixture provenance is
recorded in `security-models/xss/data/external_test_v5_manifest.json`.

## Architecture

- Base: MiniLM-L6 encoder, referenced by model ID and not bundled here.
- Adapter: PEFT LoRA, rank 8, alpha 16, dropout 0.05.
- Targets: `query`, `key`, `value`, and `dense`.
- Trainable task head: three-class sequence classifier.
- Training entry point: `training/train_peft.py`.

The saved directory contains the adapter, classifier head, tokenizer metadata,
and reproducibility metadata. It does not contain the full base-model weights.

## Intended use

Use only for authorized security research, regression testing, and analysis of
XSS model behavior. Treat predictions as advisory. High-risk and uncertain
cases require the browser oracle or human review; model confidence alone cannot
confirm a vulnerability.

## Limitations

Generalization to real project fixtures is weak, and both false positives and
false negatives remain too high for production use. The training corpus also
contains substantial synthetic data. Do not tune on External Test v5, because
doing so would invalidate the held-out gate.

## Reproduction

```bash
uv sync --group lora
uv run --group lora python training/train_peft.py \
  --base-model nreimers/MiniLM-L6-H384-uncased \
  --output-dir security-models/xss/adapters/xss-v06
```

Any new adapter must beat the v0.4 locked baseline and pass the held-out
generalization gate before the registry may mark it as promoted.
