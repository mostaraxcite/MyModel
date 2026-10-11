# Spark-X2.5 XSS training (experimental)

This is an **offline XSS-model training option inside MyModel**. It is not an
active MyHunt or PentesterFlow scanner integration and does not alter the
existing XSS Taint v1 runtime, benchmark gate, or deployed checkpoints.

## What is added

- Base: [XHToken/Spark-X2.5-4B](https://huggingface.co/XHToken/Spark-X2.5-4B).
- Training recipe: **LoRA supervised fine-tuning** using
  [LLaMA-Factory](https://github.com/hiyouga/LlamaFactory), as recommended
  by the Spark-X2.5 authors.
- Data: the existing MyModel data/training/sft_v3.jsonl corpus, explicitly
  marked **synthetic**, or separately reviewed and labeled examples.
- Group-disjoint train/development split by XSS template family. Duplicate
  prompts across groups cause an error instead of silently leaking between
  train and development splits.
- Safety boundaries: deny frozen benchmark directories, reject unknown data
  origins or unreviewed verified examples, and keep generated data, config,
  and future weights under the existing git-ignored models/ directory.
- Manifest: hashes, class mix, split counts, model ID, optional revision,
  and a permanent **NOT_EVALUATED** status until independent evaluation.

The source SFT corpus originates from the historical XSS reasoning experiments.
It is **not real-world vulnerability evidence** and it does not replace the
current deterministic XSS Taint v1 pipeline. This is a separate experiment,
not a reinstatement of the retired whole-snippet classification releases.

## 1. Prepare local training inputs (does NOT train)

From the MyModel root:

    uv run python -m training.spark_xss \
      --input data/training/sft_v3.jsonl \
      --output-dir models/spark-x25-xss

This writes:

- models/spark-x25-xss/train.json and eval.json
- models/spark-x25-xss/dataset_info.json in LLaMA-Factory Alpaca format
- models/spark-x25-xss/train.yaml (LoRA recipe, *not executed*)
- models/spark-x25-xss/manifest.json (provenance, not promotion)

Do not mix held-out or frozen benchmark cases into this source. The tool
refuses inputs outside MyModel's data/training tree.

## 2. Optional training (requires an explicit human action)

Training is **not** started by CI, a scheduled job, or the default command.

Use a CUDA-capable environment with a validated LLaMA-Factory installation
that explicitly supports the Spark spark2_5 architecture and its native
chat template. Validate versions against upstream; compatibility is NOT
established by this repository's normal CI. The recipe intentionally omits
template so a compatible LLaMA-Factory can auto-detect the model's native
chat template. If auto-detection fails, supply a verified one using
--template; do not substitute another model's chat template blindly.

Pin the base revision to the actual **40-character Hugging Face commit SHA**:

    uv run python -m training.spark_xss \
      --model-revision <40_CHARACTER_COMMIT_SHA> \
      --launch-training

This prepares artifacts and, only with --launch-training, invokes
llamafactory-cli train models/spark-x25-xss/train.yaml.

For supported hardware and dependencies you may experiment with
--four-bit to add bitsandbytes QLoRA configuration. The default is
standard BF16 LoRA. Both require appropriate GPU capacity; the model is
not downloaded by the preparer.

Avoid using unsanitized private target traffic, cookies, live URLs, or
unreviewed findings as training input. Inputs are code-review examples,
not an offensive payload corpus.

## 3. Promotion remains blocked until measured

A training run produces a **candidate adapter**, not a production model.

Before promoting it, independently evaluate and compare against the current
MyModel baseline with:

1. Previously unseen **group-disjoint**, real-world and hard-negative XSS
   cases (Reflected, Stored, and DOM-based).
2. Source/sink/sanitizer correctness, false-safe and near-miss behavior.
3. False-positive rate, precision, recall, F1, calibration and abstention.
4. End-to-end browser validation of potentially executing contexts, using
   an authorized, locally controlled test harness.
5. The repository's frozen promotion thresholds and independent human
   approval. Never label anything CONFIRMED based on model output alone.

**Do not run the locked test while tuning hyperparameters.** The training
preparer does not read those files and does not auto-promote to the registry.

## Check the code without GPU

    uv run pytest -q tests/test_spark_xss_training.py

The code is added to the regular MyModel pull-request CI regression suite.
This only checks data preparation and gates, not training compatibility,
real GPU performance, or XSS accuracy.

Further reading:
[Current architecture](ARCHITECTURE.md) and
[Known limitations](KNOWN_LIMITATIONS.md).
