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
established by this repository's normal CI. The recipe uses the Spark
model-author LLaMA-Factory fork's native template named spark, and enables
gradient checkpointing. Do not substitute another model's template.

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

## GitHub Actions: online preparation and GPU training

Workflow: .github/workflows/spark-xss-github-training.yml

- An initial push of this workflow to main runs the **prepare** job on the
  standard GitHub-hosted Ubuntu runner and uploads an artifact containing
  data splits, hashes and the training YAML.
- Actual **train** is available in the Actions tab using **Run workflow**,
  mode=train, plus an immutable 40-hex Hugging Face model revision.
- The train job targets the GitHub-hosted PAID GPU larger runner identified by
  the Run workflow input gpu_runner_label, or repository variable
  SPARK_GPU_RUNNER_LABEL. This is not a self-hosted runner.
- GitHub's available paid GPU larger-runner specification is Tesla T4,
  16 GB VRAM, 28 GB system RAM. T4 does not offer native BF16; the
  workflow uses experimental FP16 4-bit QLoRA and gradient checkpointing.
  Real Spark 4B compatibility/VRAM fit must be proven by an actual GPU run.
- The workflow requires a pinned 40-character model revision, checks
  CUDA and VRAM before training, and installs the model-author fork.
- The model-author training guide documents a LoRA path and the native
  `spark` chat template.
- The output is an **unpromoted LoRA adapter**, uploaded as a short-lived
  GitHub Actions artifact on success. There is no automatic deployment,
  registry promotion or target scanning.
- If no matching GPU runner is connected, a manual train dispatch will remain
  queued; do not expect the standard Ubuntu runner to train Spark 4B.

Important: GitHub-hosted GPU larger runners are available only to
organizations on GitHub Team or Enterprise Cloud, NOT directly to a
repository owned by a personal User account. MyModel is currently owned
by the personal account mostaraxcite. It must be moved or mirrored into
an eligible organization repository which has access to that runner before
paid GPU training can start.

Once the eligible repository has been configured, copy the runner's EXACT
name/label from the repository's Actions > Runners page. Select
Actions > Spark XSS > Run workflow, mode=train, paste the GPU runner
label and the pinned model revision, and leave four_bit=true for Tesla T4.

The model-author documents LoRA on Spark, but 4-bit QLoRA compatibility
on 16 GB T4 is an experimental path rather than a guaranteed result.
Training does not auto-promote results or scan any targets.
