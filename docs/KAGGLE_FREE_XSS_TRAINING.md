# Free Spark-X2.5 XSS training on Kaggle

This is an **optional Kaggle GPU training route** for the existing MyModel XSS specialist.
It preserves GitHub Actions training and leaves MyHunt/PentesterFlow untouched.
No GPU training happens simply by merging this documentation or the code.

## Design

1. GitHub Actions, on a normal Ubuntu runner, tests and packages a PRIVATE Kaggle kernel pinned to the exact MyModel commit.
2. Kaggle T4 x2: run the pinned script with CUDA, a pinned model-author LLaMA-Factory fork, a runtime-pinned public Spark-X2.5-4B revision and the existing curated XSS training data.
3. Kaggle outputs: an experimental 4-bit LoRA adapter and run status, not an automatically promoted model.

**The two T4 cards do not pool into 32 GB of VRAM.** This script uses GPU 0 and one process. Its single T4 has approximately 16 GiB of VRAM. Successful Spark QLoRA training on that card has not yet been confirmed. Kaggle GPU quota/availability can vary.

## One-time setup and launch

1. Sign in to https://www.kaggle.com and check remaining free GPU quota.
2. Obtain your Kaggle API token at https://www.kaggle.com/settings/api .
3. In GitHub MyModel, use Settings > Secrets and variables > Actions to add the secret named KAGGLE_API_TOKEN. Do not put a token into code or commit messages.
4. Go to Actions > Kaggle Free GPU - Spark XSS > Run workflow.
5. Supply YOUR Kaggle username and choose one of two modes:
   - package (default): validates the scripts and creates a downloadable kernel package on GitHub; no Kaggle GPU time is consumed.
   - submit: publishes a PRIVATE Kaggle script and starts the Kaggle GPU training, subject to quota, using the API token secret.

You can inspect the kernel at:

    https://www.kaggle.com/code/YOUR_USERNAME/spark-xss-qlora-kaggle

Once submitted, monitor through the authenticated Kaggle CLI:

    kaggle kernels status YOUR_USERNAME/spark-xss-qlora-kaggle
    kaggle kernels logs YOUR_USERNAME/spark-xss-qlora-kaggle
    kaggle kernels output YOUR_USERNAME/spark-xss-qlora-kaggle -p output

Or use the Kaggle Notebook page. Kaggle must permit Internet access to download pinned model and framework code. Kaggle may queue/reject jobs that exceed your free quota.

## Offline packaging without any Kaggle credentials

From a clone of the MyModel repository:

    python scripts/build_kaggle_xss_kernel.py \
      --owner YOUR_KAGGLE_USERNAME \
      --sha "$(git rev-parse HEAD)" \
      --output-dir kaggle-dist

This packages spark_xss_train.py, kernel-metadata.json and a manifest. The metadata requests a PRIVATE T4x2 script kernel, with GPU and Internet enabled.

To push manually using your own authenticated Kaggle CLI:

    kaggle kernels push -p kaggle-dist --accelerator NvidiaTeslaT4 --timeout 18000

WARNING: Kaggle kernels push starts a remote GPU job. Pass --no-run if you only want to upload the notebook without running training.

## Training configuration and output

- Input: data/training/sft_v3.jsonl, currently 359 synthetic XSS SFT examples grouped by template family. They do not represent real-world confirmed vulnerabilities.
- Training: FP16, 4-bit NF4 bitsandbytes, rank-8 LoRA, gradient checkpointing, cutoff length 1024, one epoch. These settings are experimental and may still exhaust Kaggle T4 GPU RAM.
- The source commit and framework commit are pinned. Hugging Face model revision is resolved to a commit at the start of the GPU run and logged.
- A finished candidate is saved under /kaggle/working/spark-xss-result/training/adapter. Run status lives at /kaggle/working/spark-xss-result/run_status.json.
- Successful completion requires status candidate_saved_not_evaluated and an actual adapter_config.json file.
- A model candidate is NEVER automatically added to the runtime or registry. Browser confirmation remains the authority for CONFIRMED XSS findings. Use independent held-out near-miss and hard-negative evaluations before promotion.

Existing paid GPU workflow remains unchanged:
.github/workflows/spark-xss-github-training.yml

External docs:
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels.md
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels_metadata.md
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/README.md
- https://github.com/XHToken/LlamaFactory/blob/main/examples/torch_spark2_5/Spark2_5_Finetune.md
