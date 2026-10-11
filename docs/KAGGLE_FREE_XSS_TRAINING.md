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
5. Supply the EXACT Kaggle username from the notebook URL (for the current account: dody2004, NOT "Kaggle") and choose:
   - package (default): validates scripts and produces an archive; no Kaggle job.
   - publish (**recommended**): uploads the private script but uses kaggle kernels push --no-run. Then open the notebook on Kaggle, click Edit, use Settings / Session options > Accelerator > GPU T4 x2, enable Internet, and choose Save Version > Save & Run All. The GPU assignment occurs in Kaggle's editor.
   - submit (experimental): requests an accelerated run via Kaggle CLI, but the API can accept a push while the actual session runs with Accelerator: None. This is NOT proof of training or GPU assignment. Always confirm the Logs tab and CUDA availability.

You can inspect the kernel at:

    https://www.kaggle.com/code/YOUR_USERNAME/spark-xss-qlora-kaggle

Once submitted, monitor through the authenticated Kaggle CLI:

    kaggle kernels status YOUR_USERNAME/spark-xss-qlora-kaggle
    kaggle kernels logs YOUR_USERNAME/spark-xss-qlora-kaggle
    kaggle kernels output YOUR_USERNAME/spark-xss-qlora-kaggle -p output

Or use the Kaggle Notebook page. Kaggle must permit Internet access to download pinned model and framework code. Kaggle may queue/reject jobs that exceed your free quota.

## October 2026: accepted kernel without GPU

The first Kaggle run at https://www.kaggle.com/code/dody2004/spark-xss-qlora-kaggle was marked failed in 14 seconds. Its Logs tab said "Accelerator: None" and the CUDA preflight correctly raised "CUDA GPU unavailable". The GitHub step had successfully pushed the kernel version; that alone did not guarantee a GPU. The workflow also received a mistaken Kaggle username ("Kaggle") instead of the actual account "dody2004", causing its status check to fail.

**Current recovery:** The notebook already exists, so DO NOT push the same version again just to enable the GPU. Open it in the Kaggle editor, turn on GPU T4 x2 and Internet, and use Save Version > Save & Run All. Verify that the new version's Logs tab shows Accelerator: GPU T4 x2 and that its CUDA preflight reports a real device. If the GPU option is disabled, check Kaggle phone verification and remaining free quota. The CLI-supported accelerator flag may be ignored by Kaggle's scheduling/API, so a successful push must not be described as successful GPU training.

Docs: https://www.kaggle.com/docs/notebooks and https://www.kaggle.com/discussions/product-feedback/268333 .

## GitHub Actions failure #2: unsupported --no-run flag

The GitHub Actions run 38176279389 failed during **publish**, after preparing
the private Kaggle package. It did not submit a new Kaggle job. The PyPI
Kaggle CLI version installed by `pip install --upgrade kaggle` rejected
`--no-run` (exit code 2).

The workflow now installs Kaggle's upstream CLI from the immutable commit
`9c57dd74c29904c40ff7879eed33644be89d2e2f`, whose `kernels push`
implementation supports `--no-run`. It checks the option exists BEFORE
sending any request in publish mode, failing closed instead of accidentally
executing the kernel. GitHub CI performs a separate command-line smoke test
without needing Kaggle credentials.

After this fix is merged, run the GitHub workflow **as a new Run workflow**
with username `dody2004` and mode `publish`. Do NOT rerun the old failed
run, since it checks out an older MyModel commit.

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

## Kaggle Version 4: Transformers 5.x incompatibility

The October 11 Kaggle Version 4 reached Tesla T4, downloaded the 4B model,
and tokenized **308 training / 51 development examples**. It failed while
constructing the Spark model, BEFORE the first training step:

    AttributeError: 'list' object has no attribute 'keys'

The traceback was in Transformers 5.x
`get_expanded_tied_weights_keys`. Spark model code supplies an old-style
list mapping but Transformers 5.x expects a dict. The model-author's
Spark fine-tuning guide documents **transformers 4.57.1**, so the Kaggle
launcher now explicitly pins 4.57.1 after installing the framework fork and
verifies the version BEFORE downloading model weights.

**The existing Kaggle notebook remains pinned to an OLD MyModel commit.**
A new GitHub commit does not silently update an already-saved Kaggle notebook.

To install the corrected script safely, choose Actions > Kaggle Free GPU -
Spark XSS on GitHub and manually dispatch with username **dody2004**
and mode **publish** (uploads source without running it). Then open the
notebook on Kaggle and explicitly enable GPU T4 x2 plus Internet before
Save Version > Save & Run All. Alternatively update the existing Kaggle
notebook's install_training_deps function to install transformers==4.57.1
before starting training. Merely repeating the OLD Kaggle Version 4 will
repeat the same crash.

This is a compatibility fix based on the identified traceback. It does
**not** demonstrate that 4B QLoRA fits within the first T4's 16 GiB
or that training/evaluation subsequently succeeds.

Existing paid GPU workflow remains unchanged:
.github/workflows/spark-xss-github-training.yml

External docs:
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels.md
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels_metadata.md
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/README.md
- https://github.com/XHToken/LlamaFactory/blob/main/examples/torch_spark2_5/Spark2_5_Finetune.md
