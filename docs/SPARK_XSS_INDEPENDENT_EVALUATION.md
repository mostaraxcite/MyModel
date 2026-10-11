# Independent Spark XSS evaluation (not production clearance)

This is a **locked, synthetic code-review benchmark**, not a browser demonstration
or real-world bug-bounty success rate. The benchmark does not scan or submit to
any website. It cannot justify claiming a runtime-confirmed XSS vulnerability.

## Evaluation sources and provenance

- Model base: `XHToken/Spark-X2.5-4B` revision `0bcb35678590218655dff3765b9e61c83b35e9c4`.
- Trained adapter: private Kaggle notebook `dody2004/spark-xss-qlora-kaggle`,
  verified by `run_status.json` containing training commit
  `a112ec7c4db50e19c40de95f5f35a804d9fdf6fb` and
  `candidate_saved_not_evaluated`.
- 48 manually authored source/sink examples in
  `evaluation/spark_xss_heldout.py`: 24 safe and 24 potentially vulnerable
  static code paths, in 24 matched contrasts.
- The harness hashes full prompts and code snippets against **all 359 SFT v3
  records** (training and prior validation combined). Exact-match or full
  snippet leakage aborts evaluation. Conceptual overlap may still exist and
  means this test is not sufficient for real-world performance claims.

## Metric protocol

- Run base Spark and adapter on **identical** inputs using the same tokenizer,
  first-label inference, seed-independent deterministic logits and 4-bit T4.
- Gold labels are static code-review judgments only, not runtime proofs.
- We report TP/TN/FP/FN, false-positive rate, false-negative rate, precision,
  recall, F1, balanced accuracy, breakdown per family, and correct matched
  safe-vulnerable pairs.
- The full 48-case run scores conditional classification-label probabilities.
  A separate 16-case stratified free-generation smoke test measures actual
  14-field output format, classification correctness, and unsupported claims
  that XSS executed in a real browser. Generation errors count as invalid
  predictions. Even perfect format compliance cannot prove that free-form
  source/sink explanations are evidence-grounded.
- Invalid/abstained outputs are penalized rather than omitted. No training or
  threshold selection is performed on the frozen evaluation corpus.
- Results have **DO_NOT_PROMOTE** status even if accuracy is perfect.

## Operation

The GitHub Action `Spark XSS Independent GPU Evaluation` was created
for an explicit one-shot opt-in. It can be launched by workflow dispatch, or by
a main-branch merge whose commit title contains `[launch-xss-eval]`.

The Action tests corpus integrity on CPU, uploads a private Kaggle kernel
with the successful private training notebook attached via `kernel_sources`,
requests a GPU T4, polls Kaggle status, downloads `report.json` and
`status.json`, and archives them as GitHub Actions artifacts.

Check:
- GitHub workflow under Actions → Spark XSS Independent GPU Evaluation.
- Kaggle notebook: https://www.kaggle.com/code/dody2004/spark-xss-independent-evaluation

Important caveat: a Kaggle CLI push may start with **Accelerator: None**
despite a GPU request. If so, a human must activate `GPU T4 x2` in the
Kaggle editor before saving/running a new version, as was required for training.
A submitted kernel is never called a completed GPU evaluation until the
`report.json` and `status.json` are both verified.

**No automatic MyHunt/PentesterFlow deployment or model promotion occurs.**
Before production: independently audited real site-specific/browser-confirmed
XSS experiments under authorization, unknown/abstain calibration, output
format/evidence validation, and safety review are all still required.
