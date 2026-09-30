# Third-party notices

The Apache-2.0 license in this repository applies to original project code unless
a file or dataset says otherwise. Third-party models, test fixtures, and source
material retain their own upstream terms.

## External XSS fixtures

- GitHub CodeQL fixtures: imported with upstream provenance and recorded as MIT
  in the dataset manifests.
- Semgrep rules fixtures: imported with upstream provenance and recorded under
  the Semgrep Rules License v1.0.

See `security-models/xss/data/external_test_v5.jsonl` and its manifest for
per-record provenance. Quarantined contradictory snippets are kept separately
and are not evaluation inputs.

## Base models

The repository references, but does not bundle, third-party base-model weights,
including Google BERT-family checkpoints and
`nreimers/MiniLM-L6-H384-uncased`. Users must review and comply with the
upstream model-card/license terms when downloading those weights.

## Generated adapters

LoRA/PEFT adapter files in this repository are project-generated deltas. Their
use still requires the compatible upstream base model and does not replace the
base model's license terms.
