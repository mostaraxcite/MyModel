# XSS Evidence V4: deterministic facts and model-only focus

## Why V3 did not meet the target

The completed Kaggle field evaluation (2026-10-12; 12 synthetic dev
cases) measured 100% JSON parse validity but **0% exact matching**
for every semantic evidence field. The base Spark model and the
evidence-only LoRA both copied the snippet SHA correctly.

Directly retrieved raw model outputs show the primary interface fault:
the old evaluator asked for nested AST-grounded objects, while the
models emitted simple strings for source, flow, sink, defense and
limitations. There were also **real semantic mistakes**: V3 claimed
outerHTML was a text-only DOM API, and marked simple connected flows
UNKNOWN. It would be incorrect to fix only the score parser, or to
claim that nesting changes prove genuine XSS understanding.

## New authority boundary

XSS V4 treats the existing bounded AST/taint analyzer as the **only
source of security facts**. Its report includes:

- snippet SHA256 and stable per-path IDs (p1, p2, ...)
- observed source expressions; connected / disconnected / unresolved
  flow traces; real sink expression and execution kind
- contextual defense status, limitations and a three-way decision:
  CANDIDATE, SAFE in a bounded path, or INCONCLUSIVE
- deterministic English explanations derived from exact oracle rules
- browser_confirmed=false; **never** a model-confirmed vulnerability

A language model is not asked to echo or regenerate nested AST objects.
Instead its entire permitted output is only a schema-valid focus
proposal referring to IDs already present in the oracle's report:

    {
      "schema_version": "xss-path-focus-v1",
      "snippet_sha256": "<actual digest from oracle>",
      "focus_path_ids": ["p1"]
    }

This is an **ID selection**, not new security evidence. The validator
rejects unknown IDs, duplicate IDs, incorrect SHA, incorrect versions,
extra keys (including verdict/confirmed/defense/explanation), wrong
types, or overlong selections. Even a formally valid model selection
cannot hide any CANDIDATE or INCONCLUSIVE path from presentation.
Every security explanation is rendered by the deterministic code,
never generated from untrusted model prose.

The original evidence-only V3 checkpoint is preserved for research but
not used as an authority. This V4 release does not retrain or evaluate
a model on Kaggle, use live targets, or promote a model to production.

## Use the new local-only CLI

From the MyModel repository:

    uv run xss-grounded ./example.js

To verify a model-suggested focus selection (still without trusting
its opinions or executing source JavaScript):

    uv run xss-grounded ./example.js --model-focus-json ./focus.json

The response always contains the entire immutable oracle evidence.
The model can only influence the listed presentation order, never the
security classification or browser-confirmation state.

For existing programmatic callers:

    from xss_specialist.grounded_advisor import grounded_review
    result = grounded_review(js_source, model_focus=optional_json)

The unified XSS Specialist's review function also accepts
model_focus=optional_json and returns the same locked report under
SpecialistDecision.model_assistance. Its verdict, browser-enforcer
scope, and evidence status remain independently computed.

## Acceptance and next training checkpoint

The CI suite includes adversarial attempts to spoof browser
confirmation, label outerHTML as a text API, invent defenses,
introduce unknown source paths, or hide a candidate by selecting a
safe path. All must be rejected without changing the oracle verdict.

Before any additional GPU fine-tuning, validate this stable **three-key
focus contract** and the AST rules on independent, reviewed snippets.
The exposed old 48-case regression is not a fresh acceptance suite.
Measure candidate recall, false positives, and abstentions separately.
Browser execution evidence on an authorized local fixture is
still required for confirmed XSS.

The oracle is deliberately limited: unsupported syntax and unknown
runtime behavior must remain INCONCLUSIVE rather than being claimed
safe. Zero alerts on a narrow synthetic suite are not proof that a
scanner detects every real-world XSS vulnerability.
