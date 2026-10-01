# Native-code flow relation pilot

This corpus contains 60 training queries selected from Express and 30 development
queries selected from Fastify. Both upstream repositories license their source
under MIT; complete copyright/license notices are retained with the source
snapshots. Commits and exact source/query byte spans are recorded in every row.

The input source code is original upstream code. No input statements were
rewritten, synthesized, or taken from the locked external XSS benchmark. Selected
files exclude upstream generated validators and serializers. The reviewed
selections were frozen before fitting the first candidate.

## Exact task

The question is explicit local **value** dependency at the selected assignment
program point. `source_expression` names the source value and `sink_expression`
names the assignment target at the byte location in `query_location`.

- CONNECTED: the exact source expression is the RHS assigned directly.
- DISCONNECTED: the selected write assigns a literal independently of a named
  in-scope parameter. This excludes implicit/control dependency and later writes.
- UNKNOWN: a source is passed to a call but its return-value summary is unavailable
  under this excerpt-only, opaque-call policy. Known library behavior outside the
  supplied excerpt is intentionally not part of this task.

These labels are **not** assertions about source trust, XSS sinks, exploitability,
whole-program flow, or actual behavior of a library call. This is a small initial
relation-training task, not the ambiguous whole-program reasoning problem solved.

## Provenance and independence

Training and development repositories and frameworks are distinct. Templates and
code generators are not applicable to these selected handwritten source excerpts;
we record `not-applicable` explicitly rather than inventing disjoint identifiers.
The audit permits that value only with a pinned reference and byte-verified source
snapshot. Generated-code records still require disjoint actual template/generator
identities. Structural template independence of handwritten code is not claimed.

The same Codex agent selected and reviewed these annotations. Reviews are separate
from the XSS analyzer's output, but there has been **no independent expert review**.
The rows have been deliberately balanced and chosen for a bounded simple task;
this is a selection bias and must not be presented as representative XSS accuracy.
Promotion remains disabled.

## Reproduce

Check out the upstream commits recorded in `reviewed_selections.json`, then run:

```
uv run python -m training.build_native_flow_data \
  --express-source /path/to/pinned-express \
  --fastify-source /path/to/pinned-fastify
uv run python -m training.train_flow_relations \
  --train data/flow-relations-v1/train.jsonl \
  --dev data/flow-relations-v1/dev.jsonl \
  --output /path/to/new-candidate
```

The checked-in `flow-relation-v1-native-001` candidate completed training but was
rejected for use: development accuracy 15/30 (50%), macro F1 0.4374, CONNECTED recall
40%, DISCONNECTED recall 100%, UNKNOWN recall 10%. It is an uncalibrated TF-IDF/
logistic model, not an SLM. No tuning or second fitting run was performed after
seeing these development results. The locked external benchmark remains unopened.
