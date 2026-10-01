# External v7 — Sealed Generalization Protocol

Status: **LOCKED BEFORE FIRST SCORE**

This benchmark is a fresh external gate for the XSS structural specialist after
Source Head v4e. It MUST NOT reuse External v6 repositories, cases, thresholds,
or row-level failures.

## Candidate under test

- Semantic run: `36920030570`
- Semantic artifact: `xss-source-v4e-lr25e5-e12`
- Canonical flow run: `36867388302`
- Flow artifact: `xss-flow-v2-candidate-f0-lr3e5-e8`
- Deterministic semantic + relation oracles remain authoritative where bounded.
- Neural outputs are advisory only and can never confirm XSS.

## Frozen upstream repositories

Exactly these pinned snapshots are used:

| family | repository | commit |
|---|---|---|
| alpine | alpinejs/alpine | da60871ea404e23e46938c9e6137f05258614c63 |
| express | expressjs/express | 7ef98448f8b38099ab1ded55e458538ad47a51e7 |
| vue-router | vuejs/router | 610644a63281a0415b8769f7830c3d80fbb55f49 |
| lit | lit/lit | 01dbc6673cdc211543932afd0ca04e223e567366 |
| sanitize-html | apostrophecms/sanitize-html | 6ac6b8ea4898c2ba7f843d8cdd5f7d036d760a0e |

No repository used by External v6 is permitted.

## Frozen selection rules

Selection is lexical and deterministic. Files are sorted by repository-relative
path, then line number. Generated/minified/vendor/node_modules output is excluded.

The evaluator selects at most 2 qualifying rows per family and never substitutes
rows from another family.

- **alpine**: dynamic HTML-producing DOM sinks (`innerHTML`, `outerHTML`,
  `insertAdjacentHTML`) from source packages.
- **express**: explicit request-derived source expressions containing
  `req/request.(query|body|params|headers|cookies)`.
- **vue-router**: framework source expressions involving route/router params,
  query/search params, or route-derived values.
- **lit**: dynamic DOM/HTML sink expressions or unsafe HTML directive usage;
  if no qualifying sink exists, a safe text/template output expression may be
  selected as `SAFE_OUTPUT`.
- **sanitize-html**: sanitizer invocations that pass a dynamic value into
  `sanitizeHtml(...)` / `sanitize(...)` and are labeled `SANITIZATION`.

A family may contain one qualifying row. Zero rows makes the benchmark invalid.
The full benchmark must contain at least 8 rows.

## Frozen labels

Only the structural field taxonomy already defined by the project is used.

- source: NONE / BROWSER / SERVER / FRAMEWORK / OTHER
- sink: NONE / DANGEROUS_HTML / DANGEROUS_JS / DANGEROUS_URL / SAFE_OUTPUT / OTHER
- defense: NONE / SANITIZATION / CONTEXTUAL_ENCODING / FRAMEWORK_ESCAPING /
  SAFE_DOM_API / INPUT_CONSTRAINT / OTHER

Expected labels are produced only by the frozen lexical selection rules above;
they are not changed after seeing predictions.

## Frozen thresholds

The v7 gate passes only when all are true:

- selection integrity = true
- authority boundary = true
- deterministic/system primary accuracy >= **0.85**
- neural model-advice primary accuracy >= **0.70**
- minimum family system accuracy >= **0.50**
- no External v6 repository is present

These thresholds are fixed before the first scored v7 run.

## Information barrier

The first scored run may print aggregate metrics only. Case-level failures are
written to an artifact for audit but MUST NOT be inspected or used to tune this
candidate. If v7 fails, v7 is sealed and any later improvement must be evaluated
on a new External v8 benchmark with different repositories.

## Promotion

Passing External v7 is a research gate only. `promotion_allowed=false`.
Browser execution remains required for confirmed XSS.
