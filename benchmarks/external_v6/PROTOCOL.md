# XSS External v6 — frozen selection protocol

Status: **LOCKED BEFORE CASE INSPECTION**

This benchmark is a one-shot external architecture gate. It is not training or
development data. External v5 remains untouched.

## Frozen upstream repositories

| Repository | Frozen commit |
|---|---|
| bigskysoftware/htmx | fa978b24e75fb03c137bf2cdae4fef0e711cf8a1 |
| janl/mustache.js | 972fd2b27a036888acfcb60d6119317744fac7ee |
| koajs/koa | 824c1cf8de9a91a2941973b25dc8a3d3029b9e4f |
| remix-run/react-router | a6090382ed467b5a2d46c8de1a13b331f14959f8 |
| hotwired/turbo | 75350a19212ef0d29a0e6db75e0bfdeb96b10cd7 |

The repositories and commits above were fixed before reading candidate source
files for v6.

## Case extraction rules

Case selection must follow these lexical rules, not model success/failure:

1. **htmx** — take the first two production-code occurrences, in repository path
   order, that write dynamic content through an HTML-producing DOM API such as
   innerHTML or insertAdjacentHTML.
2. **mustache.js** — take the first two production/spec occurrences, in path
   order, that demonstrate the library's HTML escaping path on a non-literal
   value.
3. **koa** — take the first two production/example/test occurrences, in path
   order, where request-derived or variable data is assigned to the HTTP response
   body or redirect location.
4. **react-router** — take the first two production/example/test occurrences, in
   path order, where route/query/location-derived data is read and subsequently
   used in an output/navigation expression within the bounded excerpt.
5. **turbo** — take the first two production-code occurrences, in path order,
   that write dynamic content through an HTML-producing DOM API.

If a repository has fewer than two qualifying occurrences, record the shortfall
and do not substitute another repository.

## Integrity rules

- Store exact repository, commit, file path, and literal excerpt for every case.
- Verify the excerpt exists byte-for-byte in the frozen checkout before scoring.
- No v6 row may enter train/dev, augmentation, prompt tuning, rule tuning, or
  threshold tuning.
- After the first scored v6 run, only aggregate metrics may guide future
  architecture decisions. Row-level failures are quarantined from development.
- The neural/static system cannot confirm XSS. Confirmation authority remains
  observed browser execution.
- A v6 pass does not by itself allow promotion; end-to-end browser authority
  must also pass.
- promotion_allowed remains false inside the v6 evaluator.
