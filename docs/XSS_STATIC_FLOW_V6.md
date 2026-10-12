# XSS V6: bounded asynchronous values and DOM-safe text

V5's one-time new synthetic audit (run 38315457687) found
6/8 potential static XSS candidates, 0/8 false positives, and
50% three-way decision coverage. The frozen per-case artifact is
preserved; these exposed audit cases must NOT be presented as
independent evaluation evidence for this V6 update.

The read-only diagnostic run 38315749203 identified:
- an unresolved built-in window.setTimeout string argument;
- an unresolved Promise.resolve(...).then handler;
- a known Text node passed to replaceChildren;
- an untyped anchor receiver after a new URL(...,location.origin)
  constructor, where DOM element identity is still missing.

## Supported V6 patterns

- Global window.setTimeout / window.setInterval string-based code
  sinks, as potential script execution paths. If window is shadowed
  or the callback is a function rather than a string, do not assume
  execution semantics that are not established.
- A one-argument Promise.resolve(value).then(callback) chain with one
  recognized callback parameter and a bounded AST body. Transfer
  the source and trace through the callback; do not assume that an
  arbitrary custom promise, overload or thenable is trusted.
- DOM replaceChildren when every argument is proven to be the result
  of document.createTextNode; inserting arbitrary nodes remains
  unresolved because they may contain executable elements.
- A two-argument new URL(relativeEncodedValue,location.origin) with a
  **fixed root-relative path and encoded query value**, provided URL
  and location are not shadowed. This preserves the narrowly safe
  relative-URL proof when href is later accessed. It does not infer
  that an unknown variable called anchor is really an HTMLAnchorElement.

These operations do not run JavaScript, issue network requests, or
confirm browser exploitability. Their output is still one of:
CANDIDATE, SAFE (bounded local path), or INCONCLUSIVE.

## Validation and production status

The new V6 development tests check both unsafe and safe counterparts,
unknown callbacks, shadowed globals, untyped URL receivers and DOM
nodes whose types cannot be established. CI runs the original suite
without re-running the exposed V5 held-out evaluation as a fresh test.

V1, V2, V3 model checkpoints are preserved and not retrained. The
language model remains subordinate to deterministic AST evidence.
**DO_NOT_PROMOTE** remains in effect for MyHunt/PentesterFlow.
A new, separately authored audit is needed before claims about
generalization; real-world XSS requires actual authorized browser
execution evidence.
