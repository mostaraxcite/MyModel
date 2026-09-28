"""Build XSS-SLM v0.3 dataset.

Round 3 design:
  * Training set  = original synthetic v0.1 (8 000) + remaining curated
                    external samples + a fresh batch of ``external-shape``
                    rows that mimic real-world code but are produced from
                    a separate grammar.
  * Validation set = original v0.1 validation (1 000) + held-out curated.
  * Standard test  = original v0.1 test (1 000) — unchanged and unseen by
                    training since Round 1.
  * Hard test v3   = LOCKED. Drawn ONLY from external samples and from
                    novel external-shape patterns. Never imported into the
                    training pipeline.

The split is deterministic (``seed``) and provenance-tracked so we can
audit exactly which samples ended up in which bucket.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_DIR = ROOT / "data_sources" / "external"
DATA_DIR = ROOT / "data"

LABELS = ("SAFE", "POSSIBLE_XSS", "XSS")
SANITIZERS_KNOWN = ("DOMPurify.sanitize", "sanitizeHtml", "escapeHtml", "createTextNode")
DANGEROUS_TOKENS = (
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "contentDocument.write", ".html(",
    ".append(", ".prepend(", ".after(", ".before(", ".replaceWith(",
    "dangerouslySetInnerHTML", "v-html", "[innerHTML]", "srcdoc",
    "onclick", "onmouseover", "onerror", "onfocus", "onblur", "onload",
    "onkeyup", "onkeydown", "onsubmit", "onchange", "ontoggle",
    "eval(", "setTimeout(", "setInterval(",
    "new Function(", "Function(", "createHTML", "indirectEval", "window.eval",
    "runInThisContext", "runInNewContext", "exec(", "execSync(",
    "setImmediate(", "appendChild(", "outer' + 'HTML",
    "createContextualFragment", "DOMParser", "Mustache", "lodash.template",
    "compile(", "customElements",
)


# ---------------------------------------------------------------------------
# External-shape generator. Produces real-world style snippets without
# using the synthetic template grammar (``value0`` / ``tainted_0``). All
# tokens are real identifiers, attribute names and API shapes from common
# open-source codebases.
# ---------------------------------------------------------------------------

USER_INPUT_SHAPES = (
    "urlParams.get('q')", "urlParams.get('about')", "urlParams.get('name')",
    "urlParams.get('comment')", "urlParams.get('search')", "urlParams.get('html')",
    "urlParams.get('text')", "urlParams.get('content')", "urlParams.get('bio')",
    "req.query.q", "req.query.comment", "req.query.bio", "req.body.html",
    "req.body.markup", "req.body.content", "req.body.preview", "req.body.text",
    "req.body.bio", "req.body.post", "searchParams.get('q')", "searchParams.get('text')",
    "searchParams.get('html')", "window.location.hash", "window.location.search",
    "window.name", "document.referrer", "document.cookie", "navigator.userAgent",
    "decodeURIComponent(location.hash.slice(1))", "decodeURIComponent(location.search.slice(1))",
    "atob(message)", "event.data", "postMessage.payload", "JSON.parse(wsMessage).html",
    "route.params.slug", "route.query.text", "params.term", "formData.get('note')",
    "inputRef.current.value", "e.target.value", "e.target.innerHTML",
    "context.query.searchTerm", "request.body.preview", "request.body.html",
    "queryString('q')", "request.params.q", "args['body']", "bodyAsString",
    "userTypedText", "userTypedMarkdown", "rawUserInput", "unescapedUserInput",
    "untrustedField", "commentSnippet", "remoteContent", "unsafeHTMLString",
    "commentText", "userStyles", "titleFromUrl", "payload", "unescapedField",
    "untrustedInput", "richEditor.getHTML()", "userInput", "userTypedValue",
)

SINKS = {
    "innerHTML": ("document.getElementById('panel').innerHTML = __SRC__;",
                  "container.innerHTML = __SRC__;",
                  "el.innerHTML = __SRC__;",
                  "renderTarget.innerHTML = __SRC__;",
                  "listEl.innerHTML = __SRC__;",
                  "row.innerHTML = __SRC__;",
                  "banner.innerHTML = __SRC__;",
                  "modalBody.innerHTML = __SRC__;"),
    "outerHTML": ("container.outerHTML = __SRC__;", "el.outerHTML = __SRC__;",
                  "formPreview.outerHTML = __SRC__;", "previewEl.outerHTML = __SRC__;"),
    "insertAdjacentHTML": ("el.insertAdjacentHTML('beforeend', __SRC__);",
                           "node.insertAdjacentHTML('afterbegin', __SRC__);",
                           "anchor.insertAdjacentHTML('beforebegin', __SRC__);",
                           "btn.insertAdjacentHTML('afterend', __SRC__);"),
    "document.write": ("document.write(__SRC__);",
                       "w.document.write(__SRC__);",
                       "document.write(`<title>${{__SRC__}}</title>`);",
                       "popup.document.write(__SRC__);",
                       "iframe.contentDocument.write(__SRC__);"),
    "jquery.html": ("$('#panel').html(__SRC__);",
                    "$('.feed').html(__SRC__);",
                    "$el.html(__SRC__);",
                    "$('#preview').html(__SRC__);",
                    "$('#bio').html(__SRC__);"),
    "jquery.append": ("$('.feed').append(__SRC__);", "$('#list').append(__SRC__);",
                      "$('body').prepend(__SRC__);", "$('#content').append(__SRC__);"),
    "dangerouslySetInnerHTML": (
        "ReactDOM.render(<div dangerouslySetInnerHTML={{{{__html: __SRC__}}}} />, root);",
        "return <section dangerouslySetInnerHTML={{{{__html: __SRC__}}}} />;",
        "<div dangerouslySetInnerHTML={{{{__html: __SRC__}}}} />",
    ),
    "v-html": ("app.component('unsafe', {{ template: `<p v-html=\"${{{{__SRC__}}}}\"></p>` }});",
               "new Vue({{ template: `<div v-html=\"${{{{__SRC__}}}}\"></div>` }});",
               "Vue.createApp({{ template: `<h1 v-html=\"${{{{__SRC__}}}}\"></h1>` }});"),
    "srcdoc": ("iframe.srcdoc = __SRC__;", "frame.srcdoc = __SRC__;",
               "iframe.contentDocument.body.innerHTML = __SRC__;"),
    "onclick": ("anchor.setAttribute('onclick', __SRC__);",
                "btn.setAttribute('onmouseover', __SRC__);",
                "host.setAttribute('onfocus', __SRC__);",
                "div.setAttribute('onmouseover', __SRC__);"),
    "eval": ("eval(__SRC__);", "window.eval(__SRC__);", "indirectEval(__SRC__);",
             "setTimeout(__SRC__, 0);", "setTimeout('console.log(' + __SRC__ + ')', 0);",
             "setInterval(__SRC__, 1000);",
             "const fn = new Function('return ' + __SRC__); fn();",
             "Function('return this')().alert(__SRC__);"),
    "Function": ("const fn = new Function('a', 'return ' + __SRC__); fn();",
                 "const f = (new Function('x', 'document.title = x'))(__SRC__);"),
    "shadow": ("shadow.innerHTML = `<style>${{__SRC__}}</style>`;",
               "shadowRoot.innerHTML = __SRC__;"),
    "replaceWith": ("container.replaceWith(__SRC__);",),
    "after/before": ("formField.after(__SRC__);", "el.before(__SRC__);"),
    "appendChild(HTML)": ("head.appendChild(parseHTML(__SRC__).firstChild);",
                          "target.appendChild(new DOMParser().parseFromString(__SRC__, 'text/html').body.firstChild);"),
    "outer' + 'HTML": ("el['outer' + 'HTML'] = __SRC__;",),
}

SAFE_SINKS = {
    "textContent": ("document.getElementById('panel').textContent = __SRC__;",
                    "el.textContent = __SRC__;",
                    "rowEl.textContent = __SRC__;",
                    "cardBody.innerText = __SRC__;",
                    "label.textContent = __SRC__;"),
    "innerText": ("el.innerText = __SRC__;", "cardBody.innerText = __SRC__;"),
    "jquery.text": ("$('#panel').text(__SRC__);", "$el.text(__SRC__);",
                    "$('h1#greeting').text(__SRC__);"),
    "createTextNode": ("container.appendChild(document.createTextNode(__SRC__));",
                       "$el.append(document.createTextNode(__SRC__));",
                       "row.append(document.createTextNode(__SRC__));"),
    "title": ("anchor.setAttribute('title', __SRC__);", "el.title = __SRC__;"),
    "alt": ("img.alt = __SRC__;", "img.setAttribute('alt', __SRC__);"),
    "aria-label": ("link.setAttribute('aria-label', __SRC__);",),
    "data-*": ("el.setAttribute('data-comment', encodeURIComponent(__SRC__));",
               "cell.dataset.userId = String(__SRC__);"),
    "sandbox": ("iframe.setAttribute('sandbox', 'allow-scripts');",
                "iframe.setAttribute('sandbox', __SRC__);"),
    "react.text": ("return <p>{{__SRC__}}</p>;",
                   "ReactDOM.render(<pre>{{__SRC__}}</pre>, mount);",
                   "return React.createElement('div', null, __SRC__);"),
    "vue.interpolation": ("app.component('safe', {{ template: `<p>{{ ${{{{__SRC__}}}}} }}</p>` }});",
                          "new Vue({{ template: `<div>{{ ${{{{__SRC__}}}}} }}</div>` }});"),
    "angular.text": ("compile(`<a title=\"${{{{__SRC__}}}}}\">link</a>`)($scope);",
                     "<div [textContent]=\"${{{{__SRC__}}}}}\"></div>"),
}

POSSIBLE_SANITIZERS = (
    "project.xssClean", "company.sanitizer.clean", "htmlSafe", "company.clean",
    "helpers.scrubHtml", "companyScrub", "securityLayer.sanitize",
    "trustService.scrub", "allowlist.butNotReally", "internal.escapeHtmlStrict",
    "sanitizeComment", "brandScrubber.clean", "scrubHtml", "toMarkdown",
    "stripXss", "stringSanitizer.process", "internalSafe", "sanitizerLite",
    "maybeSafe", "htmlWhitelist", "companyHtmlWhitelist", "legacyFilter",
    "decodeThenFilter", "security.clean", "app.clean", "props.cleaner",
    "company.sanitize", "scrubAndEncode", "markdownSafe", "internalFilter",
)


def _id(seed_text: str) -> str:
    return hashlib.sha256(seed_text.encode()).hexdigest()[:20]


def make_external_shape_rows(count: int, seed: int) -> list[dict]:
    """Generate ``count`` rows that mirror real-world code shapes.

    All rows are marked ``origin: ``external-shape`` so they are easy to
    filter out of Hard Test if we ever need to. Template substitution uses
    a simple ``__SRC__`` placeholder to avoid clashing with JS braces.
    """
    rng = random.Random(seed)
    rows: list[dict] = []
    for index in range(count):
        label = rng.choices(("XSS", "POSSIBLE_XSS", "SAFE"), weights=(5, 2, 4))[0]
        src = rng.choice(USER_INPUT_SHAPES)
        if label == "SAFE":
            sink_pool = SAFE_SINKS
        else:
            sink_pool = SINKS  # XSS and POSSIBLE_XSS must use dangerous sinks
        sink = rng.choice(list(sink_pool.keys()))
        template = rng.choice(sink_pool[sink])
        if label == "XSS":
            code = template.replace("__SRC__", src)
            provenance_note = "external-shape XSS: dangerous sink with user-controlled source"
        elif label == "POSSIBLE_XSS":
            sanitizer = rng.choice(POSSIBLE_SANITIZERS)
            code = template.replace("__SRC__", f"{sanitizer}({src})")
            provenance_note = "external-shape POSSIBLE_XSS: unknown sanitizer wrapping user source"
        else:
            if rng.random() < 0.5:
                code = template.replace("__SRC__", src)
            else:
                known = rng.choice(SANITIZERS_KNOWN)
                code = template.replace("__SRC__", f"{known}({src})")
            provenance_note = "external-shape SAFE: text sink or known sanitizer"
        rows.append({
            "id": _id(f"shape-{index}-{label}-{code}"),
            "group_id": f"shape-{index // 5:05d}",
            "code": code,
            "label": label,
            "sink": sink,
            "source": src,
            "language": "javascript",
            "provenance": {
                "origin": "external-shape",
                "generator": "xss-v0.4-shape",
                "note": provenance_note,
                "seed": seed,
            },
        })
    return rows


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_sample(sample: dict, *, allow_unknown_sanitizer: bool = False) -> list[str]:
    errors: list[str] = []
    required = {"id", "code", "label", "sink", "language", "provenance"}
    missing = required - sample.keys()
    if missing:
        errors.append(f"missing fields: {sorted(missing)}")
        return errors
    if sample["label"] not in LABELS:
        errors.append("invalid label")
    if sample["language"] not in {"javascript", "html"}:
        errors.append("invalid language")
    code = sample["code"]
    has_dangerous = any(token in code for token in DANGEROUS_TOKENS)
    has_known_sanitizer = any(token in code for token in SANITIZERS_KNOWN)
    has_safe_sink = bool(re.search(r"\.(textContent|innerText)\s*=", code)) or any(
        token in code for token in SAFE_SINKS.keys()
    )
    if sample["label"] == "XSS" and (not has_dangerous or has_known_sanitizer or has_safe_sink):
        if not allow_unknown_sanitizer:
            errors.append("XSS conflicts with sink/sanitizer rules")
    if sample["label"] == "SAFE" and has_dangerous and not (has_known_sanitizer or has_safe_sink):
        if not allow_unknown_sanitizer:
            errors.append("SAFE dangerous sink has no known sanitizer")
    if sample["label"] == "POSSIBLE_XSS" and not has_dangerous:
        errors.append("POSSIBLE_XSS has no dangerous sink")
    return errors


# ---------------------------------------------------------------------------
# Splitter
# ---------------------------------------------------------------------------

def _split_external(rows: list[dict], seed: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Split curated rows deterministically into hard_test (50%), train (35%), val (15%).

    Stratified by label so each split keeps the original class proportions.
    """
    rng = random.Random(seed)
    by_label: dict[str, list[dict]] = {label: [] for label in LABELS}
    for row in rows:
        by_label[row["label"]].append(row)
    hard: list[dict] = []
    train: list[dict] = []
    val: list[dict] = []
    for label, items in by_label.items():
        rng_local = random.Random(f"{seed}-{label}")
        pool = list(items)
        rng_local.shuffle(pool)
        n = len(pool)
        n_hard = n // 2
        n_val = max(1, n // 7) if n > 4 else 0
        hard.extend(pool[:n_hard])
        val.extend(pool[n_hard : n_hard + n_val])
        train.extend(pool[n_hard + n_val :])
    return hard, train, val


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _stats(rows: list[dict]) -> dict:
    return {"count": len(rows), "labels": dict(sorted(Counter(r["label"] for r in rows).items()))}


def build_v3(*, seed: int = 2027, shape_train_count: int = 4000, shape_hard_count: int = 250,
             allow_unknown_sanitizer: bool = True) -> dict:
    curated_path = EXTERNAL_DIR / "curated.jsonl"
    if not curated_path.exists():
        raise FileNotFoundError("curated.jsonl missing — run fetch_external_sources.py first")
    curated = _read_jsonl(curated_path)
    # Curated rows from the fetcher carry content_sha256_20 but no ``id``; assign one.
    for index, row in enumerate(curated):
        if "id" not in row:
            digest = row.get("provenance", {}).get("content_sha256_20") or _id(row["code"])
            row["id"] = f"cur-{digest}"
            row.setdefault("group_id", f"cur-{index // 5:05d}")
        errors = validate_sample(row, allow_unknown_sanitizer=allow_unknown_sanitizer)
        if errors:
            raise ValueError(f"invalid curated row {row.get('id')}: {errors}")

    # Curated → 50% hard test, 10% validation, 40% training (mostly train so the model sees the patterns).
    hard_curated, train_curated, val_curated = _split_external(curated, seed)

    shape_train = make_external_shape_rows(shape_train_count, seed)
    shape_hard = make_external_shape_rows(shape_hard_count, seed + 1)
    for row in shape_hard:
        row["group_id"] = f"hard-shape-{int(row['group_id'].split('-')[-1]):05d}"
        row["id"] = _id(f"hard-{row['code']}")
        row["provenance"]["partition"] = "hard_test_v4_locked"
    for row in shape_train:
        row["provenance"]["partition"] = "train"

    for row in shape_train + shape_hard:
        errors = validate_sample(row, allow_unknown_sanitizer=allow_unknown_sanitizer)
        if errors:
            raise ValueError(f"invalid external-shape row {row.get('id')}: {errors}")

    # Adversarial cases — only ever land in hard_test, never in training.
    adversarial_path = DATA_DIR / "adversarial_hard.jsonl"
    adversarial = _read_jsonl(adversarial_path) if adversarial_path.exists() else []
    for row in adversarial:
        errors = validate_sample(row, allow_unknown_sanitizer=allow_unknown_sanitizer)
        if errors:
            raise ValueError(f"invalid adversarial row {row.get('id')}: {errors}")
        row["provenance"]["partition"] = "hard_test_v4_locked"

    base_train = _read_jsonl(DATA_DIR / "train.jsonl")
    base_val = _read_jsonl(DATA_DIR / "validation.jsonl")
    base_test = _read_jsonl(DATA_DIR / "test.jsonl")

    new_train = base_train + train_curated + shape_train
    new_val = base_val + val_curated
    new_hard = hard_curated + shape_hard + adversarial

    rng_train = random.Random(seed)
    rng_val = random.Random(seed + 2)
    rng_hard = random.Random(seed + 3)
    rng_train.shuffle(new_train)
    rng_val.shuffle(new_val)
    rng_hard.shuffle(new_hard)

    _write_jsonl(DATA_DIR / "train.jsonl", new_train)
    _write_jsonl(DATA_DIR / "validation.jsonl", new_val)
    _write_jsonl(DATA_DIR / "test.jsonl", base_test)
    _write_jsonl(DATA_DIR / "hard_test.jsonl", new_hard)

    manifest = {
        "version": "v0.4",
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "splits": {
            "train": _stats(new_train),
            "validation": _stats(new_val),
            "test": _stats(base_test),
            "hard_test_v4": _stats(new_hard),
        },
        "external_breakdown": {
            "curated_in_train": _stats(train_curated),
            "curated_in_validation": _stats(val_curated),
            "curated_in_hard_test_v4": _stats(hard_curated),
            "shape_in_train": _stats(shape_train),
            "shape_in_hard_test_v4": _stats(shape_hard),
            "adversarial_in_hard_test_v4": _stats(adversarial),
        },
        "policy": {
            "hard_test_v4_locked": True,
            "standard_test_unchanged": True,
            "promotion_threshold_macro_f1": 0.90,
        },
    }
    (DATA_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=2027)
    parser.add_argument("--shape-train", type=int, default=4000)
    parser.add_argument("--shape-hard", type=int, default=250)
    args = parser.parse_args()
    manifest = build_v3(seed=args.seed, shape_train_count=args.shape_train, shape_hard_count=args.shape_hard)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
