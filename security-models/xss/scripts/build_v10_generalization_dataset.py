"""Build v0.10 XSS corpus with high-diversity contrastive hard negatives.

This builder is training-only and preserves the locked test sets. It removes
exact overlaps with standard/hard/external tests, caps legacy synthetic rows,
then adds group-disjoint contrastive examples whose code shapes vary by source,
framework, context, sink, target variable, sanitizer, and wrapper.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
LABELS = ("SAFE", "POSSIBLE_XSS", "XSS")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def locked_hashes() -> set[str]:
    out: set[str] = set()
    for name in ("test.jsonl", "hard_test.jsonl", "external_test_v5.jsonl"):
        path = DATA / name
        if path.exists():
            out |= {code_hash(row["code"]) for row in read_jsonl(path)}
    return out


def dedup(rows: list[dict], forbidden: set[str]) -> tuple[list[dict], dict]:
    seen: dict[str, str] = {}
    kept: list[dict] = []
    audit = Counter()
    for row in rows:
        h = code_hash(row["code"])
        if h in forbidden:
            audit["locked_overlap"] += 1
            continue
        if h in seen:
            audit["label_conflict" if seen[h] != row["label"] else "duplicate"] += 1
            continue
        seen[h] = row["label"]
        kept.append(row)
    return kept, dict(audit)


def cap_legacy(rows: list[dict], seed: int, per_label: int) -> list[dict]:
    rng = random.Random(seed)
    legacy: dict[str, list[dict]] = defaultdict(list)
    modern: list[dict] = []
    for row in rows:
        p = row.get("provenance", {})
        if p.get("origin") == "synthetic" or p.get("generator") == "xss-v0.1":
            legacy[row["label"]].append(row)
        else:
            modern.append(row)
    for label in LABELS:
        pool = legacy[label]
        rng.shuffle(pool)
        modern.extend(pool[:per_label])
    return modern


SOURCES = [
    "req.query.q", "req.query.search", "req.query.name", "req.params.slug",
    "req.params.id", "req.body.comment", "req.body.bio", "request.body.html",
    "request.body.preview", "location.hash.slice(1)", "location.search.slice(1)",
    "new URLSearchParams(location.search).get('q')",
    "new URL(location.href).searchParams.get('preview')",
    "event.data", "message.data", "window.name", "document.referrer",
    "formData.get('bio')", "formData.get('comment')", "route.query.preview",
    "route.params.id", "input.value", "editor.getHTML()", "socketMessage.html",
]

TARGETS = [
    "panel", "preview", "container", "result", "output", "content",
    "messageBox", "cardBody", "modalBody", "description", "profile",
]

SAFE_ATTRS = ["title", "aria-label", "alt", "data-label"]
UNKNOWN_SANITIZERS = [
    "cleanHtml", "projectSanitize", "legacyScrubber", "security.clean",
    "sanitizeMarkup", "filterRichText", "trustedMarkup",
]
KNOWN_SANITIZERS = ["DOMPurify.sanitize", "sanitizeHtml", "escapeHtml"]
WRAPPERS = [
    ("direct", "{expr}"),
    ("decoded", "decodeURIComponent({expr})"),
    ("string", "String({expr})"),
    ("trimmed", "String({expr}).trim()"),
]
ROUTES = ["/search", "/profile", "/preview", "/comment", "/lookup", "/article"]


def make_row(group: str, idx: int, code: str, label: str, sink: str, source: str, family: str) -> dict:
    return {
        "id": hashlib.sha256(f"{group}:{idx}:{label}:{code}".encode()).hexdigest()[:20],
        "group_id": group,
        "code": code,
        "label": label,
        "language": "javascript",
        "sink": sink,
        "source": source,
        "provenance": {
            "origin": "contrast-v10",
            "generator": "build_v10_generalization_dataset.py",
            "family": family,
            "training_only": True,
        },
    }


def wrapped(source: str, wrapper: tuple[str, str]) -> str:
    return wrapper[1].format(expr=source)


def contrast_group(index: int, family: str, source: str, target: str, wrapper: tuple[str, str]) -> list[dict]:
    src = wrapped(source, wrapper)
    sanitizer = UNKNOWN_SANITIZERS[index % len(UNKNOWN_SANITIZERS)]
    known = KNOWN_SANITIZERS[index % len(KNOWN_SANITIZERS)]
    route = ROUTES[index % len(ROUTES)]
    attr = SAFE_ATTRS[index % len(SAFE_ATTRS)]
    gid = f"v10-{family}-{index:05d}"
    rows: list[dict] = []

    if family == "dom-inner":
        rows += [
            make_row(gid, 0, f"{target}.innerHTML = {src};", "XSS", "innerHTML", source, family),
            make_row(gid, 1, f"{target}.textContent = {src};", "SAFE", "textContent", source, family),
            make_row(gid, 2, f"{target}.innerHTML = {known}({src});", "SAFE", "innerHTML", source, family),
            make_row(gid, 3, f"{target}.innerHTML = {sanitizer}({src});", "POSSIBLE_XSS", "innerHTML", source, family),
        ]
    elif family == "dom-adjacent":
        pos = ("beforeend", "afterbegin", "beforebegin", "afterend")[index % 4]
        rows += [
            make_row(gid, 0, f"{target}.insertAdjacentHTML('{pos}', {src});", "XSS", "insertAdjacentHTML", source, family),
            make_row(gid, 1, f"{target}.append(document.createTextNode({src}));", "SAFE", "createTextNode", source, family),
            make_row(gid, 2, f"{target}.insertAdjacentHTML('{pos}', {known}({src}));", "SAFE", "insertAdjacentHTML", source, family),
            make_row(gid, 3, f"{target}.insertAdjacentHTML('{pos}', {sanitizer}({src}));", "POSSIBLE_XSS", "insertAdjacentHTML", source, family),
        ]
    elif family == "dom-attr":
        rows += [
            make_row(gid, 0, f"{target}.setAttribute('onclick', {src});", "XSS", "event-handler", source, family),
            make_row(gid, 1, f"{target}.setAttribute('{attr}', {src});", "SAFE", attr, source, family),
            make_row(gid, 2, f"{target}.setAttribute('onclick', encodeURIComponent({src}));", "SAFE", "event-handler", source, family),
            make_row(gid, 3, f"{target}.setAttribute('onclick', {sanitizer}({src}));", "POSSIBLE_XSS", "event-handler", source, family),
        ]
    elif family == "jquery":
        selector = ("#result", ".preview", "#profile", ".message")[index % 4]
        rows += [
            make_row(gid, 0, f"$('{selector}').html({src});", "XSS", "jquery.html", source, family),
            make_row(gid, 1, f"$('{selector}').text({src});", "SAFE", "jquery.text", source, family),
            make_row(gid, 2, f"$('{selector}').html({known}({src}));", "SAFE", "jquery.html", source, family),
            make_row(gid, 3, f"$('{selector}').html({sanitizer}({src}));", "POSSIBLE_XSS", "jquery.html", source, family),
        ]
    elif family == "react":
        rows += [
            make_row(gid, 0, "return <section dangerouslySetInnerHTML={{__html: " + src + "}} />;", "XSS", "dangerouslySetInnerHTML", source, family),
            make_row(gid, 1, "return <section>{" + src + "}</section>;", "SAFE", "react.text", source, family),
            make_row(gid, 2, "return <section dangerouslySetInnerHTML={{__html: " + known + "(" + src + ")}} />;", "SAFE", "dangerouslySetInnerHTML", source, family),
            make_row(gid, 3, "return <section dangerouslySetInnerHTML={{__html: " + sanitizer + "(" + src + ")}} />;", "POSSIBLE_XSS", "dangerouslySetInnerHTML", source, family),
        ]
    elif family == "vue":
        rows += [
            make_row(gid, 0, f"const vm = {{ template: '<article v-html=\"body\"></article>', data: () => ({{body: {src}}}) }};", "XSS", "v-html", source, family),
            make_row(gid, 1, f"const vm = {{ template: '<article>{{{{ body }}}}</article>', data: () => ({{body: {src}}}) }};", "SAFE", "vue.interpolation", source, family),
            make_row(gid, 2, f"const body = {known}({src}); {target}.innerHTML = body;", "SAFE", "innerHTML", source, family),
            make_row(gid, 3, f"const body = {sanitizer}({src}); {target}.innerHTML = body;", "POSSIBLE_XSS", "innerHTML", source, family),
        ]
    elif family == "angular":
        rows += [
            make_row(gid, 0, f"this.preview = this.sanitizer.bypassSecurityTrustHtml({src});", "XSS", "bypassSecurityTrustHtml", source, family),
            make_row(gid, 1, f"this.previewText = {src}; // bound with [textContent]", "SAFE", "angular.text", source, family),
            make_row(gid, 2, f"this.preview = {known}({src});", "SAFE", "sanitized-html", source, family),
            make_row(gid, 3, f"this.preview = {sanitizer}({src});", "POSSIBLE_XSS", "unknown-sanitizer", source, family),
        ]
    elif family == "server":
        rows += [
            make_row(gid, 0, f"app.get('{route}', (req, res) => res.send('<div>' + {src} + '</div>'));", "XSS", "http-html-response", source, family),
            make_row(gid, 1, f"app.get('{route}', (req, res) => res.type('text/plain').send(String({src})));", "SAFE", "http-text-response", source, family),
            make_row(gid, 2, f"app.get('{route}', (req, res) => res.send('<div>' + {known}({src}) + '</div>'));", "SAFE", "http-html-response", source, family),
            make_row(gid, 3, f"app.get('{route}', (req, res) => res.send('<div>' + {sanitizer}({src}) + '</div>'));", "POSSIBLE_XSS", "http-html-response", source, family),
        ]
    elif family == "constant-hard-negative":
        literal = ("<strong>Welcome</strong>", "<em>Preview</em>", "<span>Ready</span>")[index % 3]
        rows += [
            make_row(gid, 0, f"{target}.innerHTML = {src};", "XSS", "innerHTML", source, family),
            make_row(gid, 1, f"{target}.innerHTML = {literal!r};", "SAFE", "innerHTML-constant", "constant", family),
            make_row(gid, 2, f"{target}.textContent = {src};", "SAFE", "textContent", source, family),
            make_row(gid, 3, f"{target}.innerHTML = {sanitizer}({src});", "POSSIBLE_XSS", "innerHTML", source, family),
        ]
    else:
        raise ValueError(f"unknown family: {family}")
    return rows


def generate_groups(seed: int, count: int) -> list[list[dict]]:
    families = (
        "dom-inner", "dom-adjacent", "dom-attr", "jquery", "react",
        "vue", "angular", "server", "constant-hard-negative",
    )
    combos = list(product(families, SOURCES, TARGETS, WRAPPERS))
    rng = random.Random(seed)
    rng.shuffle(combos)
    if count > len(combos):
        raise ValueError(f"requested {count} groups but only {len(combos)} semantic combinations exist")
    return [
        contrast_group(i, family, source, target, wrapper)
        for i, (family, source, target, wrapper) in enumerate(combos[:count])
    ]


def split_groups(groups: list[list[dict]], seed: int, val_fraction: float) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    groups = list(groups)
    rng.shuffle(groups)
    cut = max(1, round(len(groups) * val_fraction))
    val = groups[:cut]
    train = groups[cut:]
    return [r for g in train for r in g], [r for g in val for r in g]


def stats(rows: list[dict]) -> dict:
    return {
        "count": len(rows),
        "labels": dict(sorted(Counter(r["label"] for r in rows).items())),
        "origins": dict(sorted(Counter(r.get("provenance", {}).get("origin", "") for r in rows).items())),
        "unique_hashes": len({code_hash(r["code"]) for r in rows}),
        "groups": len({r.get("group_id") for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2030)
    p.add_argument("--groups", type=int, default=1800)
    p.add_argument("--legacy-per-label", type=int, default=1800)
    p.add_argument("--validation-fraction", type=float, default=0.18)
    args = p.parse_args()

    forbidden = locked_hashes()
    base_train, audit_base_train = dedup(read_jsonl(DATA / "train.jsonl"), forbidden)
    base_val, audit_base_val = dedup(read_jsonl(DATA / "validation.jsonl"), forbidden)
    base_train = cap_legacy(base_train, args.seed, args.legacy_per_label)
    base_val = cap_legacy(base_val, args.seed + 1, max(300, args.legacy_per_label // 4))

    groups = generate_groups(args.seed, args.groups)
    generated_train, generated_val = split_groups(groups, args.seed + 2, args.validation_fraction)

    train, audit_train = dedup(base_train + generated_train, forbidden)
    train_hashes = {code_hash(r["code"]) for r in train}
    validation, audit_val = dedup(base_val + generated_val, forbidden | train_hashes)

    rng = random.Random(args.seed)
    rng.shuffle(train)
    rng.shuffle(validation)

    write_jsonl(DATA / "train_v10.jsonl", train)
    write_jsonl(DATA / "validation_v10.jsonl", validation)

    manifest = {
        "version": "v0.10-generalization",
        "seed": args.seed,
        "policy": {
            "external_test_v5_training_allowed": False,
            "hard_test_v4_training_allowed": False,
            "standard_test_training_allowed": False,
            "exact_hash_overlap_with_locked_sets": 0,
            "group_disjoint_generated_train_validation": True,
        },
        "inputs": {
            "generated_groups": args.groups,
            "legacy_per_label_cap": args.legacy_per_label,
            "validation_fraction": args.validation_fraction,
        },
        "train": stats(train),
        "validation": stats(validation),
        "audit": {
            "base_train": audit_base_train,
            "base_validation": audit_base_val,
            "final_train": audit_train,
            "final_validation": audit_val,
        },
    }
    (DATA / "manifest_v10.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
