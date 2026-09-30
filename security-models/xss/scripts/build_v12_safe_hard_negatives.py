"""Build v0.12 SAFE-hard-negative contrast data.

Purpose:
- teach the classifier that dangerous sink tokens alone do not imply XSS;
- preserve XSS recall with paired tainted controls;
- keep train/dev group-disjoint;
- exclude exact overlap with locked standard/hard/external tests.

The generator follows the classifier contract: XSS requires a recognizable
untrusted-source -> executable-sink flow. Constant/local trusted values,
framework-escaped interpolation, safe text sinks, and known sanitizers are SAFE.
Unknown sanitizer/trust helpers remain POSSIBLE_XSS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

UNTRUSTED = [
    "req.query.q", "req.query.html", "req.body.comment", "req.body.preview",
    "request.params.slug", "request.body.bio", "location.hash.slice(1)",
    "location.search.slice(1)", "new URLSearchParams(location.search).get('q')",
    "event.data", "message.data", "window.name", "document.referrer",
    "formData.get('comment')", "input.value", "editor.getHTML()",
]

TRUSTED_LITERALS = [
    "'<p>Welcome</p>'",
    "'<strong>Saved</strong>'",
    "'<span class=\"status\">Ready</span>'",
    "'<div data-state=\"ok\">OK</div>'",
    "'<em>No results</em>'",
]

TARGETS = [
    "panel", "preview", "container", "result", "output", "content",
    "modalBody", "cardBody", "messageBox", "profile", "description",
]

KNOWN_SANITIZERS = [
    "DOMPurify.sanitize", "sanitizeHtml", "escapeHtml",
]

UNKNOWN_SANITIZERS = [
    "projectSanitize", "cleanHtml", "legacyScrubber",
    "security.clean", "trustedMarkup", "filterRichText",
]

FAMILIES = [
    "innerhtml-constant",
    "innerhtml-alias",
    "adjacent-constant",
    "srcdoc-constant",
    "jquery-html-constant",
    "react-dangerous-constant",
    "server-html-constant",
    "known-sanitizer-alias",
    "text-sink",
    "safe-attribute",
]


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def h(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def locked_hashes() -> set[str]:
    out: set[str] = set()
    for name in ("test.jsonl", "hard_test.jsonl", "external_test_v5.jsonl"):
        p = DATA / name
        if p.exists():
            out |= {h(r["code"]) for r in read_jsonl(p)}
    return out


def make_row(group: str, idx: int, code: str, label: str, family: str, source: str, sink: str) -> dict:
    return {
        "id": hashlib.sha256(f"{group}:{idx}:{label}:{code}".encode()).hexdigest()[:20],
        "group_id": group,
        "code": code,
        "label": label,
        "language": "javascript",
        "source": source,
        "sink": sink,
        "provenance": {
            "origin": "safe-hard-negative-v12",
            "generator": "build_v12_safe_hard_negatives.py",
            "family": family,
            "training_allowed": True,
        },
    }


def build_group(i: int, family: str, source: str, target: str, literal: str) -> list[dict]:
    gid = f"v12-safe-{family}-{i:05d}"
    known = KNOWN_SANITIZERS[i % len(KNOWN_SANITIZERS)]
    unknown = UNKNOWN_SANITIZERS[i % len(UNKNOWN_SANITIZERS)]
    rows: list[dict] = []

    if family == "innerhtml-constant":
        rows = [
            make_row(gid, 0, f"{target}.innerHTML = {literal};", "SAFE", family, "constant", "innerHTML"),
            make_row(gid, 1, f"{target}.innerHTML = {source};", "XSS", family, source, "innerHTML"),
            make_row(gid, 2, f"{target}.innerHTML = {known}({source});", "SAFE", family, source, "innerHTML"),
            make_row(gid, 3, f"{target}.innerHTML = {unknown}({source});", "POSSIBLE_XSS", family, source, "innerHTML"),
        ]
    elif family == "innerhtml-alias":
        rows = [
            make_row(gid, 0, f"const markup = {literal};\n{target}.innerHTML = markup;", "SAFE", family, "local-constant", "innerHTML"),
            make_row(gid, 1, f"const markup = {source};\n{target}.innerHTML = markup;", "XSS", family, source, "innerHTML"),
            make_row(gid, 2, f"const markup = {known}({source});\n{target}.innerHTML = markup;", "SAFE", family, source, "innerHTML"),
            make_row(gid, 3, f"const markup = {unknown}({source});\n{target}.innerHTML = markup;", "POSSIBLE_XSS", family, source, "innerHTML"),
        ]
    elif family == "adjacent-constant":
        pos = ("beforeend", "afterbegin", "beforebegin", "afterend")[i % 4]
        rows = [
            make_row(gid, 0, f"{target}.insertAdjacentHTML('{pos}', {literal});", "SAFE", family, "constant", "insertAdjacentHTML"),
            make_row(gid, 1, f"{target}.insertAdjacentHTML('{pos}', {source});", "XSS", family, source, "insertAdjacentHTML"),
            make_row(gid, 2, f"{target}.insertAdjacentHTML('{pos}', {known}({source}));", "SAFE", family, source, "insertAdjacentHTML"),
            make_row(gid, 3, f"{target}.insertAdjacentHTML('{pos}', {unknown}({source}));", "POSSIBLE_XSS", family, source, "insertAdjacentHTML"),
        ]
    elif family == "srcdoc-constant":
        rows = [
            make_row(gid, 0, f"frame.srcdoc = {literal};", "SAFE", family, "constant", "srcdoc"),
            make_row(gid, 1, f"frame.srcdoc = {source};", "XSS", family, source, "srcdoc"),
            make_row(gid, 2, f"frame.srcdoc = {known}({source});", "SAFE", family, source, "srcdoc"),
            make_row(gid, 3, f"frame.srcdoc = {unknown}({source});", "POSSIBLE_XSS", family, source, "srcdoc"),
        ]
    elif family == "jquery-html-constant":
        selector = ("#preview", ".message", "#profile", ".result")[i % 4]
        rows = [
            make_row(gid, 0, f"$('{selector}').html({literal});", "SAFE", family, "constant", "jquery.html"),
            make_row(gid, 1, f"$('{selector}').html({source});", "XSS", family, source, "jquery.html"),
            make_row(gid, 2, f"$('{selector}').html({known}({source}));", "SAFE", family, source, "jquery.html"),
            make_row(gid, 3, f"$('{selector}').html({unknown}({source}));", "POSSIBLE_XSS", family, source, "jquery.html"),
        ]
    elif family == "react-dangerous-constant":
        rows = [
            make_row(gid, 0, "return <div dangerouslySetInnerHTML={{__html: " + literal + "}} />;", "SAFE", family, "constant", "dangerouslySetInnerHTML"),
            make_row(gid, 1, "return <div dangerouslySetInnerHTML={{__html: " + source + "}} />;", "XSS", family, source, "dangerouslySetInnerHTML"),
            make_row(gid, 2, "return <div>{" + source + "}</div>;", "SAFE", family, source, "react.text"),
            make_row(gid, 3, "return <div dangerouslySetInnerHTML={{__html: " + unknown + "(" + source + ")}} />;", "POSSIBLE_XSS", family, source, "dangerouslySetInnerHTML"),
        ]
    elif family == "server-html-constant":
        route = ("/search", "/preview", "/profile", "/article")[i % 4]
        rows = [
            make_row(gid, 0, f"app.get('{route}', (_req, res) => res.send({literal}));", "SAFE", family, "constant", "http-html-response"),
            make_row(gid, 1, f"app.get('{route}', (req, res) => res.send('<div>' + {source} + '</div>'));", "XSS", family, source, "http-html-response"),
            make_row(gid, 2, f"app.get('{route}', (req, res) => res.send('<div>' + {known}({source}) + '</div>'));", "SAFE", family, source, "http-html-response"),
            make_row(gid, 3, f"app.get('{route}', (req, res) => res.send('<div>' + {unknown}({source}) + '</div>'));", "POSSIBLE_XSS", family, source, "http-html-response"),
        ]
    elif family == "known-sanitizer-alias":
        rows = [
            make_row(gid, 0, f"const clean = {known}({source});\n{target}.innerHTML = clean;", "SAFE", family, source, "innerHTML"),
            make_row(gid, 1, f"const clean = {source};\n{target}.innerHTML = clean;", "XSS", family, source, "innerHTML"),
            make_row(gid, 2, f"const clean = {known}({known}({source}));\n{target}.innerHTML = clean;", "SAFE", family, source, "innerHTML"),
            make_row(gid, 3, f"const clean = {unknown}({source});\n{target}.innerHTML = clean;", "POSSIBLE_XSS", family, source, "innerHTML"),
        ]
    elif family == "text-sink":
        rows = [
            make_row(gid, 0, f"{target}.textContent = {source};", "SAFE", family, source, "textContent"),
            make_row(gid, 1, f"{target}.innerHTML = {source};", "XSS", family, source, "innerHTML"),
            make_row(gid, 2, f"{target}.append(document.createTextNode({source}));", "SAFE", family, source, "createTextNode"),
            make_row(gid, 3, f"{target}.innerHTML = {unknown}({source});", "POSSIBLE_XSS", family, source, "innerHTML"),
        ]
    elif family == "safe-attribute":
        attr = ("title", "aria-label", "alt", "data-note")[i % 4]
        rows = [
            make_row(gid, 0, f"{target}.setAttribute('{attr}', {source});", "SAFE", family, source, attr),
            make_row(gid, 1, f"{target}.setAttribute('onclick', {source});", "XSS", family, source, "event-handler"),
            make_row(gid, 2, f"{target}.setAttribute('{attr}', String({source}));", "SAFE", family, source, attr),
            make_row(gid, 3, f"{target}.setAttribute('onclick', {unknown}({source}));", "POSSIBLE_XSS", family, source, "event-handler"),
        ]
    else:
        raise ValueError(family)
    return rows


def dedup(rows: list[dict], forbidden: set[str]) -> list[dict]:
    out, seen = [], set()
    for row in rows:
        digest = h(row["code"])
        if digest in forbidden or digest in seen:
            continue
        seen.add(digest)
        out.append(row)
    return out


def stats(rows: list[dict]) -> dict:
    return {
        "count": len(rows),
        "labels": dict(sorted(Counter(r["label"] for r in rows).items())),
        "families": dict(sorted(Counter(r["provenance"]["family"] for r in rows).items())),
        "groups": len({r["group_id"] for r in rows}),
        "unique_hashes": len({h(r["code"]) for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2032)
    p.add_argument("--groups", type=int, default=2400)
    p.add_argument("--validation-fraction", type=float, default=0.20)
    args = p.parse_args()

    combos = list(product(FAMILIES, UNTRUSTED, TARGETS, TRUSTED_LITERALS))
    rng = random.Random(args.seed)
    rng.shuffle(combos)
    if args.groups > len(combos):
        raise ValueError(f"only {len(combos)} unique groups available")

    groups = [
        build_group(i, family, source, target, literal)
        for i, (family, source, target, literal) in enumerate(combos[:args.groups])
    ]
    rng.shuffle(groups)
    cut = max(1, round(len(groups) * args.validation_fraction))
    val_groups, train_groups = groups[:cut], groups[cut:]

    forbidden = locked_hashes()
    train = dedup([r for g in train_groups for r in g], forbidden)
    train_h = {h(r["code"]) for r in train}
    val = dedup([r for g in val_groups for r in g], forbidden | train_h)

    # Separate stress views make calibration constraints explicit.
    safe_stress = [r for r in val if r["label"] == "SAFE"]
    attack_stress = [r for r in val if r["label"] == "XSS"]

    write_jsonl(DATA / "safe_hard_train_v12.jsonl", train)
    write_jsonl(DATA / "safe_hard_validation_v12.jsonl", val)
    write_jsonl(DATA / "safe_stress_v12.jsonl", safe_stress)
    write_jsonl(DATA / "attack_stress_v12.jsonl", attack_stress)

    manifest = {
        "version": "v0.12-safe-hard-negatives",
        "seed": args.seed,
        "generated_groups": args.groups,
        "validation_fraction": args.validation_fraction,
        "train": stats(train),
        "validation": stats(val),
        "safe_stress": stats(safe_stress),
        "attack_stress": stats(attack_stress),
        "policy": {
            "locked_test_overlap": 0,
            "external_test_v5_training_allowed": False,
            "hard_test_v4_training_allowed": False,
            "group_disjoint_train_validation": True,
        },
    }
    (DATA / "manifest_v12_safe.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
