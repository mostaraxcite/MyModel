"""Build v0.13 hard-positive XSS curriculum.

These examples make source-to-sink flow structurally harder without using any
locked test labels or content. Training/validation are split by template family
and flow shape so the validation set is not a simple variable-name clone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

BROWSER_SOURCES = [
    "location.hash.slice(1)",
    "location.search.slice(1)",
    "new URLSearchParams(location.search).get('q')",
    "new URL(location.href).searchParams.get('html')",
    "event.data",
    "message.data",
    "window.name",
    "document.referrer",
    "localStorage.getItem('draft')",
    "sessionStorage.getItem('preview')",
    "input.value",
    "editor.getHTML()",
]

SERVER_SOURCES = [
    "req.query.q",
    "req.query.html",
    "req.params.slug",
    "req.params.id",
    "req.body.comment",
    "req.body.bio",
    "request.query.preview",
    "request.body.html",
]

TARGETS = [
    "panel", "preview", "container", "result", "output", "content",
    "modalBody", "cardBody", "messageBox", "profile", "description",
]

TRAIN_FAMILIES = (
    "dom-alias",
    "dom-double-alias",
    "dom-object-property",
    "dom-array-flow",
    "dom-template",
    "jquery-alias",
    "react-prop",
    "vue-flow",
    "server-concat",
    "server-template",
)

VALIDATION_FAMILIES = (
    "helper-return",
    "helper-parameter",
    "destructure-flow",
    "conditional-flow",
    "server-helper",
    "react-nested-prop",
)

def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def digest(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def locked_hashes() -> set[str]:
    hashes: set[str] = set()
    for name in ("test.jsonl", "hard_test.jsonl", "external_test_v5.jsonl"):
        path = DATA / name
        if path.exists():
            hashes |= {digest(r["code"]) for r in read_jsonl(path)}
    return hashes


def row(group: str, family: str, code: str, source: str, sink: str) -> dict:
    return {
        "id": hashlib.sha256(f"{group}:{code}".encode()).hexdigest()[:20],
        "group_id": group,
        "code": code,
        "label": "XSS",
        "language": "javascript",
        "source": source,
        "sink": sink,
        "provenance": {
            "origin": "hard-positive-v13",
            "generator": "build_v13_hard_positives.py",
            "family": family,
            "training_allowed": True,
        },
    }


def browser_code(family: str, src: str, target: str, i: int) -> tuple[str, str]:
    if family == "dom-alias":
        return f"const value = {src};\n{target}.innerHTML = value;", "innerHTML"
    if family == "dom-double-alias":
        return f"const first = {src};\nconst second = first;\n{target}.innerHTML = second;", "innerHTML"
    if family == "dom-object-property":
        return f"const state = {{ html: {src} }};\n{target}.innerHTML = state.html;", "innerHTML"
    if family == "dom-array-flow":
        return f"const values = [{src}];\n{target}.innerHTML = values[0];", "innerHTML"
    if family == "dom-template":
        return f"const value = {src};\n{target}.innerHTML = `<section>${{value}}</section>`;", "innerHTML"
    if family == "jquery-alias":
        sel = ("#preview", ".message", "#profile", ".result")[i % 4]
        return f"const value = {src};\n$('{sel}').html(value);", "jquery.html"
    if family == "react-prop":
        return "const html = " + src + ";\nreturn <section dangerouslySetInnerHTML={{__html: html}} />;", "dangerouslySetInnerHTML"
    if family == "vue-flow":
        return f"const state = {{ body: {src} }};\nconst vm = {{ template: '<article v-html=\"body\"></article>', data: () => state }};", "v-html"
    if family == "helper-return":
        return f"function readValue() {{ return {src}; }}\nconst html = readValue();\n{target}.innerHTML = html;", "innerHTML"
    if family == "helper-parameter":
        return f"function render(html) {{ {target}.innerHTML = html; }}\nrender({src});", "innerHTML"
    if family == "destructure-flow":
        return f"const state = {{ value: {src} }};\nconst {{ value }} = state;\n{target}.insertAdjacentHTML('beforeend', value);", "insertAdjacentHTML"
    if family == "conditional-flow":
        return f"const value = {src};\nconst html = value ? value : '<p>empty</p>';\n{target}.innerHTML = html;", "innerHTML"
    if family == "react-nested-prop":
        return "const state = { view: { html: " + src + " } };\nreturn <div dangerouslySetInnerHTML={{__html: state.view.html}} />;", "dangerouslySetInnerHTML"
    raise ValueError(family)


def server_code(family: str, src: str, i: int) -> tuple[str, str]:
    route = ("/search", "/preview", "/profile", "/article", "/comment")[i % 5]
    if family == "server-concat":
        return f"app.get('{route}', (req, res) => {{ const value = {src}; res.send('<div>' + value + '</div>'); }});", "http-html-response"
    if family == "server-template":
        return f"app.get('{route}', (req, res) => {{ const value = {src}; res.send(`<main>${{value}}</main>`); }});", "http-html-response"
    if family == "server-helper":
        return f"function page(value) {{ return '<article>' + value + '</article>'; }}\napp.get('{route}', (req, res) => res.send(page({src})));", "http-html-response"
    raise ValueError(family)


def build_family(family: str, count: int, seed: int) -> list[dict]:
    rng = random.Random(f"{seed}-{family}")
    rows: list[dict] = []
    is_server = family.startswith("server-")
    sources = SERVER_SOURCES if is_server else BROWSER_SOURCES

    combos = [(s, t) for s in sources for t in TARGETS]
    rng.shuffle(combos)
    for i in range(count):
        src, target = combos[i % len(combos)]
        if is_server:
            code, sink = server_code(family, src, i)
        else:
            code, sink = browser_code(family, src, target, i)
        # Add harmless formatting diversity without changing semantics.
        if i >= len(combos):
            n = i // len(combos)
            code = f"// flow-{n}\n" + code.replace("const ", "let " if n % 2 else "const ", 1)
        group = f"v13-{family}-{i:05d}"
        rows.append(row(group, family, code, src, sink))
    return rows


def unique(rows: list[dict], forbidden: set[str]) -> list[dict]:
    seen, out = set(), []
    for r in rows:
        h = digest(r["code"])
        if h in forbidden or h in seen:
            continue
        seen.add(h)
        out.append(r)
    return out


def stats(rows: list[dict]) -> dict:
    return {
        "count": len(rows),
        "families": dict(sorted(Counter(r["provenance"]["family"] for r in rows).items())),
        "unique_hashes": len({digest(r["code"]) for r in rows}),
        "groups": len({r["group_id"] for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2033)
    p.add_argument("--train-per-family", type=int, default=180)
    p.add_argument("--validation-per-family", type=int, default=100)
    args = p.parse_args()

    forbidden = locked_hashes()
    train_raw = []
    for family in TRAIN_FAMILIES:
        train_raw += build_family(family, args.train_per_family, args.seed)

    train = unique(train_raw, forbidden)
    train_h = {digest(r["code"]) for r in train}

    validation_raw = []
    for family in VALIDATION_FAMILIES:
        validation_raw += build_family(family, args.validation_per_family, args.seed + 1)
    validation = unique(validation_raw, forbidden | train_h)

    rng = random.Random(args.seed)
    rng.shuffle(train)
    rng.shuffle(validation)

    write_jsonl(DATA / "hard_positive_train_v13.jsonl", train)
    write_jsonl(DATA / "hard_positive_validation_v13.jsonl", validation)

    manifest = {
        "version": "v0.13-hard-positive",
        "seed": args.seed,
        "train": stats(train),
        "validation": stats(validation),
        "policy": {
            "train_validation_family_disjoint": True,
            "locked_hash_overlap": 0,
            "external_test_v5_training_allowed": False,
            "hard_test_v4_training_allowed": False,
        },
    }
    (DATA / "manifest_v13_positive.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
