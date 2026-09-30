"""Build v0.14 bridge hard-positive XSS training data.

This training-only curriculum adds unseen taint-propagation shapes between the
v0.13 train families and its family-disjoint development holdout. It never
imports locked-test content or development labels.
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
    "req.body.comment",
    "request.query.preview",
    "request.body.html",
]

TARGETS = [
    "panel", "preview", "container", "result", "output", "content",
    "modalBody", "cardBody", "messageBox", "profile",
]

FAMILIES = (
    "iife-flow",
    "getter-flow",
    "callback-flow",
    "logical-flow",
    "nullish-flow",
    "function-expression-flow",
    "server-render-arrow",
    "server-object-renderer",
    "react-helper-flow",
    "dom-method-flow",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def digest(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def forbidden_hashes() -> set[str]:
    out: set[str] = set()
    for name in (
        "test.jsonl",
        "hard_test.jsonl",
        "external_test_v5.jsonl",
        "validation_v10.jsonl",
        "safe_hard_validation_v12.jsonl",
        "hard_positive_validation_v13.jsonl",
        "realworld_validation_v08.jsonl",
    ):
        path = DATA / name
        if path.exists():
            out |= {digest(r["code"]) for r in read_jsonl(path)}
    return out


def make_row(group: str, family: str, code: str, source: str, sink: str) -> dict:
    return {
        "id": hashlib.sha256(f"{group}:{code}".encode()).hexdigest()[:20],
        "group_id": group,
        "code": code,
        "label": "XSS",
        "language": "javascript",
        "source": source,
        "sink": sink,
        "provenance": {
            "origin": "bridge-positive-v14",
            "generator": "build_v14_bridge_positives.py",
            "family": family,
            "training_allowed": True,
        },
    }


def browser_case(family: str, source: str, target: str, i: int) -> tuple[str, str]:
    if family == "iife-flow":
        return f"const html = (() => {source})();\n{target}.innerHTML = html;", "innerHTML"
    if family == "getter-flow":
        return f"const state = {{ get html() {{ return {source}; }} }};\n{target}.innerHTML = state.html;", "innerHTML"
    if family == "callback-flow":
        return f"const html = [{source}].map(value => value)[0];\n{target}.insertAdjacentHTML('beforeend', html);", "insertAdjacentHTML"
    if family == "logical-flow":
        return f"const html = {source} || '<p>empty</p>';\n{target}.innerHTML = html;", "innerHTML"
    if family == "nullish-flow":
        return f"const html = {source} ?? '<p>empty</p>';\n{target}.innerHTML = html;", "innerHTML"
    if family == "function-expression-flow":
        return f"const read = function() {{ return {source}; }};\nconst html = read();\n{target}.innerHTML = html;", "innerHTML"
    if family == "react-helper-flow":
        return "const read = () => " + source + ";\nconst html = read();\nreturn <main dangerouslySetInnerHTML={{__html: html}} />;", "dangerouslySetInnerHTML"
    if family == "dom-method-flow":
        return f"const state = new Map([['html', {source}]]);\n{target}.innerHTML = state.get('html');", "innerHTML"
    raise ValueError(family)


def server_case(family: str, source: str, i: int) -> tuple[str, str]:
    route = ("/search", "/preview", "/profile", "/article")[i % 4]
    if family == "server-render-arrow":
        return f"const render = value => '<section>' + value + '</section>';\napp.get('{route}', (req, res) => res.send(render({source})));", "http-html-response"
    if family == "server-object-renderer":
        return f"const view = {{ render(value) {{ return `<article>${{value}}</article>`; }} }};\napp.get('{route}', (req, res) => res.send(view.render({source})));", "http-html-response"
    raise ValueError(family)


def build_family(family: str, count: int, seed: int) -> list[dict]:
    rng = random.Random(f"{seed}:{family}")
    server = family.startswith("server-")
    sources = SERVER_SOURCES if server else BROWSER_SOURCES
    combos = [(source, target) for source in sources for target in TARGETS]
    rng.shuffle(combos)
    rows: list[dict] = []

    for i in range(count):
        source, target = combos[i % len(combos)]
        if server:
            code, sink = server_case(family, source, i)
        else:
            code, sink = browser_case(family, source, target, i)

        cycle = i // len(combos)
        if cycle:
            prefix = "let marker = true;\n" if cycle % 2 else "const marker = true;\n"
            code = prefix + code
        group = f"v14-{family}-{i:05d}"
        rows.append(make_row(group, family, code, source, sink))
    return rows


def stats(rows: list[dict]) -> dict:
    return {
        "count": len(rows),
        "families": dict(sorted(Counter(r["provenance"]["family"] for r in rows).items())),
        "groups": len({r["group_id"] for r in rows}),
        "unique_hashes": len({digest(r["code"]) for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2034)
    p.add_argument("--per-family", type=int, default=180)
    args = p.parse_args()

    forbidden = forbidden_hashes()
    seen: set[str] = set()
    rows: list[dict] = []

    for family in FAMILIES:
        for item in build_family(family, args.per_family, args.seed):
            h = digest(item["code"])
            if h in forbidden or h in seen:
                continue
            seen.add(h)
            rows.append(item)

    random.Random(args.seed).shuffle(rows)
    write_jsonl(DATA / "bridge_positive_train_v14.jsonl", rows)

    manifest = {
        "version": "v0.14-bridge-positive",
        "seed": args.seed,
        "train": stats(rows),
        "policy": {
            "training_only": True,
            "development_hash_overlap": 0,
            "locked_hash_overlap": 0,
            "external_test_v5_training_allowed": False,
            "hard_test_v4_training_allowed": False,
        },
    }
    (DATA / "manifest_v14_bridge.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
