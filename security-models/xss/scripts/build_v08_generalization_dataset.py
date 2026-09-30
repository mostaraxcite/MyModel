"""Build the v0.8 generalization-focused XSS training corpus.

Goals:
- preserve locked hard/external evaluation sets;
- remove exact classifier-input overlap with locked sets;
- reduce domination by legacy synthetic rows;
- add contrastive, group-disjoint examples covering DOM, framework, and
  server-side reflected-XSS shapes;
- keep provenance for every generated row.

This script NEVER reads labels from external_test_v5 into training. It reads
only hashes from locked evaluation files to enforce exclusion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

LABELS = ("SAFE", "POSSIBLE_XSS", "XSS")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def locked_hashes() -> set[str]:
    hashes: set[str] = set()
    for name in ("hard_test.jsonl", "external_test_v5.jsonl", "test.jsonl"):
        path = DATA / name
        if not path.exists():
            continue
        for row in read_jsonl(path):
            hashes.add(code_hash(row["code"]))
    return hashes


def dedup(rows: list[dict], forbidden: set[str]) -> tuple[list[dict], dict]:
    seen: dict[str, str] = {}
    out: list[dict] = []
    removed_overlap = 0
    removed_duplicate = 0
    conflicts = 0
    for row in rows:
        h = code_hash(row["code"])
        if h in forbidden:
            removed_overlap += 1
            continue
        if h in seen:
            if seen[h] != row["label"]:
                conflicts += 1
            else:
                removed_duplicate += 1
            continue
        seen[h] = row["label"]
        out.append(row)
    return out, {
        "removed_locked_overlap": removed_overlap,
        "removed_duplicates": removed_duplicate,
        "label_conflicts_removed": conflicts,
    }


def cap_legacy_synthetic(rows: list[dict], seed: int, per_label: int = 2200) -> list[dict]:
    rng = random.Random(seed)
    legacy: dict[str, list[dict]] = defaultdict(list)
    keep: list[dict] = []
    for row in rows:
        origin = row.get("provenance", {}).get("origin", "")
        generator = row.get("provenance", {}).get("generator", "")
        if origin == "synthetic" or generator == "xss-v0.1":
            legacy[row["label"]].append(row)
        else:
            keep.append(row)
    for label in LABELS:
        pool = legacy[label]
        rng.shuffle(pool)
        keep.extend(pool[:per_label])
    return keep


SOURCES = [
    "req.query.q",
    "req.query.name",
    "req.params.slug",
    "req.body.comment",
    "request.body.html",
    "new URLSearchParams(location.search).get('q')",
    "location.hash.slice(1)",
    "location.search.slice(1)",
    "event.data",
    "message.data",
    "formData.get('bio')",
    "route.query.preview",
    "route.params.id",
    "input.value",
]

UNKNOWN_SANITIZERS = [
    "cleanHtml",
    "projectSanitize",
    "legacyScrubber",
    "security.clean",
]


def row(group: str, idx: int, code: str, label: str, sink: str, source: str, family: str) -> dict:
    return {
        "id": hashlib.sha256(f"{group}:{idx}:{label}:{code}".encode()).hexdigest()[:20],
        "group_id": group,
        "code": code,
        "label": label,
        "language": "javascript",
        "sink": sink,
        "source": source,
        "provenance": {
            "origin": "generalization-contrast-v08",
            "generator": "build_v08_generalization_dataset.py",
            "family": family,
            "training_only": True,
        },
    }


def generate_contrast_groups(seed: int, groups: int = 1200) -> list[list[dict]]:
    rng = random.Random(seed)
    out: list[list[dict]] = []

    dom_templates = [
        ("panel.innerHTML = {src};", "panel.textContent = {src};", "panel.innerHTML = DOMPurify.sanitize({src});", "innerHTML"),
        ("target.insertAdjacentHTML('beforeend', {src});", "target.append(document.createTextNode({src}));", "target.insertAdjacentHTML('beforeend', DOMPurify.sanitize({src}));", "insertAdjacentHTML"),
        ("frame.srcdoc = {src};", "frame.setAttribute('title', {src});", "frame.srcdoc = DOMPurify.sanitize({src});", "srcdoc"),
        ("button.setAttribute('onclick', {src});", "button.setAttribute('aria-label', {src});", "button.setAttribute('onclick', encodeURIComponent({src}));", "event-handler"),
    ]

    for i in range(groups):
        src = rng.choice(SOURCES)
        family = rng.choice(("dom", "jquery", "react", "vue", "angular", "server"))
        gid = f"v08-{family}-{i:05d}"
        rows: list[dict] = []

        if family == "dom":
            bad, safe_text, safe_sanitized, sink = rng.choice(dom_templates)
            rows.append(row(gid, 0, bad.format(src=src), "XSS", sink, src, family))
            rows.append(row(gid, 1, safe_text.format(src=src), "SAFE", "text-safe", src, family))
            rows.append(row(gid, 2, safe_sanitized.format(src=src), "SAFE", sink, src, family))
            unknown = rng.choice(UNKNOWN_SANITIZERS)
            rows.append(row(gid, 3, bad.format(src=f"{unknown}({src})"), "POSSIBLE_XSS", sink, src, family))

        elif family == "jquery":
            rows.append(row(gid, 0, f"$('#result').html({src});", "XSS", "jquery.html", src, family))
            rows.append(row(gid, 1, f"$('#result').text({src});", "SAFE", "jquery.text", src, family))
            rows.append(row(gid, 2, f"$('#result').html(DOMPurify.sanitize({src}));", "SAFE", "jquery.html", src, family))
            rows.append(row(gid, 3, f"$('#result').html(projectSanitize({src}));", "POSSIBLE_XSS", "jquery.html", src, family))

        elif family == "react":
            rows.append(row(gid, 0, f"return <div dangerouslySetInnerHTML={{{{__html: {src}}}}} />;", "XSS", "dangerouslySetInnerHTML", src, family))
            rows.append(row(gid, 1, f"return <div>{{{src}}}</div>;", "SAFE", "react.text", src, family))
            rows.append(row(gid, 2, f"return <div dangerouslySetInnerHTML={{{{__html: DOMPurify.sanitize({src})}}}}} />;", "SAFE", "dangerouslySetInnerHTML", src, family))
            rows.append(row(gid, 3, f"return <div dangerouslySetInnerHTML={{{{__html: cleanHtml({src})}}}}} />;", "POSSIBLE_XSS", "dangerouslySetInnerHTML", src, family))

        elif family == "vue":
            rows.append(row(gid, 0, f"const view = {{ template: '<div v-html=\"payload\"></div>', data: () => ({{payload: {src}}}) }};", "XSS", "v-html", src, family))
            rows.append(row(gid, 1, f"const view = {{ template: '<div>{{{{ payload }}}}</div>', data: () => ({{payload: {src}}}) }};", "SAFE", "vue.interpolation", src, family))
            rows.append(row(gid, 2, f"const payload = DOMPurify.sanitize({src}); el.innerHTML = payload;", "SAFE", "innerHTML", src, family))
            rows.append(row(gid, 3, f"const payload = projectSanitize({src}); el.innerHTML = payload;", "POSSIBLE_XSS", "innerHTML", src, family))

        elif family == "angular":
            rows.append(row(gid, 0, f"this.html = this.sanitizer.bypassSecurityTrustHtml({src});", "XSS", "bypassSecurityTrustHtml", src, family))
            rows.append(row(gid, 1, f"this.text = {src}; // rendered with [textContent]", "SAFE", "angular.text", src, family))
            rows.append(row(gid, 2, f"this.html = DOMPurify.sanitize({src});", "SAFE", "sanitized-html", src, family))
            rows.append(row(gid, 3, f"this.html = projectSanitize({src});", "POSSIBLE_XSS", "unknown-sanitizer", src, family))

        else:  # server-side reflected HTML response
            rows.append(row(gid, 0, f"app.get('/search', (req, res) => res.send('<h1>' + {src} + '</h1>'));", "XSS", "http-html-response", src, family))
            rows.append(row(gid, 1, f"app.get('/search', (req, res) => res.type('text/plain').send(String({src})));", "SAFE", "http-text-response", src, family))
            rows.append(row(gid, 2, f"app.get('/search', (req, res) => res.send('<h1>' + escapeHtml({src}) + '</h1>'));", "SAFE", "http-html-response", src, family))
            rows.append(row(gid, 3, f"app.get('/search', (req, res) => res.send('<h1>' + cleanHtml({src}) + '</h1>'));", "POSSIBLE_XSS", "http-html-response", src, family))

        out.append(rows)
    return out


def split_groups(groups: list[list[dict]], seed: int, validation_fraction: float = 0.15) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    groups = list(groups)
    rng.shuffle(groups)
    n_val = max(1, int(len(groups) * validation_fraction))
    val_groups = groups[:n_val]
    train_groups = groups[n_val:]
    return [r for g in train_groups for r in g], [r for g in val_groups for r in g]


def stats(rows: list[dict]) -> dict:
    origins = Counter(r.get("provenance", {}).get("origin", "unknown") for r in rows)
    return {
        "count": len(rows),
        "labels": dict(Counter(r["label"] for r in rows)),
        "origins": dict(origins),
        "unique_hashes": len({code_hash(r["code"]) for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2028)
    p.add_argument("--groups", type=int, default=1200)
    p.add_argument("--legacy-per-label", type=int, default=2200)
    args = p.parse_args()

    forbidden = locked_hashes()
    base_train = read_jsonl(DATA / "train.jsonl")
    base_val = read_jsonl(DATA / "validation.jsonl")

    base_train, audit_train = dedup(base_train, forbidden)
    base_val, audit_val = dedup(base_val, forbidden)

    base_train = cap_legacy_synthetic(base_train, args.seed, args.legacy_per_label)
    base_val = cap_legacy_synthetic(base_val, args.seed + 1, max(300, args.legacy_per_label // 4))

    groups = generate_contrast_groups(args.seed, args.groups)
    gen_train, gen_val = split_groups(groups, args.seed + 2)

    train, audit_train2 = dedup(base_train + gen_train, forbidden)
    validation, audit_val2 = dedup(base_val + gen_val, forbidden | {code_hash(r["code"]) for r in train})

    rng = random.Random(args.seed)
    rng.shuffle(train)
    rng.shuffle(validation)

    write_jsonl(DATA / "train_v08.jsonl", train)
    write_jsonl(DATA / "validation_v08.jsonl", validation)

    manifest = {
        "version": "v0.8-generalization",
        "seed": args.seed,
        "policy": {
            "external_test_v5_training_allowed": False,
            "hard_test_v4_training_allowed": False,
            "standard_test_training_allowed": False,
            "group_disjoint_generated_train_validation": True,
            "exact_hash_overlap_with_locked_sets": 0,
        },
        "inputs": {
            "legacy_per_label_cap": args.legacy_per_label,
            "generated_contrast_groups": args.groups,
        },
        "train": stats(train),
        "validation": stats(validation),
        "audit": {
            "base_train": audit_train,
            "base_validation": audit_val,
            "final_train": audit_train2,
            "final_validation": audit_val2,
        },
    }
    (DATA / "manifest_v08.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
