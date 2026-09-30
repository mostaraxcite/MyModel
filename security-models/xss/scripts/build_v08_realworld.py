"""Build the v0.8 real-world XSS curriculum from independent upstream projects.

Training sources are intentionally repository-disjoint from external_test_v5:
- google/firing-range (Apache-2.0): intentionally vulnerable XSS fixtures.
- cure53/DOMPurify (Apache-2.0): official sanitizer demos used as SAFE flows.
- apostrophecms/sanitize-html (MIT): sanitizer regression tests used as SAFE flows.

The locked CodeQL/Semgrep external benchmark is NEVER imported into training.
Exact snippet hashes are checked against external_test_v5 before any output is
written. Groups are split by upstream fixture/test case, not by individual row,
so near-identical rows from the same upstream case cannot straddle train/val.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


LABELS = ("SAFE", "POSSIBLE_XSS", "XSS")
TRAINING_REPOSITORIES = {
    "google/firing-range",
    "cure53/DOMPurify",
    "apostrophecms/sanitize-html",
}
LOCKED_EXTERNAL_REPOSITORIES = {"github/codeql", "semgrep/semgrep-rules"}


def git_sha(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def stable_id(repository: str, group: str, label: str, code: str) -> str:
    return hashlib.sha256(f"{repository}\0{group}\0{label}\0{code}".encode()).hexdigest()[:20]


def normalize(code: str) -> str:
    lines = []
    for raw in code.replace("\r\n", "\n").splitlines():
        line = raw.rstrip()
        # Avoid label leakage from upstream comments/test descriptions.
        if re.search(r"\b(?:xss|vulnerab|exploit|attack|fix for|safe)\b", line, re.I):
            if line.lstrip().startswith(("//", "/*", "*", "<!--")):
                continue
        lines.append(line)
    text = "\n".join(lines).strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def make_row(
    *,
    repository: str,
    commit: str,
    license_name: str,
    group: str,
    path: str,
    label: str,
    code: str,
    note: str,
) -> dict:
    code = normalize(code)
    digest = sha256_text(code)
    return {
        "id": stable_id(repository, group, label, code),
        "group_id": f"{repository}:{group}",
        "project": repository,
        "code": code,
        "label": label,
        "language": "javascript",
        "sink": "upstream-fixture",
        "source": "upstream-fixture",
        "provenance": {
            "origin": "realworld-v08",
            "repository": repository,
            "commit": commit,
            "path": path,
            "license": license_name,
            "note": note,
            "content_sha256": digest,
            "training_allowed": True,
        },
    }


def firing_range_rows(root: Path) -> list[dict]:
    repository = "google/firing-range"
    commit = git_sha(root)
    rows: list[dict] = []

    sink_dir = root / "src/tests/dom/data/sinks"
    sink_paths = [
        sink_dir / "innerHtml.tmpl",
        sink_dir / "documentWrite.tmpl",
        sink_dir / "eval.tmpl",
        sink_dir / "js_html_sanitize_eval.tmpl",
    ]
    source_paths: list[Path] = []
    for rel in (
        "src/tests/dom/data/sources/document",
        "src/tests/dom/data/sources/localStorage",
        "src/tests/dom/data/sources/sessionStorage",
        "src/tests/dom/data/sources/window",
    ):
        source_paths.extend(sorted((root / rel).glob("*.tmpl")))

    # Firing Range's DOM suite is itself composed from independent source and
    # sink templates. Recompose those exact upstream fixtures so each sample
    # contains both attacker-controlled source and executable sink.
    for source_path in source_paths:
        source = source_path.read_text(encoding="utf-8", errors="replace")
        if "payload" not in source and "trigger(" not in source:
            continue
        for sink_path in sink_paths:
            sink = sink_path.read_text(encoding="utf-8", errors="replace")
            code = source + "\n\n" + sink
            group = source_path.relative_to(root).as_posix()
            rows.append(make_row(
                repository=repository,
                commit=commit,
                license_name="Apache-2.0",
                group=group,
                path=f"{group} + {sink_path.relative_to(root).as_posix()}",
                label="XSS",
                code=code,
                note="Official Firing Range DOM source/sink fixture composition.",
            ))

    # Some postMessage fixtures are already complete source-to-sink programs.
    post_dir = root / "src/tests/dom/data/sources/postMessage"
    for path in sorted(post_dir.glob("*.tmpl")):
        code = path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"innerHTML|document\.write|\beval\s*\(", code):
            continue
        rel = path.relative_to(root).as_posix()
        rows.append(make_row(
            repository=repository,
            commit=commit,
            license_name="Apache-2.0",
            group=rel,
            path=rel,
            label="XSS",
            code=code,
            note="Official complete postMessage XSS fixture.",
        ))

    propagation = root / "src/tests/dom/data/dompropagation.tmpl"
    if propagation.exists():
        rel = propagation.relative_to(root).as_posix()
        rows.append(make_row(
            repository=repository,
            commit=commit,
            license_name="Apache-2.0",
            group=rel,
            path=rel,
            label="XSS",
            code=propagation.read_text(encoding="utf-8", errors="replace"),
            note="Official DOM propagation fixture.",
        ))
    return rows


def _script_windows(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    for index, line in enumerate(lines):
        if "DOMPurify.sanitize" not in line:
            continue
        sink_index = None
        for j in range(index, min(len(lines), index + 9)):
            if re.search(r"innerHTML\s*(?:\+?=)|document\.write\s*\(", lines[j]):
                sink_index = j
                break
        if sink_index is None:
            continue
        start = max(0, index - 3)
        end = min(len(lines), sink_index + 2)
        code = "\n".join(lines[start:end])
        if "DOMPurify.sanitize" in code:
            out.append(code)
    return out


def dompurify_rows(root: Path) -> list[dict]:
    repository = "cure53/DOMPurify"
    commit = git_sha(root)
    rows: list[dict] = []
    for path in sorted((root / "demos").glob("*.html")):
        for ordinal, code in enumerate(_script_windows(path)):
            rel = path.relative_to(root).as_posix()
            rows.append(make_row(
                repository=repository,
                commit=commit,
                license_name="Apache-2.0",
                group=rel,
                path=rel,
                label="SAFE",
                code=code,
                note=f"Official DOMPurify demo sanitizer-to-sink flow #{ordinal + 1}.",
            ))
    return rows


def _extract_sanitize_calls(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    rows: list[tuple[int, str]] = []
    dangerous = re.compile(
        r"javascript:|<script|onerror|onload|onclick|<iframe|srcdoc|<svg|<math|&#\d+;",
        re.I,
    )
    for i, line in enumerate(lines):
        if "sanitizeHtml(" not in line:
            continue
        block = [line]
        balance = line.count("(") - line.count(")")
        j = i + 1
        while balance > 0 and j < len(lines) and len(block) < 18:
            block.append(lines[j])
            balance += lines[j].count("(") - lines[j].count(")")
            j += 1
        code = "\n".join(block)
        if dangerous.search(code):
            rows.append((i + 1, code))
    return rows


def sanitize_html_rows(root: Path) -> list[dict]:
    repository = "apostrophecms/sanitize-html"
    commit = git_sha(root)
    path = root / "test/test.js"
    text = path.read_text(encoding="utf-8", errors="replace")
    rows: list[dict] = []
    for line_no, call in _extract_sanitize_calls(text):
        # Wrap the actual upstream sanitizer invocation as an executable-style
        # assignment and intentionally omit the assertion's expected output.
        code = "const clean = " + call.strip().rstrip(";") + ";"
        rel = path.relative_to(root).as_posix()
        rows.append(make_row(
            repository=repository,
            commit=commit,
            license_name="MIT",
            group=f"{rel}:test-{line_no}",
            path=f"{rel}#L{line_no}",
            label="SAFE",
            code=code,
            note="Upstream sanitize-html security regression invocation.",
        ))
    return rows


def deduplicate(rows: list[dict]) -> list[dict]:
    by_hash: dict[str, dict] = {}
    for row in rows:
        digest = row["provenance"]["content_sha256"]
        previous = by_hash.get(digest)
        if previous and previous["label"] != row["label"]:
            raise ValueError(
                f"contradictory labels for real-world content hash {digest}: "
                f"{previous['label']} vs {row['label']}"
            )
        by_hash.setdefault(digest, row)
    return list(by_hash.values())


def load_external_guard(path: Path) -> tuple[set[str], set[str]]:
    hashes: set[str] = set()
    repos: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        provenance = row.get("provenance", {})
        hashes.add(provenance.get("content_sha256") or sha256_text(row["code"]))
        repos.add(row.get("project") or provenance.get("repository") or "")
    return hashes, repos


def split_by_group(rows: list[dict], seed: int, validation_fraction: float) -> tuple[list[dict], list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["group_id"]].append(row)

    train_groups: set[str] = set()
    val_groups: set[str] = set()
    by_label: dict[str, list[str]] = defaultdict(list)
    for group, items in grouped.items():
        labels = {item["label"] for item in items}
        if len(labels) != 1:
            raise ValueError(f"group {group} mixes labels: {sorted(labels)}")
        by_label[next(iter(labels))].append(group)

    for label, groups in sorted(by_label.items()):
        groups = sorted(groups)
        rng = random.Random(f"{seed}-{label}")
        rng.shuffle(groups)
        n_val = max(1, round(len(groups) * validation_fraction)) if len(groups) > 1 else 0
        val_groups.update(groups[:n_val])
        train_groups.update(groups[n_val:])

    train = [row for row in rows if row["group_id"] in train_groups]
    val = [row for row in rows if row["group_id"] in val_groups]
    return train, val


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def stats(rows: list[dict]) -> dict:
    return {
        "count": len(rows),
        "labels": dict(sorted(Counter(row["label"] for row in rows).items())),
        "projects": dict(sorted(Counter(row["project"] for row in rows).items())),
        "groups": len({row["group_id"] for row in rows}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firing-range-root", type=Path, required=True)
    parser.add_argument("--dompurify-root", type=Path, required=True)
    parser.add_argument("--sanitize-html-root", type=Path, required=True)
    parser.add_argument(
        "--external-test",
        type=Path,
        default=Path("security-models/xss/data/external_test_v5.jsonl"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("security-models/xss/data"),
    )
    parser.add_argument("--seed", type=int, default=2028)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    args = parser.parse_args()

    external_hashes, external_repos = load_external_guard(args.external_test)
    if TRAINING_REPOSITORIES & external_repos:
        raise ValueError(
            "real-world training repositories overlap the locked external benchmark: "
            f"{sorted(TRAINING_REPOSITORIES & external_repos)}"
        )
    if not LOCKED_EXTERNAL_REPOSITORIES.issubset(external_repos):
        raise ValueError(
            "external_test_v5 provenance changed unexpectedly; refusing to build training data"
        )

    rows = deduplicate(
        firing_range_rows(args.firing_range_root)
        + dompurify_rows(args.dompurify_root)
        + sanitize_html_rows(args.sanitize_html_root)
    )
    overlap = [row for row in rows if row["provenance"]["content_sha256"] in external_hashes]
    if overlap:
        raise ValueError(f"{len(overlap)} real-world rows overlap external_test_v5 by exact hash")

    train, validation = split_by_group(rows, args.seed, args.validation_fraction)
    train_hashes = {row["provenance"]["content_sha256"] for row in train}
    val_hashes = {row["provenance"]["content_sha256"] for row in validation}
    if train_hashes & val_hashes:
        raise AssertionError("real-world train/validation content overlap")
    if {row["group_id"] for row in train} & {row["group_id"] for row in validation}:
        raise AssertionError("real-world train/validation group overlap")

    train_path = args.output_dir / "realworld_train_v08.jsonl"
    val_path = args.output_dir / "realworld_validation_v08.jsonl"
    write_jsonl(train_path, train)
    write_jsonl(val_path, validation)

    manifest = {
        "version": "v0.8",
        "seed": args.seed,
        "training_repositories": sorted(TRAINING_REPOSITORIES),
        "locked_external_repositories": sorted(external_repos),
        "repository_disjoint_from_external": True,
        "content_hash_disjoint_from_external": True,
        "group_disjoint_train_validation": True,
        "training_allowed": True,
        "external_test_v5_used_for_training": False,
        "all": stats(rows),
        "train": stats(train),
        "validation": stats(validation),
        "commits": {
            "google/firing-range": git_sha(args.firing_range_root),
            "cure53/DOMPurify": git_sha(args.dompurify_root),
            "apostrophecms/sanitize-html": git_sha(args.sanitize_html_root),
        },
    }
    manifest_path = args.output_dir / "realworld_v08_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
