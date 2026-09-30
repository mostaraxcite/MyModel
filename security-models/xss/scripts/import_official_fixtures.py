"""Import labelled XSS snippets from official CodeQL and Semgrep test fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".vue", ".ejs", ".mustache", ".pug"}
CODEQL_DIRS = (
    "javascript/ql/src/Security/CWE-079/examples",
    "javascript/ql/test/query-tests/Security/CWE-079/DomBasedXss",
    "javascript/ql/test/query-tests/Security/CWE-079/ReflectedXss",
    "javascript/ql/test/query-tests/Security/CWE-079/XssThroughDom",
)
SEMGREP_DIRS = (
    "javascript/browser/security",
    "javascript/express/security/audit/xss",
    "javascript/vue/security/audit/xss",
)


def git_sha(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def stable_id(repository: str, relative_path: str, line: int, label: str, code: str) -> str:
    value = f"{repository}\0{relative_path}\0{line}\0{label}\0{code}".encode()
    return hashlib.sha256(value).hexdigest()[:20]


def snippet(lines: list[str], index: int, before: int = 5, after: int = 2) -> str:
    start, end = max(0, index - before), min(len(lines), index + after + 1)
    return "\n".join(lines[start:end]).strip()


def record(repository: str, sha: str, license_name: str, relative: str, line: int,
           code: str, label: str, annotation: str) -> dict:
    url = f"https://github.com/{repository}/blob/{sha}/{relative.replace('\\', '/')}#L{line}"
    return {
        "id": stable_id(repository, relative, line, label, code),
        "group_id": f"{repository}:{relative}",
        "project": repository,
        "code": code,
        "label": label,
        "language": "javascript",
        "sink": "fixture-labelled",
        "source": "fixture-labelled",
        "provenance": {
            "origin": "official-fixture",
            "repository": repository,
            "commit": sha,
            "path": relative.replace("\\", "/"),
            "line": line,
            "source_url": url,
            "license": license_name,
            "annotation": annotation,
            "partition": "external_test_v5_locked",
            "content_sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
    }


def codeql_records(root: Path) -> list[dict]:
    sha, rows = git_sha(root), []
    for directory in CODEQL_DIRS:
        for path in sorted((root / directory).rglob("*")):
            if path.suffix.lower() not in EXTENSIONS or not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            relative = path.relative_to(root).as_posix()
            for index, line in enumerate(lines):
                if "$ Alert" in line or re.search(r"\bBAD\s*:", line):
                    label = "XSS"
                elif re.search(r"\b(?:OK|GOOD)\s*(?:-|:)", line):
                    label = "SAFE"
                else:
                    continue
                code = snippet(lines, index)
                rows.append(record("github/codeql", sha, "MIT", relative, index + 1, code, label, line.strip()))
    return rows


def semgrep_records(root: Path) -> list[dict]:
    sha, rows = git_sha(root), []
    annotation = re.compile(r"(?:ruleid|ok)\s*:\s*([\w.-]+)")
    for directory in SEMGREP_DIRS:
        for path in sorted((root / directory).rglob("*")):
            if path.suffix.lower() not in EXTENSIONS or not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            relative = path.relative_to(root).as_posix()
            for index, line in enumerate(lines):
                match = annotation.search(line)
                if not match:
                    continue
                rule = match.group(1).lower()
                if "xss" not in rule and rule not in {"direct-response-write", "avoid-v-html"}:
                    continue
                target = index + 1
                while target < len(lines) and not lines[target].strip():
                    target += 1
                if target >= len(lines):
                    continue
                label = "SAFE" if re.search(r"\bok\s*:", line) else "XSS"
                code = snippet(lines, target)
                rows.append(record("semgrep/semgrep-rules", sha, "Semgrep Rules License v1.0",
                                   relative, target + 1, code, label, line.strip()))
    return rows


def deduplicate_by_content(rows: list[dict]) -> tuple[list[dict], list[dict], int]:
    """Return unique snippet inputs and quarantine contradictory labels.

    The classifier sees only the snippet text, so two records with identical code
    are not independent examples. If identical code has different labels, the
    benchmark is ill-posed for this input contract and both records are quarantined.
    """
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["provenance"]["content_sha256"], []).append(row)

    clean: list[dict] = []
    conflicts: list[dict] = []
    duplicate_rows_removed = 0
    for items in groups.values():
        labels = {row["label"] for row in items}
        if len(labels) > 1:
            conflicts.extend(items)
            continue
        clean.append(items[0])
        duplicate_rows_removed += len(items) - 1
    return clean, conflicts, duplicate_rows_removed


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def main() -> None:
    here = Path(__file__).resolve()
    workspace = here.parents[4]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codeql-root", type=Path, default=workspace / "external" / "codeql")
    parser.add_argument("--semgrep-root", type=Path, default=workspace / "external" / "semgrep-rules")
    parser.add_argument("--output", type=Path, default=here.parents[1] / "data" / "external_test_v5.jsonl")
    args = parser.parse_args()

    raw_rows = codeql_records(args.codeql_root) + semgrep_records(args.semgrep_root)
    rows, conflicts, duplicate_rows_removed = deduplicate_by_content(raw_rows)
    write_jsonl(args.output, rows)
    conflict_path = args.output.with_name("external_test_v5_conflicts.jsonl")
    write_jsonl(conflict_path, conflicts)
    manifest = {
        "version": "v0.5",
        "partition": "external_test_v5_locked",
        "count": len(rows),
        "labels": dict(Counter(row["label"] for row in rows)),
        "projects": dict(Counter(row["project"] for row in rows)),
        "source_group_disjoint_unit": "repository + fixture path",
        "evaluation_dedup_unit": "provenance.content_sha256",
        "duplicate_rows_removed": duplicate_rows_removed,
        "contradictory_rows_quarantined": len(conflicts),
        "conflict_file": conflict_path.name,
        "training_allowed": False,
    }
    manifest_path = args.output.with_name("external_test_v5_manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
