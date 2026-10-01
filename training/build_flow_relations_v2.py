"""Build a larger native JavaScript flow-relation corpus from pinned repositories.

Annotation policy is deliberately local and conservative:
- CONNECTED: direct value copy/member read into a sink variable.
- DISCONNECTED: a sink is overwritten by a literal while a nearby earlier variable
  exists in the same block; local value dependency from that source variable is absent.
- UNKNOWN: sink receives an opaque call/new return involving a source expression.

This is relation supervision only. It does not label vulnerabilities and does not
use locked external XSS data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

from tree_sitter import Language, Parser
import tree_sitter_javascript

from xss_specialist.flow_relations import audit_relation_splits, MAX_EXCERPT

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "flow-relations-v2" / "source_manifest.json"
OUT_ROOT = ROOT / "data" / "flow-relations-v2"
SOURCE_ROOT = OUT_ROOT / "sources"

DIRECT_TYPES = {"identifier", "member_expression", "subscript_expression"}
LITERAL_TYPES = {"string", "number", "true", "false", "null", "undefined", "regex"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(repository: str, commit: str, path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "MyModel-flow-corpus-v2"})
    with urllib.request.urlopen(req, timeout=45) as response:
        data = response.read()
    if not data:
        raise RuntimeError(f"empty source download: {repository}@{commit}:{path}")
    return data


def save_snapshot(repository: str, path: str, data: bytes) -> Path:
    dest = (SOURCE_ROOT / repository / path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest


def text(data: bytes, node) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8")


def field(node, name: str):
    return node.child_by_field_name(name)


def statement_for(node):
    cur = node
    while cur is not None:
        if cur.type in {
            "lexical_declaration",
            "variable_declaration",
            "expression_statement",
            "return_statement",
        }:
            return cur
        cur = cur.parent
    return node


def container_for(stmt):
    cur = stmt.parent
    while cur is not None:
        if cur.type in {"statement_block", "program"}:
            return cur
        cur = cur.parent
    return stmt.parent or stmt


def literal_like(node) -> bool:
    if node is None:
        return False
    if node.type in LITERAL_TYPES:
        return True
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.named_children)
    return False


def first_unknown_source(node):
    if node is None:
        return None
    if node.type not in {"call_expression", "new_expression"}:
        return None
    args = field(node, "arguments")
    if args is not None:
        for arg in args.named_children:
            if not literal_like(arg):
                return arg
    fn = field(node, "function") or field(node, "constructor")
    if fn is not None and fn.type == "member_expression":
        obj = field(fn, "object")
        if obj is not None:
            return obj
    return None


def extract_assignments(data: bytes):
    parser = Parser(Language(tree_sitter_javascript.language()))
    tree = parser.parse(data)
    if tree.root_node.has_error:
        # Modern JS files can contain syntax unsupported by this parser build.
        # Skip only the file with a visible reason; never guess spans.
        return [], "parse_error"

    rows = []

    def walk(node):
        lhs = rhs = None
        if node.type == "variable_declarator":
            lhs, rhs = field(node, "name"), field(node, "value")
        elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
            lhs, rhs = field(node, "left"), field(node, "right")

        if lhs is not None and rhs is not None and lhs.type in {
            "identifier", "member_expression", "subscript_expression"
        }:
            stmt = statement_for(node)
            container = container_for(stmt)
            rows.append({
                "lhs": lhs,
                "rhs": rhs,
                "stmt": stmt,
                "container_key": (container.start_byte, container.end_byte, container.type),
            })

        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    rows.sort(key=lambda r: (r["stmt"].start_byte, r["lhs"].start_byte))
    return rows, None


def relation_row(*, repository, framework, commit, source_file, source_path,
                 source_sha, label, source_node, sink_node, excerpt_start,
                 excerpt_end, data, rationale):
    source_expr = text(data, source_node)
    sink_expr = text(data, sink_node)
    line = sink_node.start_point.row + 1
    ident = (
        f"{repository}:{source_file}:{label}:"
        f"{source_node.start_byte}:{sink_node.start_byte}"
    )
    return {
        "id": ident,
        "task": "FLOW_RELATION",
        "source_expression": source_expr,
        "sink_expression": sink_expr,
        "flow_excerpt": data[excerpt_start:excerpt_end].decode("utf-8"),
        "label": label,
        "query_location": {
            "line": line,
            "source_span": {
                "start_byte": source_node.start_byte,
                "end_byte": source_node.end_byte,
            },
            "sink_span": {
                "start_byte": sink_node.start_byte,
                "end_byte": sink_node.end_byte,
            },
            "statement_span": {
                "start_byte": excerpt_start,
                "end_byte": excerpt_end,
            },
        },
        "provenance": {
            "code_origin": "repository",
            "repository": repository,
            "commit": commit,
            "framework": framework,
            "template": "not-applicable",
            "generator": "not-applicable",
            "license": "upstream license snapshot included",
            "source_file": source_file,
            "source_sha256": source_sha,
            "source_snapshot": str(source_path.resolve().relative_to(ROOT.resolve())),
            "excerpt_span": {
                "start_byte": excerpt_start,
                "end_byte": excerpt_end,
            },
        },
        "verification": {
            "status": "REVIEWED",
            "reviewer": "deterministic local-value annotation policy v2; no independent expert claim",
            "rationale": rationale,
            "reference": (
                f"https://github.com/{repository}/blob/{commit}/{source_file}#L{line}"
            ),
        },
    }


def extract_file(entry: dict, source_file: str, data: bytes, source_path: Path):
    assignments, error = extract_assignments(data)
    if error:
        return [], {"file": source_file, "status": error}

    source_sha = sha256(data)
    out = []
    by_container = {}

    for item in assignments:
        lhs, rhs, stmt = item["lhs"], item["rhs"], item["stmt"]
        key = item["container_key"]
        prior = by_container.setdefault(key, [])

        if rhs.type in DIRECT_TYPES and stmt.end_byte - stmt.start_byte <= MAX_EXCERPT:
            out.append(relation_row(
                repository=entry["repository"],
                framework=entry["framework"],
                commit=entry["commit"],
                source_file=source_file,
                source_path=source_path,
                source_sha=source_sha,
                label="CONNECTED",
                source_node=rhs,
                sink_node=lhs,
                excerpt_start=stmt.start_byte,
                excerpt_end=stmt.end_byte,
                data=data,
                rationale=(
                    "The selected sink receives the exact identifier/member value on the "
                    "right-hand side. This is local value dependency only."
                ),
            ))

        opaque_source = first_unknown_source(rhs)
        if opaque_source is not None and stmt.end_byte - stmt.start_byte <= MAX_EXCERPT:
            out.append(relation_row(
                repository=entry["repository"],
                framework=entry["framework"],
                commit=entry["commit"],
                source_file=source_file,
                source_path=source_path,
                source_sha=source_sha,
                label="UNKNOWN",
                source_node=opaque_source,
                sink_node=lhs,
                excerpt_start=stmt.start_byte,
                excerpt_end=stmt.end_byte,
                data=data,
                rationale=(
                    "The selected source participates in an opaque call/new expression whose "
                    "return-value dependency is not summarized by this bounded task."
                ),
            ))

        if literal_like(rhs):
            # Use up to two nearby prior written variables in the same block as
            # explicit negative value-flow queries. The sink's new value is a literal.
            for previous in reversed(prior[-4:]):
                prev_lhs = previous["lhs"]
                if text(data, prev_lhs) == text(data, lhs):
                    continue
                excerpt_start = min(previous["stmt"].start_byte, stmt.start_byte)
                excerpt_end = max(previous["stmt"].end_byte, stmt.end_byte)
                if excerpt_end - excerpt_start > 1200:
                    continue
                out.append(relation_row(
                    repository=entry["repository"],
                    framework=entry["framework"],
                    commit=entry["commit"],
                    source_file=source_file,
                    source_path=source_path,
                    source_sha=source_sha,
                    label="DISCONNECTED",
                    source_node=prev_lhs,
                    sink_node=lhs,
                    excerpt_start=excerpt_start,
                    excerpt_end=excerpt_end,
                    data=data,
                    rationale=(
                        "At the selected write, the sink is overwritten by a literal. The "
                        "nearby earlier source variable is not a data operand of that value; "
                        "control dependencies are outside this local value-flow label."
                    ),
                ))
                if sum(
                    1 for r in out
                    if r["label"] == "DISCONNECTED"
                    and r["query_location"]["sink_span"]["start_byte"] == lhs.start_byte
                ) >= 2:
                    break

        prior.append(item)

    # Exact relation dedupe inside a file.
    seen = set()
    deduped = []
    for row in out:
        key = (
            row["label"],
            row["query_location"]["source_span"]["start_byte"],
            row["query_location"]["sink_span"]["start_byte"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped, {"file": source_file, "status": "ok", "candidates": len(deduped)}


def relation_identity(row: dict) -> tuple[str, str]:
    content = (
        f"[source_expression]\\n{row['source_expression']}\\n"
        f"[sink_expression]\\n{row['sink_expression']}\\n"
        f"[flow_excerpt]\\n{row['flow_excerpt']}"
    )
    return row["id"], hashlib.sha256(content.encode()).hexdigest()


def dedupe_rows(rows: list[dict]) -> list[dict]:
    seen_ids = set()
    seen_content = set()
    out = []
    for row in rows:
        ident, digest = relation_identity(row)
        if ident in seen_ids or digest in seen_content:
            continue
        seen_ids.add(ident)
        seen_content.add(digest)
        out.append(row)
    return out


def balanced_select(rows: list[dict], per_class: int) -> list[dict]:
    selected = []
    for label in ("CONNECTED", "DISCONNECTED", "UNKNOWN"):
        group = [r for r in rows if r["label"] == label]
        # deterministic, diverse across repositories/files due source ordering
        selected.extend(group[:per_class])
    selected.sort(key=lambda r: r["id"])
    return selected


def count_labels(rows):
    return {
        label: sum(1 for row in rows if row["label"] == label)
        for label in ("CONNECTED", "DISCONNECTED", "UNKNOWN")
    }


def build_split(entries: list[dict], per_class: int):
    all_rows = []
    file_report = []
    for entry in entries:
        # Preserve upstream license next to snapshots.
        license_data = download(
            entry["repository"], entry["commit"], entry["license_path"]
        )
        save_snapshot(
            entry["repository"],
            f"_LICENSE/{Path(entry['license_path']).name}",
            license_data,
        )

        repo_rows = []
        for source_file in entry["files"]:
            data = download(entry["repository"], entry["commit"], source_file)
            source_path = save_snapshot(entry["repository"], source_file, data)
            rows, report = extract_file(entry, source_file, data, source_path)
            repo_rows.extend(rows)
            file_report.append({
                "repository": entry["repository"],
                **report,
            })

        # Cap each repository so one codebase cannot dominate a split.
        all_rows.extend(balanced_select(repo_rows, per_class))

    # Remove exact duplicate reviewed relation inputs across repositories/files
    # before balancing. The split audit treats content duplicates as leakage.
    all_rows = dedupe_rows(all_rows)

    # Then balance the aggregate split by its smallest class.
    counts = count_labels(all_rows)
    usable = min(counts.values())
    balanced = balanced_select(all_rows, usable)
    return balanced, file_report, counts


def write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, default=MANIFEST)
    p.add_argument("--output-dir", type=Path, default=OUT_ROOT)
    p.add_argument("--train-per-class-per-repo", type=int, default=60)
    p.add_argument("--dev-per-class-per-repo", type=int, default=40)
    p.add_argument("--min-train-per-class", type=int, default=120)
    p.add_argument("--min-dev-per-class", type=int, default=45)
    args = p.parse_args()

    manifest = json.loads(args.manifest.read_text())
    if manifest.get("schema") != "xss-flow-source-manifest-v2":
        raise SystemExit("unexpected source manifest schema")

    global SOURCE_ROOT
    SOURCE_ROOT = args.output_dir / "sources"

    train, train_files, train_raw = build_split(
        manifest["train"], args.train_per_class_per_repo
    )
    dev, dev_files, dev_raw = build_split(
        manifest["dev"], args.dev_per_class_per_repo
    )

    train_counts = count_labels(train)
    dev_counts = count_labels(dev)
    if min(train_counts.values()) < args.min_train_per_class:
        raise SystemExit(f"insufficient train flow corpus: {train_counts}")
    if min(dev_counts.values()) < args.min_dev_per_class:
        raise SystemExit(f"insufficient dev flow corpus: {dev_counts}")

    write_jsonl(args.output_dir / "train.jsonl", train)
    write_jsonl(args.output_dir / "dev.jsonl", dev)

    audit = audit_relation_splits({"train": train, "dev": dev})
    report = {
        "schema": "xss-flow-relations-v2-build",
        "source_manifest": str(args.manifest.relative_to(ROOT)),
        "train_rows": len(train),
        "dev_rows": len(dev),
        "train_counts": train_counts,
        "dev_counts": dev_counts,
        "prebalance_train_counts": train_raw,
        "prebalance_dev_counts": dev_raw,
        "train_repositories": [e["repository"] for e in manifest["train"]],
        "dev_repositories": [e["repository"] for e in manifest["dev"]],
        "locked_external_used": False,
        "annotation_scope": "bounded local JavaScript value relations",
        "independent_expert_review": False,
        "audit": audit,
        "files": {
            "train": train_files,
            "dev": dev_files,
        },
    }
    (args.output_dir / "build_report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
