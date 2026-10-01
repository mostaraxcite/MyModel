"""Fresh sealed External v7 generalization gate.

Protocol: benchmarks/external_v7/PROTOCOL.md
The first scored run prints aggregate metrics only. Row-level failures are
quarantined in the artifact and must never be used to tune this candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from xss_specialist.field_advisor import StructuralFieldAdvisor

COMMITS = {
    "alpine": "da60871ea404e23e46938c9e6137f05258614c63",
    "express": "7ef98448f8b38099ab1ded55e458538ad47a51e7",
    "vue-router": "610644a63281a0415b8769f7830c3d80fbb55f49",
    "lit": "01dbc6673cdc211543932afd0ca04e223e567366",
    "sanitize-html": "6ac6b8ea4898c2ba7f843d8cdd5f7d036d760a0e",
}

EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


@dataclass(frozen=True)
class Case:
    repo: str
    commit: str
    path: str
    line: int
    excerpt_sha256: str
    task: str
    expression: str
    expected: str


def _head(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def _files(root: Path):
    rows = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS:
            continue
        rel = p.relative_to(root).as_posix()
        low = "/" + rel.lower()
        if any(x in low for x in (
            "/node_modules/", "/vendor/", "/dist/", "/build/", "/coverage/",
            ".min.js", "/fixtures/generated/", "/generated/",
        )):
            continue
        rows.append((rel, p))
    return sorted(rows, key=lambda x: x[0])


def _literal(expr: str) -> bool:
    s = expr.strip().rstrip(";").strip()
    if not s:
        return True
    if re.fullmatch(r"(?:true|false|null|undefined|-?\d+(?:\.\d+)?)", s, re.I):
        return True
    if len(s) >= 2 and s[0] == s[-1] and s[0] in {"'", '"'}:
        return True
    if len(s) >= 2 and s[0] == s[-1] == "`" and "${" not in s:
        return True
    return False


def _case(repo: str, rel: str, line: int, excerpt: str,
          task: str, expression: str, expected: str) -> Case:
    return Case(
        repo=repo,
        commit=COMMITS[repo],
        path=rel,
        line=line,
        excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        task=task,
        expression=expression.strip(),
        expected=expected,
    )


def select_alpine(root: Path) -> list[Case]:
    out = []
    for rel, p in _files(root):
        for i, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            m = re.search(r"\b(?P<api>innerHTML|outerHTML)\s*=(?!=)\s*(?P<rhs>.+?);?\s*$", line)
            if m and not _literal(m.group("rhs")):
                out.append(_case("alpine", rel, i, line, "sink",
                                 f"element.{m.group('api')} = VALUE", "DANGEROUS_HTML"))
            if "insertAdjacentHTML" in line:
                m = re.search(r"insertAdjacentHTML\s*\((?P<args>.*)\)", line)
                if m:
                    parts = m.group("args").split(",", 1)
                    if len(parts) == 2 and not _literal(parts[1]):
                        out.append(_case(
                            "alpine", rel, i, line, "sink",
                            f"element.insertAdjacentHTML({parts[0].strip()}, VALUE)",
                            "DANGEROUS_HTML",
                        ))
            if len(out) >= 2:
                return out[:2]
    return out[:2]


def select_express(root: Path) -> list[Case]:
    out = []
    token = re.compile(
        r"\b(?:req|request)\.(?:query|body|params|headers|cookies)"
        r"(?:\.[A-Za-z_$][\w$]*)?"
    )
    for rel, p in _files(root):
        for i, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            for m in token.finditer(line):
                out.append(_case("express", rel, i, line, "source", m.group(0), "SERVER"))
                if len(out) >= 2:
                    return out[:2]
    return out[:2]


def select_vue_router(root: Path) -> list[Case]:
    out = []
    patterns = (
        re.compile(r"\broute\.(?:params|query)\.[A-Za-z_$][\w$]*"),
        re.compile(r"\brouter\.currentRoute\.value\.(?:params|query)\.[A-Za-z_$][\w$]*"),
        re.compile(r"\b(?:useRoute|useRouter)\s*\(\s*\)"),
    )
    for rel, p in _files(root):
        for i, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            for pattern in patterns:
                m = pattern.search(line)
                if m:
                    out.append(_case(
                        "vue-router", rel, i, line, "source", m.group(0), "FRAMEWORK"
                    ))
                    break
            if len(out) >= 2:
                return out[:2]
    return out[:2]


def select_lit(root: Path) -> list[Case]:
    dangerous = []
    safe = []
    for rel, p in _files(root):
        for i, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            m = re.search(r"\b(?P<api>innerHTML|outerHTML)\s*=(?!=)\s*(?P<rhs>.+?);?\s*$", line)
            if m and not _literal(m.group("rhs")):
                dangerous.append(_case(
                    "lit", rel, i, line, "sink",
                    f"element.{m.group('api')} = VALUE", "DANGEROUS_HTML",
                ))
            m = re.search(r"\bunsafeHTML\s*\(\s*(?P<arg>[^,)]+)", line)
            if m and not _literal(m.group("arg")):
                dangerous.append(_case(
                    "lit", rel, i, line, "sink", "unsafeHTML(VALUE)", "DANGEROUS_HTML"
                ))
            m = re.search(r"\btextContent\s*=(?!=)\s*(?P<rhs>.+?);?\s*$", line)
            if m and not _literal(m.group("rhs")):
                safe.append(_case(
                    "lit", rel, i, line, "sink", "element.textContent = VALUE", "SAFE_OUTPUT"
                ))
            if len(dangerous) >= 2:
                return dangerous[:2]
    return (dangerous + safe)[:2]


def select_sanitize_html(root: Path) -> list[Case]:
    out = []
    call = re.compile(
        r"\b(?:sanitizeHtml|sanitize)\s*\(\s*(?P<arg>[A-Za-z_$][\w$\.\[\]'\"]*)"
    )
    for rel, p in _files(root):
        for i, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            if re.search(r"function\s+(?:sanitizeHtml|sanitize)\b", line):
                continue
            for m in call.finditer(line):
                arg = m.group("arg")
                if _literal(arg):
                    continue
                out.append(_case(
                    "sanitize-html", rel, i, line, "defense",
                    "sanitizeHtml(VALUE)", "SANITIZATION",
                ))
                if len(out) >= 2:
                    return out[:2]
    return out[:2]


def select_all(roots: dict[str, Path]) -> list[Case]:
    for repo, sha in COMMITS.items():
        actual = _head(roots[repo])
        if actual != sha:
            raise SystemExit(f"integrity failure: {repo} commit mismatch")

    groups = {
        "alpine": select_alpine(roots["alpine"]),
        "express": select_express(roots["express"]),
        "vue-router": select_vue_router(roots["vue-router"]),
        "lit": select_lit(roots["lit"]),
        "sanitize-html": select_sanitize_html(roots["sanitize-html"]),
    }
    counts = {k: len(v) for k, v in groups.items()}
    integrity = all(1 <= counts[k] <= 2 for k in COMMITS) and sum(counts.values()) >= 8
    if not integrity:
        print(json.dumps({"selection_counts": counts, "selection_integrity": False}, indent=2))
        raise SystemExit("external v7 selection integrity failed")

    cases = [c for repo in COMMITS for c in groups[repo]]
    identities = {(c.repo, c.path, c.line, c.excerpt_sha256) for c in cases}
    if len(identities) != len(cases):
        raise SystemExit("external v7 duplicate selection")
    return cases


def main():
    p = argparse.ArgumentParser()
    for repo in COMMITS:
        p.add_argument("--" + repo + "-root", type=Path, required=True)
    p.add_argument("--semantic-dir", type=Path)
    p.add_argument("--flow-dir", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--select-only", action="store_true")
    a = p.parse_args()

    roots = {
        "alpine": a.alpine_root,
        "express": a.express_root,
        "vue-router": a.vue_router_root,
        "lit": a.lit_root,
        "sanitize-html": a.sanitize_html_root,
    }
    cases = select_all(roots)
    selection_counts = {repo: sum(c.repo == repo for c in cases) for repo in COMMITS}
    selection_summary = {
        "case_count": len(cases),
        "selection_counts": selection_counts,
        "selection_integrity": True,
        "protocol": "benchmarks/external_v7/PROTOCOL.md",
    }
    if a.select_only:
        print(json.dumps(selection_summary, indent=2))
        return

    if not a.semantic_dir or not a.flow_dir or not a.output:
        raise SystemExit("scoring requires model dirs and output")

    advisor = StructuralFieldAdvisor(a.semantic_dir, a.flow_dir)
    rows = []
    family_system = {repo: [0, 0] for repo in COMMITS}
    family_model = {repo: [0, 0] for repo in COMMITS}
    authority_ok = True

    for case in cases:
        result = advisor.semantic_field(case.task, case.expression)
        system_correct = result["label"] == case.expected
        model_correct = result["model_advice"]["label"] == case.expected
        family_system[case.repo][0] += int(system_correct)
        family_system[case.repo][1] += 1
        family_model[case.repo][0] += int(model_correct)
        family_model[case.repo][1] += 1
        authority_ok = authority_ok and result.get("advisory_only") is True and result.get("confirmed") is False
        rows.append({
            **asdict(case),
            "system_label": result["label"],
            "model_advice_label": result["model_advice"]["label"],
            "system_correct": system_correct,
            "model_advice_correct": model_correct,
            "authority": result["authority"],
        })

    n = len(rows)
    system_accuracy = sum(r["system_correct"] for r in rows) / n
    model_accuracy = sum(r["model_advice_correct"] for r in rows) / n
    family_system_accuracy = {k: v[0] / v[1] for k, v in family_system.items()}
    family_model_accuracy = {k: v[0] / v[1] for k, v in family_model.items()}

    passed = bool(
        selection_summary["selection_integrity"]
        and authority_ok
        and system_accuracy >= 0.85
        and model_accuracy >= 0.70
        and min(family_system_accuracy.values()) >= 0.50
    )

    report = {
        "schema": "xss-external-v7-sealed",
        **selection_summary,
        "semantic_run_id": "36920030570",
        "semantic_artifact": "xss-source-v4e-lr25e5-e12",
        "flow_run_id": "36867388302",
        "flow_artifact": "xss-flow-v2-candidate-f0-lr3e5-e8",
        "system_primary_accuracy": system_accuracy,
        "model_advice_primary_accuracy": model_accuracy,
        "family_system_accuracy": family_system_accuracy,
        "family_model_advice_accuracy": family_model_accuracy,
        "authority_boundary_ok": authority_ok,
        "research_gate_passed": passed,
        "promotion_allowed": False,
        "external_v6_reused": False,
        "row_level_failures_quarantined": True,
        "cases": rows,
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps({
        "schema": report["schema"],
        "case_count": report["case_count"],
        "selection_counts": report["selection_counts"],
        "selection_integrity": report["selection_integrity"],
        "system_primary_accuracy": report["system_primary_accuracy"],
        "model_advice_primary_accuracy": report["model_advice_primary_accuracy"],
        "family_system_accuracy": report["family_system_accuracy"],
        "family_model_advice_accuracy": report["family_model_advice_accuracy"],
        "authority_boundary_ok": report["authority_boundary_ok"],
        "research_gate_passed": report["research_gate_passed"],
        "promotion_allowed": False,
        "external_v6_reused": False,
        "row_level_failures_quarantined": True,
    }, indent=2))
    if not passed:
        raise SystemExit("external v7 sealed architecture gate failed")


if __name__ == "__main__":
    main()
