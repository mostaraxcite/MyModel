"""One-shot External v6 architecture gate.

Selection is fixed by benchmarks/external_v6/PROTOCOL.md.  This evaluator never
prints case-level content.  After the first scored run, only aggregate metrics
may be used for architecture decisions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

from xss_specialist.field_advisor import StructuralFieldAdvisor

COMMITS = {
    "htmx": "fa978b24e75fb03c137bf2cdae4fef0e711cf8a1",
    "mustache": "972fd2b27a036888acfcb60d6119317744fac7ee",
    "koa": "824c1cf8de9a91a2941973b25dc8a3d3029b9e4f",
    "react-router": "a6090382ed467b5a2d46c8de1a13b331f14959f8",
    "turbo": "75350a19212ef0d29a0e6db75e0bfdeb96b10cd7",
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


def _files(root: Path, allowed_roots: tuple[str, ...] | None = None):
    rows = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS:
            continue
        rel = p.relative_to(root).as_posix()
        low = rel.lower()
        if any(x in low for x in ("/node_modules/", "/vendor/", "/dist/", ".min.js")):
            continue
        if allowed_roots and not any(rel == x or rel.startswith(x + "/") for x in allowed_roots):
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


def _case(repo: str, rel: str, lineno: int, line: str, task: str, expression: str, expected: str) -> Case:
    return Case(
        repo=repo,
        commit=COMMITS[repo],
        path=rel,
        line=lineno,
        excerpt_sha256=hashlib.sha256(line.encode()).hexdigest(),
        task=task,
        expression=expression.strip(),
        expected=expected,
    )


def select_html_sinks(repo: str, root: Path) -> list[Case]:
    out = []
    for rel, p in _files(root, ("src",)):
        lowrel = rel.lower()
        if any(x in lowrel for x in ("/test", "/tests", "/spec", "__test")):
            continue
        for lineno, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            m = re.search(r"(?P<lhs>[A-Za-z_$][\w$\.\[\]'\"-]*\.(?:innerHTML|outerHTML))\s*=\s*(?P<rhs>.+?);?\s*$", line)
            if m and not _literal(m.group("rhs")):
                out.append(_case(repo, rel, lineno, line, "sink", f"{m.group('lhs')} = VALUE", "DANGEROUS_HTML"))
            for cm in re.finditer(r"(?P<call>[A-Za-z_$][\w$\.\[\]'\"-]*\.insertAdjacentHTML)\s*\((?P<args>[^;]+)\)", line):
                args = cm.group("args").split(",", 1)
                if len(args) == 2 and not _literal(args[1]):
                    out.append(_case(repo, rel, lineno, line, "sink", f"{cm.group('call')}({args[0].strip()}, VALUE)", "DANGEROUS_HTML"))
            if len(out) >= 2:
                return out[:2]
    return out[:2]


def select_mustache(root: Path) -> list[Case]:
    out = []
    for rel, p in _files(root):
        lowrel = rel.lower()
        if not (
            "mustache" in lowrel
            or lowrel.startswith("spec/")
            or lowrel.startswith("test/")
            or lowrel.startswith("tests/")
        ):
            continue
        for lineno, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            if "function escapeHtml" in line:
                continue
            for m in re.finditer(r"\bescapeHtml\s*\(\s*(?P<arg>[^,)]+)", line):
                arg = m.group("arg").strip()
                if _literal(arg):
                    continue
                out.append(_case("mustache", rel, lineno, line, "defense", "escapeHtml(VALUE)", "CONTEXTUAL_ENCODING"))
                if len(out) >= 2:
                    return out[:2]
    return out[:2]


def _koa_source_expected(expr: str) -> str:
    low = expr.lower()
    if re.search(r"\b(?:req|request)\.(?:body|query|params|headers|cookies)\b", low):
        return "SERVER"
    if re.search(r"\bctx\.(?:request|query|params)\b", low):
        return "SERVER"
    return "OTHER"


def select_koa(root: Path) -> list[Case]:
    out = []
    for rel, p in _files(root, ("lib", "examples", "test", "tests")):
        for lineno, raw in enumerate(p.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            m = re.search(r"\b(?:ctx|context)\.body\s*=\s*(?P<rhs>.+?);?\s*$", line)
            if m and not _literal(m.group("rhs")):
                expr = m.group("rhs").strip().rstrip(";")
                out.append(_case("koa", rel, lineno, line, "source", expr, _koa_source_expected(expr)))
            m = re.search(r"\b(?:ctx|context)\.redirect\s*\(\s*(?P<arg>[^,)]+)", line)
            if m and not _literal(m.group("arg")):
                expr = m.group("arg").strip()
                out.append(_case("koa", rel, lineno, line, "source", expr, _koa_source_expected(expr)))
            if len(out) >= 2:
                return out[:2]
    return out[:2]


def _router_expected(expr: str) -> str:
    low = expr.lower()
    if re.search(r"(?:window\.)?location\.(?:hash|search|pathname|href)", low):
        return "BROWSER"
    if any(x in low for x in ("searchparams", "useparams", "usesearchparams", "params.", "loaderdata", "routedata")):
        return "FRAMEWORK"
    return "OTHER"


def select_router(root: Path) -> list[Case]:
    out = []
    source_token = re.compile(
        r"(?:window\.)?location\.(?:hash|search|pathname|href)|"
        r"useSearchParams\s*\(|useParams\s*\(|searchParams\.get\s*\(|\bparams\.[A-Za-z_$]"
    )
    use_token = re.compile(
        r"navigate\s*\(|redirect\s*\(|<Link\b|\bto\s*=|\bhref\s*=|"
        r"window\.location|location\.(?:assign|replace)|\breturn\b"
    )
    for rel, p in _files(root, ("packages", "examples", "integration", "test", "tests")):
        lines = p.read_text(errors="replace").splitlines()
        for i, raw in enumerate(lines):
            line = raw.strip()
            if not source_token.search(line):
                continue
            assign = re.search(r"(?:const|let|var)\s+(?P<lhs>[^=]+?)\s*=\s*(?P<rhs>.+?);?\s*$", line)
            if not assign:
                continue
            rhs = assign.group("rhs").strip().rstrip(";")
            if not source_token.search(rhs):
                continue
            ids = re.findall(r"[A-Za-z_$][\w$]*", assign.group("lhs"))
            if not ids:
                continue
            var = ids[-1]
            window = "\n".join(lines[i:min(len(lines), i + 13)])
            if var not in window or not use_token.search(window):
                continue
            out.append(_case("react-router", rel, i + 1, line, "source", rhs, _router_expected(rhs)))
            if len(out) >= 2:
                return out[:2]
    return out[:2]


def select_all(roots: dict[str, Path]) -> list[Case]:
    for repo, expected in COMMITS.items():
        actual = _head(roots[repo])
        if actual != expected:
            raise SystemExit(f"integrity failure: {repo} commit mismatch")
    groups = {
        "htmx": select_html_sinks("htmx", roots["htmx"]),
        "mustache": select_mustache(roots["mustache"]),
        "koa": select_koa(roots["koa"]),
        "react-router": select_router(roots["react-router"]),
        "turbo": select_html_sinks("turbo", roots["turbo"]),
    }
    counts = {k: len(v) for k, v in groups.items()}
    if counts != {k: 2 for k in COMMITS}:
        print(json.dumps({"selection_counts": counts, "selection_integrity": False}, indent=2))
        raise SystemExit("external v6 selection integrity failed")
    cases = [case for repo in COMMITS for case in groups[repo]]
    if len({(c.repo, c.path, c.line, c.excerpt_sha256) for c in cases}) != 10:
        raise SystemExit("external v6 duplicate selection")
    return cases


def main() -> None:
    p = argparse.ArgumentParser()
    for repo in COMMITS:
        p.add_argument("--" + repo + "-root", type=Path, required=True)
    p.add_argument("--semantic-dir", type=Path)
    p.add_argument("--flow-dir", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--select-only", action="store_true")
    a = p.parse_args()

    roots = {
        "htmx": a.htmx_root,
        "mustache": a.mustache_root,
        "koa": a.koa_root,
        "react-router": a.react_router_root,
        "turbo": a.turbo_root,
    }
    cases = select_all(roots)
    selection_summary = {
        "selection_counts": {repo: sum(c.repo == repo for c in cases) for repo in COMMITS},
        "selection_integrity": True,
        "case_count": len(cases),
        "protocol": "benchmarks/external_v6/PROTOCOL.md",
    }
    if a.select_only:
        print(json.dumps(selection_summary, indent=2))
        return

    if not a.semantic_dir or not a.flow_dir or not a.output:
        raise SystemExit("scoring requires --semantic-dir, --flow-dir, and --output")

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

    system_correct = sum(r["system_correct"] for r in rows)
    model_correct = sum(r["model_advice_correct"] for r in rows)
    system_accuracy = system_correct / len(rows)
    model_accuracy = model_correct / len(rows)
    family_system_accuracy = {k: v[0] / v[1] for k, v in family_system.items()}
    family_model_accuracy = {k: v[0] / v[1] for k, v in family_model.items()}

    # Frozen before first scored run. Do not tune these thresholds from v6 rows.
    passed = bool(
        selection_summary["selection_integrity"]
        and authority_ok
        and system_accuracy >= 0.80
        and model_accuracy >= 0.60
        and min(family_system_accuracy.values()) >= 0.50
    )

    report = {
        "schema": "xss-external-v6-one-shot",
        **selection_summary,
        "system_primary_accuracy": system_accuracy,
        "model_advice_primary_accuracy": model_accuracy,
        "family_system_accuracy": family_system_accuracy,
        "family_model_advice_accuracy": family_model_accuracy,
        "authority_boundary_ok": authority_ok,
        "research_gate_passed": passed,
        "promotion_allowed": False,
        "external_v6_used": True,
        "locked_hard_used": False,
        "row_level_failures_quarantined": True,
        "cases": rows,
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")

    # Aggregate only: protocol forbids row-level failure inspection after score.
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
        "row_level_failures_quarantined": True,
    }, indent=2))
    if not passed:
        raise SystemExit("external v6 one-shot architecture gate failed")


if __name__ == "__main__":
    main()
