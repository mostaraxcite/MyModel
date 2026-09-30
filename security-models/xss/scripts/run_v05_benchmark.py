"""Run the v0.5 benchmark suite: Hard Test v4 + external_test_v5 on both adapters."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
EVAL = ROOT / "evaluation"
EXTERNAL = ROOT / "data"


def verify_external_provenance() -> dict:
    """Confirm external_test_v5 content is fully disjoint from training data."""
    if not (EXTERNAL / "external_test_v5.jsonl").exists():
        return {"checked": False, "reason": "external_test_v5.jsonl missing"}
    external_rows = [
        json.loads(line)
        for line in (EXTERNAL / "external_test_v5.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    external_hashes = [row["provenance"]["content_sha256"] for row in external_rows]
    external_codes = set(external_hashes)
    if len(external_hashes) != len(external_codes):
        return {
            "checked": True,
            "passed": False,
            "reason": "duplicate_content_hashes_in_external_test",
            "rows": len(external_hashes),
            "unique": len(external_codes),
        }
    for name in ("train.jsonl", "validation.jsonl", "test.jsonl", "hard_test.jsonl"):
        path = EXTERNAL / name
        if not path.exists():
            continue
        codes = {
            hashlib.sha256(json.loads(line)["code"].encode()).hexdigest()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        }
        if not external_codes.isdisjoint(codes):
            return {"checked": True, "passed": False, "overlap": name}
    return {
        "checked": True,
        "passed": True,
        "external_count": len(external_rows),
        "external_partition": "external_test_v5_locked",
        "training_allowed": False,
    }


def run(cmd: list[str]) -> dict:
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def run_adapter_evaluation(adapter: str, evaluator: str, output: Path) -> tuple[dict, dict]:
    metrics_path = EVAL / output
    cmd = [
        sys.executable,
        str(EVAL / evaluator),
        "--adapter", adapter,
        "--output", str(metrics_path),
    ]
    run_log = run(cmd)
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    else:
        metrics = {"error": "metrics not produced", "run": run_log}
    return metrics, run_log


def main() -> None:
    EVAL.mkdir(exist_ok=True)
    summary: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    summary["provenance"] = verify_external_provenance()

    targets = [
        ("v0.4-baseline", "evaluate.py", "v05_hard_v04.json"),
        ("xss-v0.5", "evaluate.py", "v05_hard_v05.json"),
        ("v0.4-baseline", "evaluate_external_v5.py", "v05_external_v04.json"),
        ("xss-v0.5", "evaluate_external_v5.py", "v05_external_v05.json"),
    ]
    evaluations: dict[str, dict] = {}
    for adapter, evaluator, output in targets:
        metrics, run_log = run_adapter_evaluation(adapter, evaluator, Path(output))
        evaluations[f"{adapter}__{evaluator.replace('.py', '')}"] = {
            "metrics": metrics,
            "run": run_log,
        }

    summary["evaluations"] = evaluations

    comparison = {}
    hard_v04 = evaluations.get("v0.4-baseline__evaluate", {}).get("metrics", {})
    hard_v05 = evaluations.get("xss-v0.5__evaluate", {}).get("metrics", {})
    if hard_v04 and hard_v05:
        v04_f1 = hard_v04.get("classification_report", {}).get("macro avg", {}).get("f1-score")
        v05_f1 = hard_v05.get("classification_report", {}).get("macro avg", {}).get("f1-score")
        comparison["hard_test_v4"] = {
            "v0.4_baseline_macro_f1": v04_f1,
            "xss_v0_5_macro_f1": v05_f1,
            "delta": (v05_f1 - v04_f1) if (v04_f1 is not None and v05_f1 is not None) else None,
            "promotion_recommended": (
                v05_f1 is not None
                and v04_f1 is not None
                and v05_f1 >= 0.90
                and v05_f1 >= v04_f1 - 0.005
            ),
        }
    ext_v04 = evaluations.get("v0.4-baseline__evaluate_external_v5", {}).get("metrics", {})
    ext_v05 = evaluations.get("xss-v0.5__evaluate_external_v5", {}).get("metrics", {})
    if ext_v04 and ext_v05:
        comparison["external_test_v5"] = {
            "v0.4_baseline": {
                "coverage": ext_v04.get("coverage"),
                "decided_macro_f1": ext_v04.get("decided_macro_f1"),
                "xss_fpr_all": ext_v04.get("xss_false_positive_rate_all"),
                "xss_fnr_all": ext_v04.get("xss_false_negative_rate_all"),
            },
            "xss_v0_5": {
                "coverage": ext_v05.get("coverage"),
                "decided_macro_f1": ext_v05.get("decided_macro_f1"),
                "xss_fpr_all": ext_v05.get("xss_false_positive_rate_all"),
                "xss_fnr_all": ext_v05.get("xss_false_negative_rate_all"),
            },
        }
    summary["comparison"] = comparison
    summary["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    out = EVAL / "v05_benchmark_summary.json"
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(comparison, indent=2))
    print(f"\nFull summary: {out}")


if __name__ == "__main__":
    main()
