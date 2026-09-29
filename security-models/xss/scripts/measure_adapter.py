"""Measure adapter footprint + inference latency for a registry entry."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from xss_specialist.adapter_registry import ROOT, default_registry, load_classifier


def dir_size(path: Path) -> int:
    total = 0
    for entry in path.rglob("*"):
        if entry.is_file():
            total += entry.stat().st_size
    return total


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} TB"


def measure(adapter_name: str, n_samples: int = 128) -> dict:
    reg = default_registry()
    spec = reg.get(adapter_name)

    classify, _ = load_classifier(adapter_name)

    # Single-snippet latency
    samples = ["node.textContent = input"] * n_samples
    start = time.perf_counter()
    classify(samples, truncation=True)
    bulk_elapsed = time.perf_counter() - start

    # Single snippet latency (more realistic)
    single_times = []
    for code in samples[:32]:
        s = time.perf_counter()
        classify(code, truncation=True)
        single_times.append(time.perf_counter() - s)
    single_avg_ms = (sum(single_times) / len(single_times)) * 1000

    footprint = {}
    if spec.kind == "full":
        resolved = (ROOT / spec.path).resolve()
        footprint["model_dir"] = str(resolved)
        footprint["total_bytes"] = dir_size(resolved)
    elif spec.kind == "peft":
        adapter_dir = (ROOT / spec.path).resolve()
        footprint["adapter_dir"] = str(adapter_dir)
        footprint["adapter_bytes"] = dir_size(adapter_dir)
        # Base is loaded by name; count cached HF snapshot bytes if present.
        from transformers import AutoConfig

        config = AutoConfig.from_pretrained(spec.base_model)
        cache_dir = Path.home() / ".cache" / "huggingface" / "hub"
        # Try to find the base in the local HF cache
        base_name_safe = spec.base_model.replace("/", "--")
        base_path = cache_dir / f"models--{base_name_safe}" / "snapshots"
        if base_path.exists():
            # take the latest snapshot
            snapshots = sorted(base_path.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            if snapshots:
                latest = snapshots[0]
                footprint["base_dir"] = str(latest)
                footprint["base_bytes"] = dir_size(latest)
        footprint["base_model_id"] = spec.base_model

    return {
        "adapter": spec.name,
        "kind": spec.kind,
        "base_model": spec.base_model,
        "footprint": {key: (human_bytes(value) if isinstance(value, int) else value) for key, value in footprint.items()}
        | (
            {key: value for key, value in footprint.items() if not isinstance(value, int)}
        ),
        "footprint_raw_bytes": {key: value for key, value in footprint.items() if isinstance(value, int)},
        "latency": {
            "single_avg_ms": round(single_avg_ms, 3),
            "bulk_avg_ms_per_snippet": round((bulk_elapsed / n_samples) * 1000, 3),
            "sample_size": n_samples,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="v0.4-baseline")
    parser.add_argument("--n-samples", type=int, default=128)
    args = parser.parse_args()
    report = measure(args.adapter, args.n_samples)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()