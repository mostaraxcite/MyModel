"""Initialise the adapter registry with v0.4 baseline + xss-v0.5 stub."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.adapter_registry import (
    ROOT,
    AdapterSpec,
    Registry,
    write_registry,
)


def build_seed_registry() -> Registry:
    return Registry(
        registry_path=ROOT / "security-models" / "xss" / "adapters" / "REGISTRY.json",
        adapters={
            "v0.4-baseline": AdapterSpec(
                name="v0.4-baseline",
                kind="full",
                base_model="google/bert_uncased_L-4_H-256_A-4",
                path="security-models/xss/model",
                description=(
                    "v0.4 promotion gate. bert-tiny full fine-tune, "
                    "Hard Test v4 macro F1 = 0.9092."
                ),
                promoted=True,
                metrics={
                    "hard_test_v4_macro_f1": 0.9091944844453206,
                    "hard_test_v4_count": 465,
                },
            ),
            "xss-v0.5": AdapterSpec(
                name="xss-v0.5",
                kind="peft",
                base_model="nreimers/MiniLM-L6-H384-uncased",
                path="security-models/xss/adapters/xss-v05",
                description=(
                    "Rejected v0.5 candidate. MiniLM-L6 + LoRA classifier; "
                    "v0.4 remains active after Hard Test v4 regression."
                ),
                promoted=False,
                metrics={
                    "hard_test_v4_macro_f1": 0.8359201671136308,
                    "v0_4_baseline_macro_f1": 0.9091944844453206,
                    "macro_f1_delta": -0.07327431733168976,
                    "external_test_v5_pre_dedup_decided_macro_f1": 0.4697115205657919,
                    "external_test_v5_current_metrics": "rerun_required_after_content_dedup",
                    "promotion_recommended": False,
                },
            ),
        },
        active="v0.4-baseline",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Overwrite existing registry.")
    args = parser.parse_args()

    target = ROOT / "security-models" / "xss" / "adapters" / "REGISTRY.json"
    if target.exists() and not args.force:
        print(json.dumps({"status": "exists", "path": str(target)}))
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    registry = build_seed_registry()
    write_registry(registry)
    print(json.dumps({"status": "written", "path": str(target), "active": registry.active}, indent=2))


if __name__ == "__main__":
    main()
