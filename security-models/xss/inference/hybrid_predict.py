"""Run the encoder+LoRA adapter and route uncertain cases to the oracle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.adapter_registry import default_registry
from xss_specialist.router_factory import build_router


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code")
    parser.add_argument(
        "--adapter",
        default=None,
        help="Adapter name from the registry. Defaults to the active adapter.",
    )
    parser.add_argument("--direct-threshold", type=float, default=0.90)
    parser.add_argument("--xss-threshold", type=float, default=0.85)
    parser.add_argument("--list", action="store_true", help="List adapters and exit.")
    args = parser.parse_args()

    if args.list:
        reg = default_registry()
        print(json.dumps(
            {"active": reg.active, "adapters": [spec.to_dict() for spec in reg.list_adapters()]},
            indent=2,
        ))
        return

    router, spec = build_router(
        args.adapter,
        direct_threshold=args.direct_threshold,
        xss_threshold=args.xss_threshold,
    )
    result = router.predict(args.code)
    print(json.dumps({
        "adapter": spec.name,
        "adapter_kind": spec.kind,
        "base_model": spec.base_model,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "route": result.route,
        "requires_oracle": result.requires_oracle,\n        "confirmation_status": "BROWSER_REQUIRED" if result.requires_oracle else "TRIAGE_ONLY",
        "escalation_reason": result.escalation_reason,
        "specialist_output": result.specialist_output,
    }, indent=2))


if __name__ == "__main__":
    main()