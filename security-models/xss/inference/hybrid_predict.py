"""Run classifier triage and mark cases that require browser confirmation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.adapter_registry import ROOT, default_registry
from xss_specialist.router_factory import build_router


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code", nargs="?", default="")
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
        adapters = []
        for spec in reg.list_adapters():
            raw = Path(spec.path)
            resolved = raw if raw.is_absolute() else (ROOT / raw).resolve()
            adapters.append({**spec.to_dict(), "artifact_available": resolved.exists()})
        print(json.dumps({"active": reg.active, "adapters": adapters}, indent=2))
        return

    if not args.code:
        parser.error("code is required unless --list is used")

    router, spec = build_router(
        args.adapter,
        direct_threshold=args.direct_threshold,
        xss_threshold=args.xss_threshold,
    )
    result = router.predict(args.code)
    payload = {
        "adapter": spec.name,
        "adapter_kind": spec.kind,
        "base_model": spec.base_model,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "route": result.route,
        "requires_oracle": result.requires_oracle,
        "confirmation_status": (
            "BROWSER_REQUIRED" if result.requires_oracle else "TRIAGE_ONLY"
        ),
        "escalation_reason": result.escalation_reason,
        "specialist_output": result.specialist_output,
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
