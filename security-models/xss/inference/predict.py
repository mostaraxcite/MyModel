"""Classify one HTML/JavaScript snippet using the versioned adapter registry."""
from __future__ import annotations

import argparse
import json

from xss_specialist.adapter_registry import load_classifier


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code")
    parser.add_argument(
        "--adapter",
        default=None,
        help="Registry adapter name. Defaults to the promoted active adapter.",
    )
    args = parser.parse_args()

    classify, spec = load_classifier(args.adapter)
    scores = classify(args.code, truncation=True)[0]
    best = max(scores, key=lambda item: item["score"])
    print(json.dumps({
        "adapter": spec.name,
        "adapter_kind": spec.kind,
        "verdict": best["label"],
        "confidence": float(best["score"]),
    }, indent=2))


if __name__ == "__main__":
    main()
