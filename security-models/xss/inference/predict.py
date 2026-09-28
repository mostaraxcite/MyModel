"""Classify one HTML/JavaScript snippet with XSS-SLM v0.1."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from transformers import pipeline


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code")
    parser.add_argument("--model-dir", type=Path, default=root / "model")
    args = parser.parse_args()
    scores = pipeline("text-classification", model=str(args.model_dir), tokenizer=str(args.model_dir), top_k=None, device=-1)(args.code)[0]
    best = max(scores, key=lambda item: item["score"])
    print(json.dumps({"verdict": best["label"], "confidence": best["score"]}, indent=2))


if __name__ == "__main__":
    main()
