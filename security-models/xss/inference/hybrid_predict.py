"""Offline AST taint review; an optional legacy adapter supplies routing scores only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.taint import analyze


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('code', nargs='?', default='')
    parser.add_argument('--file', type=Path)
    parser.add_argument('--adapter', help='Optional advisory classifier; never the final judge')
    parser.add_argument('--trusted-module', action='append', default=[])
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    if args.list:
        from xss_specialist.adapter_registry import default_registry
        registry = default_registry()
        print(json.dumps({'engine':'xss-taint-v1', 'risk_adapters':[s.to_dict() for s in registry.list_adapters()]}, indent=2))
        return
    if bool(args.code) == bool(args.file):
        parser.error('provide exactly one of code or --file')
    code = args.file.read_text() if args.file else args.code
    scores = None
    if args.adapter:
        from xss_specialist.adapter_registry import load_classifier
        classifier, _ = load_classifier(args.adapter)
        scores = {r['label']:float(r['score']) for r in classifier(code, truncation=True)[0]}
    print(json.dumps(analyze(code, trusted_modules=tuple(args.trusted_module), risk_scores=scores), indent=2))


if __name__ == '__main__':
    main()
