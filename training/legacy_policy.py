"""The whole-snippet three-way classifier training series is retired."""


def require_supported_training():
    raise SystemExit(
        "Legacy SAFE/POSSIBLE_XSS/XSS classifier training is retired. "
        "Use the offline xss-taint-v1 analysis path. No v0.15 training is authorized. "
        "See docs/XSS_TAINT_V1.md."
    )
