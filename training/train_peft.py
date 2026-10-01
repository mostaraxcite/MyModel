"""Retired whole-snippet classifier entry point; fail before loading ML dependencies."""
from __future__ import annotations

from training.legacy_policy import require_supported_training


def main():
    require_supported_training()


if __name__ == "__main__":
    main()
