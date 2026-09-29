"""Official PEFT training entry point for XSS Specialist v0.5+.

The supported architecture is MiniLM-L6 with a LoRA sequence-classification
adapter. The implementation remains in ``train_peft_encoder`` so existing
automation that imports that module continues to work.
"""
from __future__ import annotations

from training.train_peft_encoder import main


if __name__ == "__main__":
    main()
