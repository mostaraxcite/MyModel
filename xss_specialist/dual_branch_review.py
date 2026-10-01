"""Conservative integration for the XSS dual-branch structural advisor.

The neural model can only prioritize and describe structure. It cannot produce a
confirmed XSS verdict. Deterministic taint analysis remains authoritative for
static candidate routing; observed browser execution is required for confirmation.
"""
from __future__ import annotations

import json
from pathlib import Path

import torch
from transformers import AutoTokenizer

from verification.browser_oracle import verify_dom_case
from xss_specialist.dual_branch import XSSDualBranchModel, LABEL_SPACES
from xss_specialist.taint import analyze as taint_analyze


def _distribution(logits: torch.Tensor, labels: list[str]) -> dict[str, float]:
    probs = torch.softmax(logits, dim=-1)[0].detach().cpu().tolist()
    return {label: float(prob) for label, prob in zip(labels, probs)}


def _top(distribution: dict[str, float]) -> dict:
    label, confidence = max(distribution.items(), key=lambda kv: kv[1])
    return {
        "label": label,
        "confidence": float(confidence),
        "probabilities": distribution,
    }


class DualBranchAdvisor:
    def __init__(self, model_dir: str | Path, device: str | None = None):
        self.model_dir = Path(model_dir)
        self.device = torch.device(
            device or ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.model = XSSDualBranchModel.load(self.model_dir)
        self.model.to(self.device)
        self.model.eval()
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_dir / "semantic_backbone"
        )

    def _tokens(self, text: str) -> dict[str, torch.Tensor]:
        batch = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=128,
        )
        return {k: v.to(self.device) for k, v in batch.items()}

    @torch.no_grad()
    def semantic(self, code: str) -> dict:
        out = self.model.forward_semantic(**self._tokens(code))
        return {
            task: _top(_distribution(out.logits[task], LABEL_SPACES[task]))
            for task in ("source", "sink", "defense")
        }

    @torch.no_grad()
    def flow(self, relation: dict) -> dict:
        required = ("source_expression", "sink_expression", "flow_excerpt")
        if any(not relation.get(k) for k in required):
            return {
                "label": "UNKNOWN",
                "confidence": 0.0,
                "probabilities": {},
                "status": "MISSING_REVIEWED_RELATION_INPUT",
            }
        text = (
            f"[SOURCE]\n{relation['source_expression']}\n"
            f"[SINK]\n{relation['sink_expression']}\n"
            f"[FLOW]\n{relation['flow_excerpt']}"
        )
        out = self.model.forward_flow(**self._tokens(text))
        result = _top(_distribution(out.logits["flow"], LABEL_SPACES["flow"]))
        result["status"] = "ADVISORY_ONLY"
        return result


def _advisory_risk(semantic: dict, flow: dict | None) -> float:
    source = semantic["source"]["probabilities"]
    sink = semantic["sink"]["probabilities"]
    defense = semantic["defense"]["probabilities"]

    source_risk = 1.0 - float(source.get("NONE", 0.0))
    sink_risk = sum(
        float(sink.get(name, 0.0))
        for name in ("DANGEROUS_HTML", "DANGEROUS_JS", "DANGEROUS_URL")
    )
    no_defense = float(defense.get("NONE", 0.0))

    flow_factor = 0.5
    if flow and flow.get("probabilities"):
        flow_factor = (
            float(flow["probabilities"].get("CONNECTED", 0.0))
            + 0.5 * float(flow["probabilities"].get("UNKNOWN", 0.0))
        )

    return float(source_risk * sink_risk * no_defense * flow_factor)


def review(
    code: str,
    *,
    model_dir: str | Path,
    relation: dict | None = None,
    trusted_modules: tuple[str, ...] = (),
    confirm_browser: bool = False,
) -> dict:
    advisor = DualBranchAdvisor(model_dir)
    semantic = advisor.semantic(code)
    flow = advisor.flow(relation) if relation else None
    risk = _advisory_risk(semantic, flow)

    advisory = {
        "engine": "xss-dual-branch-v2",
        "semantic": semantic,
        "flow": flow,
        "risk_score": risk,
        "final_judge": False,
    }

    deterministic = taint_analyze(
        code,
        trusted_modules=trusted_modules,
        risk_scores={
            "XSS": risk,
            "dual_branch": advisory,
        },
    )

    final = {
        "verdict": "SAFE" if deterministic["verdict"] == "SAFE" else "POSSIBLE_XSS",
        "confirmed": False,
        "confirmation_status": "NOT_REQUESTED",
        "requires_browser": bool(deterministic["requires_oracle"]),
        "browser_evidence": None,
    }

    if confirm_browser and deterministic["requires_oracle"]:
        evidence = verify_dom_case({
            "code": code,
            "language": "javascript",
            "vulnerable": True,
        })
        compact = {
            key: evidence.get(key)
            for key in ("status", "executed", "scope", "js_error")
            if key in evidence
        }
        final["browser_evidence"] = compact
        if evidence.get("executed") is True:
            final.update({
                "verdict": "XSS",
                "confirmed": True,
                "confirmation_status": "CONFIRMED_EXECUTION",
                "requires_browser": False,
            })
        else:
            final.update({
                "verdict": "POSSIBLE_XSS",
                "confirmed": False,
                "confirmation_status": "UNCONFIRMED",
                "requires_browser": True,
            })

    return {
        "advisory": advisory,
        "deterministic": deterministic,
        "final": final,
        "policy": {
            "model_can_confirm_xss": False,
            "deterministic_candidate_before_browser": True,
            "browser_execution_required_for_confirmation": True,
        },
    }


def main():
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", type=Path)
    p.add_argument("--model-dir", type=Path, required=True)
    p.add_argument("--relation", type=Path)
    p.add_argument("--trusted-module", action="append", default=[])
    p.add_argument("--confirm-browser", action="store_true")
    args = p.parse_args()

    relation = json.loads(args.relation.read_text()) if args.relation else None
    result = review(
        args.file.read_text(),
        model_dir=args.model_dir,
        relation=relation,
        trusted_modules=tuple(args.trusted_module),
        confirm_browser=args.confirm_browser,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
