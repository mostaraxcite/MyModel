"""Model-only GPU evaluation of evidence-only Spark v3 against its group-held-out dev.

This measures extraction, NOT XSS confirmation. The deterministic AST gate
retains the sole authority over its bounded static decision; browser evidence
is necessary for confirmed findings. Internal generated dev is not a
real-world independent acceptance suite.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from training.spark_xss_evidence_v3 import candidate_rows
from xss_specialist.evidence_pipeline import review_evidence, validate_advisory

FIELDS = ("snippet_sha256", "source", "flow", "sink", "defense", "limitations")
EXPECTED_REVISION = "0bcb35678590218655dff3765b9e61c83b35e9c4"
EXPECTED_TRAINING_COMMIT = "131bbeb6600537a0635047bd62dca688da72a7fe"
SYSTEM = "you are a helpful assistant."


def select_internal_dev() -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for item in candidate_rows():
        if item["split"] == "eval":
            groups.setdefault(item["family"], []).append(item)
    expected={"html-outer", "javascript-timeout", "safe-inner-text",
              "safe-constant-sink", "unknown-sanitizer", "unknown-no-sink"}
    if set(groups) != expected or any(len(v) != 20 for v in groups.values()):
        raise RuntimeError("Unexpected internal-dev template groups")
    chosen=[]
    # Deterministic 12-case light GPU smoke test, two cases from
    # each family, not scores selected after observing model predictions.
    for name in sorted(groups):
        chosen.extend([groups[name][2],groups[name][16]])
    return chosen


def spark_prompt(instruction: str) -> str:
    return (
        "<｜start▁of▁sentence｜><|System|>\n" + SYSTEM
        + "<｜end▁of▁sentence｜><｜start▁of▁sentence｜><|User|>"
        + instruction + "<｜end▁of▁sentence｜><｜start▁of▁sentence｜><|Bot|></think>"
    )


def parse_advisory(raw: str) -> dict | None:
    try:
        obj=json.loads(raw.strip())
    except (json.JSONDecodeError,ValueError,TypeError):
        return None
    if not isinstance(obj,dict) or set(obj)!=set(FIELDS):
        return None
    return obj


def score_predictions(items: list[dict], predictions: list[dict]) -> dict:
    if len(items)!=len(predictions) or not items:
        raise ValueError("Missing or incomplete model predictions")
    details=[]
    for case,pred in zip(items,predictions):
        if pred.get("case_id")!=case["case_id"]:
            raise ValueError("Mismatched model prediction case order")
        truth=review_evidence(case["code"])
        proposal=parse_advisory(pred.get("raw",""))
        fields={
            key: bool(proposal is not None and proposal.get(key)==truth[key])
            for key in FIELDS
        }
        verified=validate_advisory(proposal,truth)
        details.append({
            "case_id":case["case_id"], "expected_static_status":case["expected_static_status"],
            "valid_json":proposal is not None,
            "per_field_exact":fields,
            "fully_grounded_advisory":verified["accepted"],
            "refusal_reason":verified["reason"],
            "raw":str(pred.get("raw",""))[:12000],
        })
    n=len(details)
    return {
        "n":n,
        "json_valid_rate":sum(v["valid_json"] for v in details)/n,
        "grounded_exact_rate":sum(v["fully_grounded_advisory"] for v in details)/n,
        "field_exact_rate":{
            key:sum(v["per_field_exact"][key] for v in details)/n
            for key in FIELDS
        },
        "static_labels":{name:sum(x["expected_static_status"]==name for x in details)
                         for name in ("CANDIDATE","SAFE","INCONCLUSIVE")},
        "details":details,
        "model_can_override_gate":False,
        "browser_confirmations":0,
    }


def generate(model,tokenizer,prompt: str) -> str:
    import torch
    encoded=tokenizer(spark_prompt(prompt),return_tensors="pt",add_special_tokens=False)
    device=next(model.parameters()).device
    encoded={key:value.to(device) for key,value in encoded.items()}
    with torch.inference_mode():
        out=model.generate(
            **encoded,max_new_tokens=520,do_sample=False,use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(out[0,encoded["input_ids"].shape[1]:],
                            skip_special_tokens=True)


def run_gpu(adapter: Path,output: Path) -> dict:
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    from peft import PeftModel

    if not torch.cuda.is_available():
        raise RuntimeError("T4 GPU required for actual model evaluation")
    for name in ("adapter_config.json","adapter_model.safetensors"):
        if not (adapter/name).is_file():
            raise FileNotFoundError(f"Missing {name} in trained evidence adapter")
    items=select_internal_dev()
    tokenizer=AutoTokenizer.from_pretrained(
        "XHToken/Spark-X2.5-4B",revision=EXPECTED_REVISION,trust_remote_code=True
    )
    base=AutoModelForCausalLM.from_pretrained(
        "XHToken/Spark-X2.5-4B",revision=EXPECTED_REVISION,trust_remote_code=True,
        torch_dtype=torch.float16,device_map={"":0},low_cpu_mem_usage=True
    ).eval()
    # Spark custom decoder needs actual FP16 gate weights to avoid CUDA
    # baddbmm(Byte). Never directly load the custom model with BNB byte weights.
    if any(layer.mlp.gate_proj.weight.dtype!=torch.float16
           for layer in base.model.layers):
        raise RuntimeError("Spark gate weights must be FP16 for evaluation")
    before=[]
    for i,item in enumerate(items,1):
        try: raw=generate(base,tokenizer,item["messages"][0]["content"])
        except Exception as exc: raw=f"GENERATE_FAILED: {type(exc).__name__}: {exc}"
        before.append({"case_id":item["case_id"],"raw":raw})
        print(f"BASE_EVIDENCE {i}/{len(items)} {item['case_id']}",flush=True)
    adapted=PeftModel.from_pretrained(base,str(adapter),is_trainable=False).eval()
    after=[]
    for i,item in enumerate(items,1):
        try: raw=generate(adapted,tokenizer,item["messages"][0]["content"])
        except Exception as exc: raw=f"GENERATE_FAILED: {type(exc).__name__}: {exc}"
        after.append({"case_id":item["case_id"],"raw":raw})
        print(f"TUNED_EVIDENCE {i}/{len(items)} {item['case_id']}",flush=True)
    report={
        "benchmark":"internal_group_heldout_synthetic_smoke_not_real_world",
        "trained_task":"ADVISORY_EVIDENCE_FIELDS_ONLY",
        "source_commit":EXPECTED_TRAINING_COMMIT,
        "base_model_revision":EXPECTED_REVISION,
        "base":score_predictions(items,before),
        "evidence_v3":score_predictions(items,after),
        "promotion":"DO_NOT_PROMOTE",
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    return report
