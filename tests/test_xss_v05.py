"""v0.5 stack tests: adapter registry, oracle, hybrid router."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from xss_specialist.adapter_registry import (
    AdapterSpec,
    Registry,
    default_registry,
    load_registry,
    register_adapter,
    write_registry,
)
from xss_specialist.oracle import analyze


def test_official_peft_entrypoint_is_minilm_lora():
    from training.train_peft import main as official_main
    from training.train_peft_encoder import DEFAULT_BASE_MODEL, main as encoder_main

    assert official_main is encoder_main
    assert DEFAULT_BASE_MODEL == "nreimers/MiniLM-L6-H384-uncased"


# -------- Adapter registry --------


def test_default_registry_returns_v04_baseline_when_uninitialised(tmp_path: Path, monkeypatch):
    """If no registry file exists yet, the legacy v0.4 model dir is exposed as a full adapter."""
    fake_root = tmp_path
    (fake_root / "security-models" / "xss" / "model").mkdir(parents=True)
    monkeypatch.setattr("xss_specialist.adapter_registry.ROOT", fake_root)
    reg = default_registry()
    assert reg.active == "v0.4-baseline"
    assert reg.get("v0.4-baseline").kind == "full"


def test_registry_round_trips_through_disk(tmp_path: Path):
    reg = Registry(
        registry_path=tmp_path / "REGISTRY.json",
        adapters={
            "alpha": AdapterSpec("alpha", "peft", "base/model", "adapters/alpha", promoted=True),
            "beta": AdapterSpec("beta", "full", "base/model", "adapters/beta", promoted=False),
        },
        active="alpha",
    )
    write_registry(reg)
    loaded = load_registry(tmp_path / "REGISTRY.json")
    assert loaded.active == "alpha"
    assert {name for name in loaded.adapters} == {"alpha", "beta"}
    assert loaded.get("beta").kind == "full"


def test_registering_adapter_persists(tmp_path: Path):
    reg = Registry(
        registry_path=tmp_path / "REGISTRY.json",
        adapters={"v0.4-baseline": AdapterSpec("v0.4-baseline", "full", "base/model", "model")},
        active="v0.4-baseline",
    )
    write_registry(reg)
    new_reg = register_adapter(
        reg,
        name="xss-v0.5",
        kind="peft",
        base_model="microsoft/MiniLM-L6-H384-uncased",
        path="adapters/xss-v05",
        description="LoRA adapter for v0.5",
        promoted=False,
        activate=True,
    )
    assert new_reg.active == "xss-v0.5"
    reloaded = load_registry(tmp_path / "REGISTRY.json")
    assert "xss-v0.5" in reloaded.adapters
    assert reloaded.active == "xss-v0.5"


def test_unknown_adapter_name_raises():
    reg = Registry(
        registry_path=Path("/tmp/_unused.json"),
        adapters={"only": AdapterSpec("only", "full", "base", "path")},
        active="only",
    )
    with pytest.raises(KeyError):
        reg.get("does-not-exist")


# -------- Oracle --------


def test_oracle_classifies_sink_and_source_as_xss():
    assert analyze("container.innerHTML = location.hash").label == "XSS"
    assert analyze("eval(req.body.payload)").label == "XSS"
    assert analyze("a.setAttribute('onclick', location.search)").label == "XSS"


def test_oracle_classifies_text_content_assignment_as_safe():
    assert analyze("node.textContent = userInput").label == "SAFE"


def test_oracle_abstains_on_arithmetic():
    assert analyze("x = 1 + 2").label == "POSSIBLE_XSS"
    assert analyze("y = a + b").label == "POSSIBLE_XSS"


def test_oracle_handles_empty_input():
    assert analyze("").label == "SAFE"
    assert analyze("   ").label == "SAFE"


# -------- Provenance contract (locked external_test_v5 disjoint from training) --------


def test_external_test_v5_is_disjoint_from_training_splits():
    data = Path("security-models/xss/data")
    external_path = data / "external_test_v5.jsonl"
    if not external_path.exists():
        pytest.skip("external_test_v5.jsonl not present")
    import hashlib

    external = {
        json.loads(line)["provenance"]["content_sha256"]
        for line in external_path.read_text(encoding="utf-8").splitlines()
        if line
    }
    for name in ("train.jsonl", "validation.jsonl", "test.jsonl", "hard_test.jsonl"):
        path = data / name
        if not path.exists():
            continue
        hashes = {
            hashlib.sha256(json.loads(line)["code"].encode()).hexdigest()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        }
        assert external.isdisjoint(hashes), f"{name} overlaps external_test_v5"


def test_external_test_v5_manifest_declares_training_disallowed():
    manifest_path = Path("security-models/xss/data/external_test_v5_manifest.json")
    if not manifest_path.exists():
        pytest.skip("external_test_v5_manifest.json not present")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["training_allowed"] is False
    assert manifest["partition"] == "external_test_v5_locked"


def test_peft_load_failure_is_not_masked_by_random_head(tmp_path: Path, monkeypatch):
    """A PEFT adapter that cannot be applied must fail loudly, never serve a fresh random head."""
    from xss_specialist import adapter_registry as ar

    monkeypatch.setattr(ar.AutoTokenizer, "from_pretrained", lambda *a, **k: object())
    monkeypatch.setattr(ar.AutoModelForSequenceClassification, "from_pretrained",
                        lambda *a, **k: object())

    def boom(*a, **k):
        raise KeyError("classifier")

    monkeypatch.setattr(ar.PeftModel, "from_pretrained", boom)
    reg = ar.Registry(tmp_path / "REGISTRY.json", {
        "x": ar.AdapterSpec(name="x", kind="peft", base_model="base", path=str(tmp_path))}, "x")
    with pytest.raises(RuntimeError, match="classifier"):
        ar.load_classifier(registry=reg)
