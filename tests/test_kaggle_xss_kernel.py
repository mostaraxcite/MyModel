"""CPU-only tests for packaging a private free Kaggle GPU kernel."""
from __future__ import annotations

import json
from pathlib import Path
import py_compile

import pytest

from scripts.build_kaggle_xss_kernel import build


def test_private_kaggle_t4_kernel_is_pinned_and_runnable(tmp_path):
    sha = "a" * 40
    result = build(owner="test_kaggle_user", sha=sha, output_dir=tmp_path)
    metadata = json.loads((tmp_path / "kernel-metadata.json").read_text())
    code = (tmp_path / "spark_xss_train.py").read_text()
    assert metadata["id"] == "test_kaggle_user/spark-xss-qlora-kaggle"
    assert metadata["machine_shape"] == "NvidiaTeslaT4"
    assert metadata["enable_gpu"] is True
    assert metadata["enable_internet"] is True
    assert metadata["is_private"] is True
    assert metadata["kernel_type"] == "script"
    assert metadata["code_file"] == "spark_xss_train.py"
    assert f'REPO_SHA = "{sha}"' in code
    assert 'REPO_SHA = "__MYMODEL_SHA__"' not in code
    assert "--four-bit" in code
    assert "--launch-training" in code
    assert 'SPARK_XSS_PREPARE_ONLY' in code
    assert result["training_started"] is False
    assert result["status"] == "PACKAGED_NOT_SUBMITTED"
    assert result["registered_or_deployed"] is False
    py_compile.compile(str(tmp_path / "spark_xss_train.py"), doraise=True)


@pytest.mark.parametrize("owner", [
    "", "../escape", "evil/name", "--flag", "contains space",
])
def test_unsafe_kaggle_owner_rejected(tmp_path, owner):
    with pytest.raises(ValueError, match="username"):
        build(owner=owner, sha="a" * 40, output_dir=tmp_path)


@pytest.mark.parametrize("sha", ["main", "a" * 39, "g" * 40, "refs/heads/main"])
def test_unpinned_source_rejected(tmp_path, sha):
    with pytest.raises(ValueError, match="immutable"):
        build(owner="valid-user", sha=sha, output_dir=tmp_path)


def test_kaggle_packaging_is_deterministic(tmp_path):
    first = build(owner="tester", sha="b" * 40, output_dir=tmp_path / "one")
    second = build(owner="tester", sha="b" * 40, output_dir=tmp_path / "two")
    assert first["script_sha256"] == second["script_sha256"]


def test_no_automatic_kaggle_submission():
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/kaggle-free-xss-training.yml"
    ).read_text()
    assert "workflow_dispatch" in workflow
    assert "KAGGLE_API_TOKEN" in workflow
    assert "NvidiaTeslaT4" in workflow
    assert "kaggle kernels push" in workflow
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "self-hosted" not in workflow
    assert "mode" in workflow


def test_kaggle_workflow_supports_no_run_publish_and_correct_owner():
    """An accepted Kaggle version does not prove a GPU has been assigned."""
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/kaggle-free-xss-training.yml"
    ).read_text()
    assert 'default: "dody2004"' in workflow
    assert '          - publish' in workflow
    assert 'kaggle kernels push -p kaggle-dist --no-run' in workflow
    assert "inputs.mode != 'package'" in workflow
    assert 'if [ "${KAGGLE_OWNER,,}" = "kaggle" ]' in workflow
    assert 'This does NOT prove a GPU was allocated' in workflow


def test_kaggle_spark_pins_legacy_transformers_before_loading_model():
    """Regress Kaggle v4 crash: Spark 4B list-style tied weights vs HF 5.x."""
    import ast

    script = (
        Path(__file__).resolve().parents[1]
        / "kaggle/spark_xss_train.py"
    )
    source = script.read_text(encoding="utf-8")
    ast.parse(source)
    assert 'TRANSFORMERS_VERSION = "4.57.1"' in source
    assert 'f"transformers=={TRANSFORMERS_VERSION}"' in source
    assert 'transformers.__version__ != TRANSFORMERS_VERSION' in source
    assert 'huggingface_hub>=0.34,<1' in source
    assert 'bitsandbytes>=0.45' in source
