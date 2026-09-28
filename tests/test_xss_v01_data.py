import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "security-models" / "xss" / "scripts" / "prepare_data.py"
SPEC = importlib.util.spec_from_file_location("xss_v01_prepare_data", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_dataset_has_expected_distribution_and_no_leakage():
    splits = MODULE.build_dataset(1000, 1337)
    summary = MODULE.validate_dataset(splits)
    assert {name: details["count"] for name, details in summary.items()} == {
        "train": 800,
        "validation": 100,
        "test": 100,
    }
    assert summary["train"]["labels"] == {"POSSIBLE_XSS": 160, "SAFE": 320, "XSS": 320}


def test_validator_rejects_unsafe_safe_label():
    row = MODULE._record("bad", "out.innerHTML = userInput;", "SAFE", "innerHTML", "userInput")
    assert MODULE.validate_sample(row)


def test_contrast_group_contains_all_labels():
    rows = MODULE.make_group(7, MODULE.random.Random(7))
    assert {row["label"] for row in rows} == {"SAFE", "POSSIBLE_XSS", "XSS"}


def test_hard_cases_are_valid_and_unique():
    rows = MODULE.hard_test_cases()
    assert len(rows) == 1000
    assert len({row["code"] for row in rows}) == len(rows)
    assert {label: sum(row["label"] == label for row in rows) for label in MODULE.LABELS} == {
        "SAFE": 400,
        "POSSIBLE_XSS": 200,
        "XSS": 400,
    }
    assert not [error for row in rows for error in MODULE.validate_sample(row)]
