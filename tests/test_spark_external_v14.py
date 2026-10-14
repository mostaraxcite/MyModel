import json
import pytest
from evaluation.spark_external_v14 import select_cases, score, FIELDS
from xss_specialist.evidence_pipeline import review_evidence


def test_frozen_inputs_have_no_expected_answer_or_harness():
    items, manifest = select_cases()
    assert len(items) == 24
    assert len({i['code_sha256'] for i in items}) == 21
    for item in items:
        assert set(item) == {'case_id', 'code', 'prompt', 'prompt_sha256', 'code_sha256', 'family'}
        assert 'dom_context' not in item['prompt']
        assert '__auditProof' not in item['prompt']
        assert item['code'] in item['prompt']


def test_missing_or_reordered_predictions_fail():
    items, _ = select_cases()
    with pytest.raises(ValueError): score(items, [])
    with pytest.raises(ValueError): score(items[:1], [{'case_id': 'wrong', 'raw': '{}'}])


def test_invalid_output_remains_failure_not_safe():
    items, _ = select_cases()
    result = score(items, [{'case_id': i['case_id'], 'raw': 'SAFE'} for i in items])
    assert result['grounded_exact_rate'] == 0
    assert result['json_schema_keys_rate'] == 0
    assert all(not x['advisory_accepted'] for x in result['details'])


def test_exact_fields_and_semantic_changes_are_distinguished():
    items, _ = select_cases()
    case = items[0]
    expected = review_evidence(case['code'])
    proposal = {k: expected[k] for k in FIELDS}
    result = score([case], [{'case_id': case['case_id'], 'raw': json.dumps(proposal)}])
    assert result['grounded_exact_rate'] == 1
    proposal['source'] = 'invented source'
    result = score([case], [{'case_id': case['case_id'], 'raw': json.dumps(proposal)}])
    assert result['json_schema_keys_rate'] == 1
    assert result['grounded_exact_rate'] == 0
    assert result['field_exact_agreement']['source'] == 0


def test_case_count_is_not_unique_snippet_count():
    items, _ = select_cases()
    result = score(items, [{'case_id': i['case_id'], 'raw': '{}'} for i in items])
    assert result['n'] == 24 and result['unique_snippets'] == 21
