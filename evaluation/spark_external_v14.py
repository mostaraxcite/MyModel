"""Code-only model comparison on EXPOSED conditional external fragments.

Exact agreement with the bounded AST is a conformance diagnostic, NOT
independent semantic accuracy or evidence of exploitation in upstream apps.
No browser context, expected fields, labels or fixture setup enter prompts.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

from evaluation.external_conditional_v11 import load_frozen
from evaluation.spark_evidence_v3_model_eval import (
    EXPECTED_REVISION, EXPECTED_TRAINING_COMMIT, FIELDS,
    generate, parse_advisory,
)
from training.spark_xss_evidence_v3 import INSTRUCTION
from xss_specialist.evidence_pipeline import review_evidence, validate_advisory


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def select_cases():
    cases, manifest = load_frozen()
    if len(cases) != 24 or Counter(c['label'] for c in cases) != {'unsafe': 15, 'safe': 9}:
        raise ValueError('Unexpected frozen external case inventory')
    items = []
    for case in cases:
        code = case['code']
        prompt = (INSTRUCTION + '\nSnippet SHA256: ' + digest(code.encode())
                  + '\nJavaScript:\n```javascript\n' + code
                  + '\n```\nOutput evidence JSON only.\n')
        items.append({'case_id': case['id'], 'code': code, 'prompt': prompt,
                      'prompt_sha256': digest(prompt.encode()),
                      'code_sha256': digest(code.encode()), 'family': case['family']})
    return items, manifest


def score(items, predictions):
    if not items or len(items) != len(predictions):
        raise ValueError('Missing model predictions')
    details = []
    for case, prediction in zip(items, predictions):
        if case['case_id'] != prediction.get('case_id'):
            raise ValueError('Prediction order/identity mismatch')
        raw = prediction.get('raw')
        if not isinstance(raw, str):
            raise ValueError('Model output must be retained as text')
        # Deliberately no runtime DOM profile: the model sees code only.
        oracle = review_evidence(case['code'])
        proposal = parse_advisory(raw)
        fields = {key: proposal is not None and proposal[key] == oracle[key] for key in FIELDS}
        accepted = validate_advisory(proposal, oracle)
        details.append({
            'case_id': case['case_id'], 'code_sha256': case['code_sha256'],
            'prompt_sha256': case['prompt_sha256'], 'raw': raw,
            'json_schema_keys_valid': proposal is not None,
            'field_exact_agreement': fields, 'oracle_status': oracle['decision']['status'],
            'advisory_accepted': accepted['accepted'], 'advisory_reason': accepted['reason'],
        })
    n = len(details)
    unique = {row['code_sha256']: row for row in details}
    return {
        'n': n, 'unique_snippets': len(unique),
        'json_schema_keys_rate': sum(r['json_schema_keys_valid'] for r in details) / n,
        'grounded_exact_rate': sum(r['advisory_accepted'] for r in details) / n,
        'unique_snippet_grounded_rate': sum(r['advisory_accepted'] for r in unique.values()) / len(unique),
        'field_exact_agreement': {k: sum(r['field_exact_agreement'][k] for r in details) / n for k in FIELDS},
        'oracle_status_counts': dict(Counter(r['oracle_status'] for r in details)),
        'details': details,
    }


def run_gpu(adapter, output):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel
    adapter, output = Path(adapter), Path(output)
    if not torch.cuda.is_available():
        raise RuntimeError('GPU required for actual weight inference')
    hashes = {name: digest((adapter / name).read_bytes()) for name in
              ('adapter_config.json', 'adapter_model.safetensors')}
    items, manifest = select_cases()
    report = {
        'benchmark': 'exposed_external_code_only_conformance_not_independent_accuracy',
        'status': 'running', 'model_evaluated': False,
        'base_model_revision': EXPECTED_REVISION, 'training_commit': EXPECTED_TRAINING_COMMIT,
        'adapter_sha256': hashes, 'cases_sha256': manifest['cases_sha256'],
        'input_mode': 'code_only_no_labels_no_fixture_setup_no_oracle_fields',
        'independence_verified': False, 'promotion': 'DO_NOT_PROMOTE',
        'model_has_final_authority': False, 'browser_confirmations': 0,
        'limitations': [
            'Exposed author-reviewed cases used in engine development; not a holdout.',
            'Exact AST agreement measures schema/conformance, not independent semantic truth.',
            '24 fixture cases contain 21 unique snippets, from five source repositories.',
            'Conditional attacker-controlled DOM setup is intentionally absent from model input.',
            'Source-disjoint 100 unsafe + 100 safe independently adjudicated acceptance set remains incomplete.',
        ],
        'predictions': {'base': [], 'evidence_v3': []},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        tmp = output.with_suffix('.tmp')
        tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        tmp.replace(output)
    save()
    try:
        tokenizer = AutoTokenizer.from_pretrained('XHToken/Spark-X2.5-4B', revision=EXPECTED_REVISION, trust_remote_code=True)
        base = AutoModelForCausalLM.from_pretrained(
            'XHToken/Spark-X2.5-4B', revision=EXPECTED_REVISION, trust_remote_code=True,
            torch_dtype=torch.float16, device_map={'': 0}, low_cpu_mem_usage=True).eval()
        if any(layer.mlp.gate_proj.weight.dtype != torch.float16 for layer in base.model.layers):
            raise RuntimeError('Spark inference requires FP16 gate weights')
        model = base
        for label in ('base', 'evidence_v3'):
            if label == 'evidence_v3':
                model = PeftModel.from_pretrained(base, str(adapter), is_trainable=False).eval()
            for item in items:
                raw = generate(model, tokenizer, item['prompt'])
                report['predictions'][label].append({'case_id': item['case_id'], 'raw': raw})
                save()
                print(f"V14_INFERENCE {label} {len(report['predictions'][label])}/{len(items)}", flush=True)
            report[label] = score(items, report['predictions'][label])
            save()
        report.update(status='success', model_evaluated=True)
        save()
        return report
    except BaseException as exc:
        report.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        save()
        raise
