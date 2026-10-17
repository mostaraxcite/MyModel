"""Schema-explicit V15 experiment on the unchanged V3 synthetic split."""
import hashlib
import json
from pathlib import Path
import yaml
from training.spark_xss_evidence_v3 import build as build_v3

CONTRACT = '''Return ONLY one JSON object. The required nested types are:
{"snippet_sha256":string,"source":{"observed":[string],"status":string},
"flow":{"per_sink":[{"basis":string,"relation":string,"trace":[string]}]},
"sink":{"per_sink":[{"execution_context":string,"expression":string,"kind":string,"line":integer}]},
"defense":{"per_sink":[{"context_compatible":boolean,"sanitizer_identity":string_or_null,"status":string}]},
"limitations":[string]}.
Replace type placeholders with observed evidence. Source means an untrusted input,
not an output API. Per-sink arrays follow source-code order. Empty lists are allowed.
Unknown data flow must remain UNKNOWN. Do not replace objects or arrays with prose.
Do not add a final vulnerability verdict or claim browser execution.
'''


def prompt(code):
    sha = hashlib.sha256(code.encode()).hexdigest()
    return CONTRACT + '\nSnippet SHA256: ' + sha + '\nJavaScript:\n```javascript\n' + code + '\n```\n'


def build(output_dir):
    output_dir = Path(output_dir).resolve()
    manifest = build_v3(output_dir)
    for split, key in [('train', 'train_sha256'), ('eval', 'eval_sha256')]:
        path = output_dir / (split + '.json')
        rows = json.loads(path.read_text())
        for row in rows:
            code = row['instruction'].split('```javascript\n', 1)[1].split('\n```', 1)[0]
            row['instruction'] = prompt(code)
        raw = json.dumps(rows, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
        path.write_text(raw)
        manifest[key] = hashlib.sha256(raw.encode()).hexdigest()
    recipe_path = output_dir / 'train.yaml'
    recipe = yaml.safe_load(recipe_path.read_text())
    recipe.update(num_train_epochs=3.0, learning_rate=5e-5, cutoff_len=1536)
    recipe_path.write_text(yaml.safe_dump(recipe, sort_keys=False))
    manifest.update(candidate='spark-schema-explicit-v15', training_variant='schema_explicit_v15',
                    changes=['explicit nested JSON types', '3 epochs', 'learning rate 5e-5', '1536 token cutoff'],
                    independent_evaluation=False)
    (output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    import argparse
    import subprocess
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--launch-training', action='store_true')
    args = parser.parse_args()
    print(json.dumps(build(args.output_dir)))
    if args.launch_training:
        subprocess.run(['llamafactory-cli', 'train', str(args.output_dir.resolve() / 'train.yaml')], check=True)


if __name__ == '__main__':
    main()
