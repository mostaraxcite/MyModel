import json
import yaml
from training.spark_schema_v15 import build, prompt
from training.spark_xss_evidence_v3 import candidate_rows
from evaluation.external_conditional_v11 import load_frozen


def test_schema_experiment_preserves_groups_and_targets(tmp_path):
    m=build(tmp_path)
    old=candidate_rows()
    for split, name in [('train','train'),('eval','eval')]:
        rows=json.loads((tmp_path/(name+'.json')).read_text())
        expected=[r for r in old if r['split']==split]
        assert len(rows)==len(expected)
        for row, original in zip(rows,expected):
            assert row['output']==original['messages'][1]['content']
            assert row['instruction']==prompt(original['code'])
    assert not set(m['train_groups']) & set(m['eval_groups'])
    assert m['promotion']=='DO_NOT_PROMOTE'
    recipe=yaml.safe_load((tmp_path/'train.yaml').read_text())
    assert recipe['num_train_epochs']==3 and recipe['model_revision']=='0bcb35678590218655dff3765b9e61c83b35e9c4'


def test_external_snippets_never_enter_training():
    external,_=load_frozen()
    known={c['code'] for c in external}
    assert not any(r['code'] in known for r in candidate_rows())


def test_workflow_shell_and_embedded_python_parse():
    from pathlib import Path
    import subprocess
    root=Path(__file__).resolve().parents[1]
    workflow=yaml.safe_load((root/'.github/workflows/spark-schema-v15.yml').read_text())
    for job in workflow['jobs'].values():
        for step in job['steps']:
            script=step.get('run')
            if not script: continue
            subprocess.run(['bash','-n'],input=script,text=True,check=True)
            if "python - <<'PY'\n" in script:
                code=script.split("python - <<'PY'\n",1)[1].split('\nPY',1)[0]
                compile(code,'workflow-python','exec')
