"""Score synthetic static/browser fixtures without executing external targets.

Regression cases are exposed development data. A new frozen partition must
record its provenance and hash before scoring; neither partition evaluates
model weights or establishes whole-application safety.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
from xss_specialist.grounded_advisor import grounded_review
from evaluation.xss_v7_browser_harness import run_browser

def evaluate(cases_path, output_path, manifest_path=None):
    raw=cases_path.read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    manifest=json.loads(manifest_path.read_text()) if manifest_path else None
    if manifest and manifest['cases_sha256']!=digest:
        raise ValueError('Frozen case hash changed')
    if manifest:
        repo=Path(__file__).resolve().parents[1]
        for name, expected in manifest.get('engine_sha256',{}).items():
            if hashlib.sha256((repo/name).read_bytes()).hexdigest()!=expected:
                raise ValueError('Frozen engine hash changed: '+name)
    rows=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        version=browser.version
        for case in [json.loads(line) for line in raw.decode().splitlines()]:
            packet=grounded_review(case['code'])
            runtime=run_browser(browser,case)
            rows.append({**case,'static_status':packet['decision']['status'],'packet':packet,'browser':runtime})
        browser.close()
    confusion={label:dict(Counter(row['static_status'] for row in rows if row['label']==label)) for label in ['unsafe','safe']}
    unsafe=sum(row['label']=='unsafe' for row in rows)
    safe=sum(row['label']=='safe' for row in rows)
    metrics={'unsafe_candidate_recall':confusion['unsafe'].get('CANDIDATE',0)/unsafe,
             'safe_false_positive_rate':confusion['safe'].get('CANDIDATE',0)/safe,
             'unsafe_static_safe':confusion['unsafe'].get('SAFE',0),
             'decision_coverage':sum(row['static_status']!='INCONCLUSIVE' for row in rows)/len(rows),
             'browser_executed_unsafe':sum(row['browser']['executed'] for row in rows if row['label']=='unsafe'),
             'browser_executed_safe':sum(row['browser']['executed'] for row in rows if row['label']=='safe'),
             'browser_label_mismatches':[row['id'] for row in rows if not row['browser']['label_agrees']]}
    report={'cases_sha256':digest,'manifest':manifest,'confusion':confusion,'metrics':metrics,
            'chromium':version,'model_evaluated':False,'promotion':'DO_NOT_PROMOTE',
            'scope':'synthetic browser fixture execution only; no live targets','results':rows}
    output_path.parent.mkdir(parents=True,exist_ok=True)
    output_path.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({k:report[k] for k in ['cases_sha256','confusion','metrics','promotion']},indent=2))
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--regression-gate',action='store_true')
    args=parser.parse_args()
    report=evaluate(args.cases,args.output,args.manifest)
    if args.regression_gate:
        metrics=report['metrics']
        if (metrics['unsafe_candidate_recall']!=1 or metrics['safe_false_positive_rate']!=0
            or metrics['unsafe_static_safe']!=0 or metrics['browser_label_mismatches']):
            raise SystemExit('Exposed browser regression gate failed')

if __name__=='__main__':main()
