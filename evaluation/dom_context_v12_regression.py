"""Exposed regression: same original fixtures, explicit checked runtime context.

Supplying context is a changed analysis condition, not an independent accuracy
comparison. Both default and contextual judgments remain visible.
"""
import argparse
import json
from pathlib import Path
from evaluation.external_conditional_v11 import ROOT, VENDOR, load_frozen, run_browser
from evaluation.decision_metrics import score_decisions
from xss_specialist.grounded_advisor import grounded_review


def evaluate(output):
    from playwright.sync_api import sync_playwright
    cases, _=load_frozen()
    context=json.loads((ROOT/'evaluation/fixtures/xss_dom_context_v12.json').read_text())
    rows=[]
    with sync_playwright() as p:
        browser=p.chromium.launch()
        try:
            for case in cases:
                runtime=run_browser(browser,case,VENDOR.read_text())
                default=grounded_review(case['code'])
                after=grounded_review(case['code'],dom_context=context)
                rows.append(case|{'browser':runtime,'static_status':after['decision']['status'],
                                 'default_static_status':default['decision']['status'],
                                 'dom_context':after['dom_context']})
        finally:
            browser.close()
    metrics=score_decisions(rows,{'evaluation_kind':'exposed_dom_context_regression'})
    valid=all(r['browser']['fixture_completed'] and r['browser']['label_agrees'] and not r['browser']['errors'] for r in rows)
    result={'evaluation_kind':'exposed_dom_context_regression','metrics':metrics,
            'results':rows,'dom_context':context,'browser_validation_passed':valid,
            'model_evaluated':False,'promotion':'DO_NOT_PROMOTE',
            'limitations':['Explicit DOM assertions are additional caller-supplied analysis conditions, not inferred facts.',
                          'Fixtures are exposed and author-reviewed; no independent accuracy established.',
                          'No automatic scan activation or model-weight evaluation.']}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    print('V12_DOM_CONTEXT_REGRESSION='+json.dumps(result,separators=(',',':')))
    if not valid or metrics['counts']['true_candidates']!=15 or metrics['counts']['false_candidates'] or metrics['unsafe_static_safe']:
        raise SystemExit('DOM contextual regression failed')


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    evaluate(p.parse_args().output)
