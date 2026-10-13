"""Automatically collect entry-state context in the isolated exposed fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluation.external_conditional_v11 import VENDOR,load_frozen,run_browser
from evaluation.decision_metrics import score_decisions
from xss_specialist.browser_context_evidence import BrowserContextSession,ContextEvidenceError


def evaluate(output):
    from playwright.sync_api import sync_playwright
    cases,manifest=load_frozen()
    session=BrowserContextSession(manifest['jquery_sha256'])
    rows=[];negative=[]
    with sync_playwright() as p:
        browser=p.chromium.launch()
        try:
            for case in cases:
                captures=[]
                def collect(frame,fixture,marker):
                    captures.append(session.capture(frame,fixture['code'],marker))
                runtime=run_browser(browser,case,VENDOR.read_text(),before_fixture=collect)
                if len(captures)!=1:raise ContextEvidenceError('One pre-execution capture required')
                receipt=captures[0]
                review=session.review(case['code'],receipt)
                rows.append(case|{'browser':runtime,'static_status':review['decision']['status'],
                                 'context_evidence':review['context_evidence'],'dom_context':review['dom_context'],
                                 'entry_state_receipt':receipt})
            case=next(c for c in cases if c['id']=='SRC-2-L2-B16')
            for mode in ['changed_jquery_method','changed_native_getter','removed_input_marker']:
                captures=[];denials=[]
                def negative_collect(frame,fixture,marker):
                    if mode=='changed_jquery_method':frame.evaluate('jQuery.fn.html=function(){return this;}')
                    elif mode=='changed_native_getter':frame.evaluate("Object.defineProperty(HTMLInputElement.prototype,'value',{get(){return 'replacement';},configurable:true});")
                    else:frame.evaluate("document.querySelector('textarea').value='fixed';")
                    try:captures.append(session.capture(frame,fixture['code'],marker))
                    except ContextEvidenceError as e:denials.append(str(e))
                runtime=run_browser(browser,case,VENDOR.read_text(),before_fixture=negative_collect)
                if mode=='removed_input_marker':
                    result=session.review(case['code'],captures[0]);passed=result['decision']['status']=='INCONCLUSIVE'
                else:passed=bool(denials) and not captures
                negative.append({'mode':mode,'passed':passed,'denials':denials,'browser':runtime})
        finally:browser.close()
    metrics=score_decisions(rows,{'evaluation_kind':'exposed_automatic_browser_context_regression'})
    runtime_valid=all(r['browser']['fixture_completed'] and r['browser']['label_agrees'] and not r['browser']['errors'] for r in rows)
    result={'evaluation_kind':'exposed_automatic_browser_context_regression',
            'cases_sha256':manifest['cases_sha256'],'metrics':metrics,'results':rows,
            'negative_runtime_checks':negative,'browser_validation_passed':runtime_valid,
            'context_source':'trusted-controller runtime capture; no manual selector/input profile',
            'model_evaluated':False,'promotion':'DO_NOT_PROMOTE',
            'limitations':['Evidence authenticates capture/session/code, not real-world attacker access.',
                          'Receipts require the live ephemeral controller session; exports alone cannot authorize later analysis.',
                          'These are exposed author-reviewed local fixtures, not an independent holdout.']}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    print('V13_AUTOMATIC_BROWSER_CONTEXT='+json.dumps(result,separators=(',',':')))
    if not runtime_valid or not all(n['passed'] for n in negative) or metrics['counts']['true_candidates']!=15 or metrics['counts']['false_candidates'] or metrics['unsafe_static_safe']:
        raise SystemExit('Automatic context regression failed; inspect retained evidence')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    evaluate(p.parse_args().output)
