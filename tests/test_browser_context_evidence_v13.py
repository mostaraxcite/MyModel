import copy
import json
import re
import pytest
import xss_specialist.browser_context_evidence as evidence
from xss_specialist.browser_context_evidence import BrowserContextSession,ContextEvidenceError,selectors_and_names

CODE='$("#id").html($("textarea").val());'

class Frame:
    # A mock for trusted controller observations, not claimed browser proof.
    def __init__(self,**overrides):
        self.observations={'library_identity_verified':True,'native_identity_verified':True,
                           'frame_url':'http://audit.local/case','jquery_version':'4.0.0',
                           'inputs':{'textarea':['value']},'receivers':['#id','textarea'],
                           'bindings':{},'nodes':[]}|overrides
    def evaluate(self,script,args):
        assert args['selectors']==['#id','textarea']
        return copy.deepcopy(self.observations)

def packet():
    session=BrowserContextSession('a'*64)
    return session,session.capture(Frame(),CODE,'random-controller-marker')

def test_authenticated_context_is_bound_to_the_requested_source_and_has_no_key():
    session,record=packet()
    result=session.review(CODE,record)
    assert result['decision']['status']=='CANDIDATE'
    assert result['browser_confirmed'] is False
    assert result['context_evidence']['integrity_verified'] is True
    assert result['context_evidence']['real_application_attacker_control_verified'] is False
    assert '_key' not in record

def test_changed_source_cannot_reuse_the_snapshot_even_with_valid_signature():
    session,record=packet()
    with pytest.raises(ContextEvidenceError,match='different code'):
        session.review(CODE+'\n',record)

def test_model_edited_fields_or_self_declared_flags_do_not_create_authority():
    session,record=packet()
    record['observations']['inputs']['textarea']=['html']
    record['verified']=True
    with pytest.raises(ContextEvidenceError,match='integrity'):
        session.review(CODE,record)

def test_other_controller_session_cannot_accept_a_copied_packet():
    _,record=packet()
    other=BrowserContextSession('a'*64)
    with pytest.raises(ContextEvidenceError,match='integrity'):
        other.review(CODE,record)

def test_replay_is_rejected_after_first_consumption():
    session,record=packet();session.review(CODE,record)
    with pytest.raises(ContextEvidenceError,match='consumed'):
        session.review(CODE,record)

def test_expired_snapshot_is_not_accepted(monkeypatch):
    monkeypatch.setattr(evidence.time,'monotonic',lambda:10)
    session,record=packet()
    monkeypatch.setattr(evidence.time,'monotonic',lambda:71)
    with pytest.raises(ContextEvidenceError,match='expired'):
        session.review(CODE,record)

@pytest.mark.parametrize('overrides',[{'library_identity_verified':False},{'native_identity_verified':False},{'frame_url':'http://different.local/case'}])
def test_failed_runtime_identities_never_get_signed(overrides):
    with pytest.raises(ContextEvidenceError,match='not verified'):
        BrowserContextSession('a'*64).capture(Frame(**overrides),CODE,'marker')

def test_capture_with_no_controlled_read_does_not_infer_an_untrusted_source():
    session=BrowserContextSession('a'*64)
    record=session.capture(Frame(inputs={}),CODE,'marker')
    assert session.review(CODE,record)['decision']['status']=='INCONCLUSIVE'

def test_selector_extraction_tracks_native_ids_and_nested_real_selectors():
    selectors,_=selectors_and_names('$("#foo").find(".bla")[0].value; document.getElementById("field").value;')
    assert selectors==['#field','#foo','#foo .bla']

def test_markup_strings_are_not_misclassified_as_selectors():
    assert selectors_and_names('$("<div>markup</div>");')[0]==[]

def test_native_id_with_css_punctuation_cannot_probe_a_different_element():
    assert selectors_and_names('document.getElementById("foo.bar").value;')[0]==[]

def test_malformed_source_fails_before_any_browser_probe():
    with pytest.raises(ContextEvidenceError):selectors_and_names('const =')

class Page:
    main_frame=object()
    def expose_binding(self,name,callback):
        self.channel=name;self.callback=callback

def test_setup_transport_is_one_shot_and_bound_to_original_frame():
    page=Page();session=BrowserContextSession('a'*64)
    slot=session.install(page,CODE,'marker')
    nonce=re.search(r'window\[[^]]+\]\("([a-f0-9]+)",JSON.stringify',slot['script']).group(1)
    observations=json.dumps(Frame().observations)
    assert page.callback({'frame':object()},nonce,observations)['accepted'] is False
    assert page.callback({'frame':page.main_frame},'wrong',observations)['accepted'] is False
    assert page.callback({'frame':page.main_frame},nonce,observations)['accepted'] is True
    original=copy.deepcopy(slot['receipt'])
    assert page.callback({'frame':page.main_frame},nonce,observations)['accepted'] is False
    assert slot['receipt']==original
    assert 'document.currentScript.remove()' in slot['script']
    assert session.review(CODE,original)['decision']['status']=='CANDIDATE'

def test_setup_transport_rejects_incomplete_observations():
    page=Page();session=BrowserContextSession('a'*64)
    slot=session.install(page,CODE,'marker')
    nonce=re.search(r'window\[[^]]+\]\("([a-f0-9]+)",JSON.stringify',slot['script']).group(1)
    assert page.callback({'frame':page.main_frame},nonce,'[]')['accepted'] is False
    assert slot['receipt'] is None and slot['error']
