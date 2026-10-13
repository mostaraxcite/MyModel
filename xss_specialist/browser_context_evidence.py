"""Controller-collected entry-state evidence for isolated DOM fixture review.

An ephemeral session authenticates origin/code/age and rejects replay. It does
not prove real-application attacker control or independent label correctness.
Only a trusted browser controller may retain/use the session object and key.
"""
import hashlib
import hmac
import json
import secrets
import re
import time
from tree_sitter import Language, Parser
import tree_sitter_javascript
from xss_specialist.dom_context import validate_context
from xss_specialist.grounded_advisor import grounded_review


class ContextEvidenceError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def selectors_and_names(code):
    raw=code.encode()
    root=Parser(Language(tree_sitter_javascript.language())).parse(raw).root_node
    selectors=set(); names=set()
    def text(node):return raw[node.start_byte:node.end_byte].decode() if node else ''
    def literal(node):
        value=text(node)
        return value[1:-1] if node and node.type=='string' and '\\' not in value else None
    def selector(node):
        if node is None:return None
        if node.type=='subscript_expression':return selector(node.child_by_field_name('object'))
        if node.type!='call_expression':return None
        fn=node.child_by_field_name('function');args=node.child_by_field_name('arguments')
        args=[a for a in args.named_children if a.type!='comment'] if args else []
        name=text(fn)
        if name in {'$','jQuery'} and len(args)==1:
            if text(args[0])=='document':return ':document'
            value=literal(args[0])
            return value if value and not value.lstrip().startswith('<') else None
        if name in {'document.getElementById','document.querySelector','document.querySelectorAll'} and len(args)==1:
            value=literal(args[0]);return '#'+value if value and name.endswith('getElementById') else value
        if fn.type=='member_expression':
            base=selector(fn.child_by_field_name('object'));prop=text(fn.child_by_field_name('property'))
            if base and prop=='find' and len(args)==1:
                value=literal(args[0]);return (value if base==':document' else base+' '+value) if value else None
            if base and prop=='get':return base
        return None
    def walk(node):
        if node.type=='identifier':names.add(text(node))
        value=selector(node)
        if value and value!=':document' and len(value)<=256:selectors.add(value)
        for child in node.named_children:walk(child)
    walk(root)
    if root.has_error or len(selectors)>64 or len(names)>128:
        raise ContextEvidenceError('Unsupported or oversized browser probe request')
    return sorted(selectors),sorted(names)


COLLECT = r'''({selectors,names,marker}) => {
 const jq=window.__contextBaselineJQ;
 const baseline=window.__contextBaselineMethods;
 const native=window.__contextBaselineNative;
 const nativeOK=native && native.query===Document.prototype.querySelectorAll && native.attribute===Element.prototype.getAttribute &&
   native.text===Object.getOwnPropertyDescriptor(Node.prototype,'textContent')?.get &&
   native.innerText===Object.getOwnPropertyDescriptor(HTMLElement.prototype,'innerText')?.get &&
   native.value===Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.get;
 const library=typeof jq==='function' && window.jQuery===jq && window.$===jq &&
   baseline && Object.entries(baseline).every(([k,v])=>jq.fn[k]===v);
 const permitted=new Set(['DIV','P','SPAN','A','AREA','INPUT','TEXTAREA','SELECT','OPTION','CITE','BUTTON','UL','LI','SECTION','ARTICLE','H1','H2','PRE','CODE','LABEL','FORM']);
 const receivers=[],inputs={},bindings={},nodes=[];
 const read=(el,field)=>field==='text'?jq(el).text():field==='html'?jq(el).html():field==='value'?jq(el).val():el[field];
 const inspect=(selector,el,count)=>{
   if(!el || !permitted.has(el.tagName) || el.hasAttribute('is') ||
      ['value','textContent','innerText','name'].some(f=>Object.getOwnPropertyDescriptor(el,f)))return;
   receivers.push(selector);const fields=[];
   for(const f of ['value','text','textContent','innerText','name','html']){
     try{if(read(el,f)===marker)fields.push(f);}catch{}
   }
   for(const a of el.attributes){if(a.value===marker)fields.push('attribute:'+a.name);}
   if(fields.length)inputs[selector]=[...new Set(fields)];
   nodes.push({selector,count,tag:el.tagName,controlled_fields:fields});
 };
 if(library && nativeOK){
   for(const selector of selectors){try{const list=document.querySelectorAll(selector);inspect(selector,list[0],list.length);}catch{}}
   const inert=el=>el.nodeType===Node.TEXT_NODE || el.nodeType===Node.ELEMENT_NODE &&
     ['CITE','SPAN','DIV','P','PRE','CODE'].includes(el.tagName) &&
     [...el.attributes].every(a=>['id','class'].includes(a.name)||a.name.startsWith('aria-')||a.name.startsWith('data-')) &&
     [...el.childNodes].every(inert);
   for(const name of names){
     const desc=Object.getOwnPropertyDescriptor(window,name);
     if(!desc || !('value' in desc))continue;
     const value=desc.value;
     if(!value || Object.getPrototypeOf(value)!==jq.fn || value.length!==1)continue;
     const el=value[0];if(!(el instanceof Element))continue;
     let selector=el.id?'#'+CSS.escape(el.id):el.tagName.toLowerCase();
     try{const matches=document.querySelectorAll(selector);if(matches.length!==1||matches[0]!==el)continue;
       inspect(selector,el,1);bindings[name]={selector,kind:'jquery',inert_node:inert(el)};
     }catch{}
   }
 }
 return {library_identity_verified:!!library,native_identity_verified:!!nativeOK,jquery_version:library?jq.fn.jquery:null,
   frame_url:location.href,receivers:[...new Set(receivers)],inputs,bindings,nodes};
}'''


class BrowserContextSession:
    def __init__(self,vendor_sha256,*,max_age_seconds=60):
        if not isinstance(vendor_sha256,str) or not re.fullmatch(r'[0-9a-f]{64}',vendor_sha256):
            raise ContextEvidenceError('Known vendor hash required')
        self.vendor_sha256=vendor_sha256
        self._key=secrets.token_bytes(32)
        self.session_id=secrets.token_hex(16)
        self.max_age_seconds=max_age_seconds
        self._used=set()

    def capture(self,frame,code,marker):
        selectors,names=selectors_and_names(code)
        observations=frame.evaluate(COLLECT,{'selectors':selectors,'names':names,'marker':marker})
        if observations.get('library_identity_verified') is not True or observations.get('native_identity_verified') is not True or observations.get('frame_url')!='http://audit.local/case':
            raise ContextEvidenceError('Known fixture library/frame identity was not verified')
        record={'schema':1,'session_id':self.session_id,'code_sha256':digest(code),
                'vendor_sha256':self.vendor_sha256,'marker_sha256':digest(marker),
                'captured_at':time.monotonic(),'observations':observations}
        record['signature']=hmac.new(self._key,canonical(record),hashlib.sha256).hexdigest()
        return record

    def context(self,code,record):
        if not isinstance(record,dict):raise ContextEvidenceError('Evidence packet required')
        data={k:v for k,v in record.items() if k!='signature'}
        expected=hmac.new(self._key,canonical(data),hashlib.sha256).hexdigest()
        signature=record.get('signature')
        if not isinstance(signature,str) or not hmac.compare_digest(signature,expected):
            raise ContextEvidenceError('Evidence integrity/authentication failed')
        if data.get('schema')!=1 or data.get('session_id')!=self.session_id or data.get('vendor_sha256')!=self.vendor_sha256 or data.get('code_sha256')!=digest(code):
            raise ContextEvidenceError('Evidence belongs to a different code/session/vendor')
        age=time.monotonic()-data['captured_at']
        if not 0<=age<=self.max_age_seconds:raise ContextEvidenceError('Evidence expired')
        if signature in self._used:raise ContextEvidenceError('Evidence was already consumed')
        observations=data['observations']
        context={'evidence_ref':'isolated-browser-entry-state:'+digest(canonical(data).decode()),
                 'jquery_globals':['$','jQuery'],'inputs':observations['inputs'],
                 'receivers':observations['receivers'],'bindings':observations['bindings']}
        validate_context(context)
        self._used.add(signature)
        return context

    def review(self,code,record):
        context=self.context(code,record)
        result=grounded_review(code,dom_context=context)
        result['context_evidence']={'integrity_verified':True,'session_id':self.session_id,
                                   'scope':'trusted-controller entry-state capture in an isolated fixture',
                                   'real_application_attacker_control_verified':False,
                                   'independent_review_verified':False}
        return result
