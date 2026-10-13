"""Explicit DOM/library assumptions for conditional, bounded static review.

The caller supplies independently checked identities and input trust. Metadata
validation does not certify those assertions. No name-only jQuery inference.
"""
from dataclasses import dataclass
import hashlib
import json
import re

from xss_specialist.taint import Analyzer, Value


@dataclass(frozen=True)
class DomValue(Value):
    selector: str = ''
    dom_kind: str = ''
    inert_node: bool = False


def validate_context(context):
    if not isinstance(context, dict) or not isinstance(context.get('evidence_ref'), str) or not context['evidence_ref'].strip():
        raise ValueError('DOM context requires an evidence reference')
    if set(context) - {'evidence_ref', 'jquery_globals', 'inputs', 'bindings', 'receivers'}:
        raise ValueError('Unknown DOM context fields')
    globals_ = context.get('jquery_globals', [])
    inputs = context.get('inputs', {})
    bindings = context.get('bindings', {})
    receivers = context.get('receivers', [])
    if not isinstance(receivers, list) or any(not isinstance(s,str) or not s for s in receivers):
        raise ValueError('Invalid known DOM receivers')
    identifier = r'[A-Za-z_$][A-Za-z0-9_$]*'
    if not isinstance(globals_, list) or any(not isinstance(n, str) or not re.fullmatch(identifier, n) for n in globals_) or len(set(globals_)) != len(globals_):
        raise ValueError('Invalid jQuery global identities')
    allowed = {'value', 'text', 'textContent', 'innerText', 'html', 'name'}
    if not isinstance(inputs, dict) or not isinstance(bindings, dict):
        raise ValueError('Invalid DOM context maps')
    for selector, reads in inputs.items():
        if not isinstance(selector, str) or not selector or not isinstance(reads, list) or not reads:
            raise ValueError('Invalid input selector/reads')
        if any(not isinstance(f, str) or not (f in allowed or re.fullmatch(r'attribute:[A-Za-z_:][A-Za-z0-9_:.-]*', f)) for f in reads):
            raise ValueError('Invalid DOM read operation')
    for name, binding in bindings.items():
        if not isinstance(name, str) or not re.fullmatch(identifier, name) or not isinstance(binding, dict) or set(binding) - {'selector', 'kind', 'inert_node'}:
            raise ValueError('Invalid external DOM binding')
        if not isinstance(binding.get('selector'), str) or not binding['selector'] or binding.get('kind') not in {'dom', 'jquery'} or not isinstance(binding.get('inert_node', False), bool):
            raise ValueError('Invalid typed DOM binding')
    # Copy nested caller data: a later mutation cannot change the running policy.
    return {'evidence_ref': context['evidence_ref'], 'jquery_globals': tuple(globals_),
            'inputs': {k: tuple(v) for k,v in inputs.items()},
            'receivers': tuple(receivers),
            'bindings': {k: dict(v) for k,v in bindings.items()}}


class DomAnalyzer(Analyzer):
    def __init__(self, code, trusted_modules=(), *, dom_context):
        super().__init__(code, trusted_modules)
        self.context = validate_context(dom_context)
        self.context_active = True

    def known_selector(self, selector):
        return selector in self.context['inputs'] or selector in self.context['receivers']

    def callback(self, *args, **kwargs):
        # Entry-time DOM identity/input assertions cannot be extended into an
        # asynchronous turn after arbitrary later writes or listener changes.
        self.context_active=False
        return super().callback(*args, **kwargs)

    def invalidate(self):
        self.context_active = False
        super().invalidate()

    def resolve_dom(self, node):
        if node is None or not self.context_active:
            return None
        if node.type == 'parenthesized_expression' and len(node.named_children) == 1:
            return self.resolve_dom(node.named_children[0])
        if node.type == 'identifier':
            name = self.text(node)
            if name in self.env:
                value = self.env[name]
                return value if isinstance(value, DomValue) and not value.unknown else None
            binding = self.context['bindings'].get(name)
            if binding:
                return DomValue(selector=binding['selector'], dom_kind=binding['kind'], inert_node=binding.get('inert_node', False))
            return None
        if node.type == 'subscript_expression':
            base = self.resolve_dom(self.field(node, 'object'))
            index = self.text(self.field(node, 'index'))
            if base and base.dom_kind in {'jquery', 'collection'} and index=='0':
                return DomValue(selector=base.selector, dom_kind='dom', inert_node=base.inert_node)
            return None
        if node.type != 'call_expression':
            return None
        fn = self.field(node, 'function')
        args_node = self.field(node, 'arguments')
        args = [n for n in args_node.named_children if n.type!='comment'] if args_node else []
        call = self.path(fn)
        if fn.type == 'identifier' and call in self.context['jquery_globals'] and call not in self.env and len(args)==1:
            selector = self.literal_string(args[0])
            if selector and not selector.lstrip().startswith('<') and self.known_selector(selector):
                return DomValue(selector=selector, dom_kind='jquery')
            if self.path(args[0]) == 'document' and 'document' not in self.env:
                return DomValue(selector=':document', dom_kind='jquery')
        if call in {'document.getElementById', 'document.querySelector', 'document.querySelectorAll'} and 'document' not in self.env and len(args)==1:
            selector = self.literal_string(args[0])
            if selector:
                if call=='document.getElementById': selector='#'+selector
                if self.known_selector(selector):
                    return DomValue(selector=selector, dom_kind='collection' if call.endswith('All') else 'dom')
        if fn.type == 'member_expression':
            receiver = self.resolve_dom(self.field(fn, 'object'))
            prop = self.text(self.field(fn, 'property'))
            if receiver and receiver.dom_kind=='jquery':
                if prop=='get' and len(args)==1 and self.text(args[0])=='0':
                    return DomValue(selector=receiver.selector, dom_kind='dom', inert_node=receiver.inert_node)
                if prop=='find' and len(args)==1:
                    selector=self.literal_string(args[0])
                    if selector:
                        selector=selector if receiver.selector==':document' else receiver.selector+' '+selector
                        if self.known_selector(selector):
                            return DomValue(selector=selector, dom_kind='jquery')
        return None

    def read_dom(self, node, receiver, field):
        if field not in self.context['inputs'].get(receiver.selector, ()):
            return Value(unknown=True)
        source='DOM_CONTEXT['+receiver.selector+'].'+field
        self.observed_sources.add(source)
        return Value((source,), (self.text(node),))

    def contextual_expression(self, node):
        if node is None or not self.context_active:
            return None
        if node.type in {'identifier', 'call_expression', 'subscript_expression', 'parenthesized_expression'}:
            identity=self.resolve_dom(node)
            if identity is not None:
                return identity
        if node.type=='member_expression':
            receiver=self.resolve_dom(self.field(node,'object'))
            field=self.text(self.field(node,'property'))
            if receiver and receiver.dom_kind=='dom' and field in {'value','textContent','innerText','name'}:
                return self.read_dom(node,receiver,field)
        if node.type!='call_expression':
            return None
        fn=self.field(node,'function')
        if fn.type!='member_expression':
            return None
        receiver=self.resolve_dom(self.field(fn,'object'))
        if receiver is None:
            return None
        prop=self.text(self.field(fn,'property'))
        args=[n for n in self.field(node,'arguments').named_children if n.type!='comment']
        if receiver.dom_kind=='dom' and prop=='getAttribute' and len(args)==1:
            key=self.literal_string(args[0])
            return self.read_dom(node,receiver,'attribute:'+key) if key else None
        if receiver.dom_kind!='jquery':
            return None
        if prop in {'val','text','html'} and not args:
            return self.read_dom(node,receiver,'value' if prop=='val' else prop)
        if prop in {'attr','prop'} and len(args)==1:
            key=self.literal_string(args[0])
            return self.read_dom(node,receiver,('attribute:' if prop=='attr' else '')+key) if key else None
        if prop in {'html','text','val'} and len(args)==1:
            value=self.expression(args[0])
            self.sink(fn,value,'html' if prop=='html' else 'text')
            # A write changes the entry-time input assertions. HTML may also
            # execute code. Do not resurrect the original selector trust.
            self.context_active=False
            return Value(unknown=True)  # Do not reuse setter receiver identity.
        if prop=='attr' and len(args)==2:
            key=self.literal_string(args[0])
            if key and (key.startswith('data-') or key.startswith('aria-') or key in {'title','alt','class','id','role','name','value'}):
                self.sink(fn,self.expression(args[1]),'text')
                self.context_active=False
                return Value(unknown=True)
        if prop in {'append','prepend'} and len(args)==1:
            value=self.resolve_dom(args[0])
            if value and value.inert_node:
                self.sink(fn,Value(),'text')
                self.context_active=False
                return Value(unknown=True)
        return None

    def expression(self,node):
        before=len(self.limitations)
        value=self.contextual_expression(node)
        if value is None:
            value=super().expression(node)
        if node is not None and node.type in {'assignment_expression','augmented_assignment_expression'}:
            left=self.field(node,'left')
            if left is not None and left.type=='member_expression' and self.resolve_dom(self.field(left,'object')) is not None:
                self.context_active=False
        if len(self.limitations)>before:
            self.context_active=False
        return value

    def run(self):
        result=super().run()
        result['dom_context']={'evidence_ref':self.context['evidence_ref'],
                               'context_sha256':hashlib.sha256(json.dumps(self.context,sort_keys=True).encode()).hexdigest(),
                               'verified_by_engine':False,
                               'scope':'conditional on caller-supplied DOM/library identity and input-control assertions'}
        return result
