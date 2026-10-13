"""Offline JavaScript AST review. Never executes code or contacts a target.

Bounded local flow/helper analysis: unsupported syntax and unknown calls abstain.
SAFE means supported expressions at reviewed sinks, not whole-program safety.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import json
import re
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_javascript


@dataclass(frozen=True)
class Value:
    sources: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    sanitizer: str | None = None
    unknown: bool = False
    properties: tuple[tuple[str, "Value"], ...] = ()


def join(*values: Value) -> Value:
    return Value(
        tuple(sorted({s for v in values for s in v.sources})),
        tuple(dict.fromkeys(t for v in values for t in v.trace)),
        values[0].sanitizer if values and all(v.sanitizer == values[0].sanitizer for v in values) else None,
        any(v.unknown for v in values),
    )


class Analyzer:
    def __init__(self, code: str, trusted_modules: tuple[str, ...] = ()):
        self.code = code.encode()
        self.parser = Parser(Language(tree_sitter_javascript.language()))
        self.env: dict[str, Value] = {}
        self.bindings: dict[str, str] = {}
        self.trusted_modules = trusted_modules
        self.sinks: list[dict] = []
        self.observed_sources: set[str] = set()
        self.limitations: list[str] = []
        # Only literal createElement/querySelector bindings are type-proven.
        # Never infer an element's tag from a variable name like "script".
        self.dom_tags: dict[str, str] = {}
        self.functions: dict[str, object] = {}
        self.call_depth = 0
        self.active_functions: list[tuple[int, int]] = []
        self.helper_calls = 0
        self.loop_steps = 0
        self.counter_updates: set[tuple[int, int]] = set()
        self.deferred_callbacks: list[tuple] = []
        self.callback_capture_frame = None
        self.in_deferred_review = False

    def literal_string(self, node) -> str | None:
        # Escape sequences require JS decoding; abstain rather than compare
        # the raw spelling (e.g. '/\\x2f' is not a fixed-origin prefix).
        if node is None or node.type != "string":
            return None
        raw = self.text(node)
        return raw[1:-1] if "\\" not in raw else None

    def invalidate(self):
        self.dom_tags.clear()
        self.bindings.clear()
        self.functions.clear()
        self.env = {k: replace(v, unknown=True) for k, v in self.env.items()}

    def block(self, node):
        # All lexical declarations shadow from block entry (including TDZ).
        # Restore only block-local bindings; assignments to outer names survive.
        locals_ = set()
        start_limitations = len(self.limitations)
        for child in node.named_children:
            if child.type == "lexical_declaration":
                for decl in child.named_children:
                    name = self.field(decl, "name")
                    if name is not None and name.type == "identifier":
                        locals_.add(self.text(name))
            elif child.type == "function_declaration":
                locals_.add(self.text(self.field(child, "name")))
        maps = (self.env, self.bindings, self.dom_tags, self.functions)
        saved = [{k: m[k] for k in locals_ if k in m} for m in maps]
        for name in locals_:
            self.env[name] = Value(unknown=True)
            self.bindings.pop(name, None)
            self.dom_tags.pop(name, None)
            self.functions.pop(name, None)
        for child in node.named_children:
            if child.type == "function_declaration":
                self.register_function(child)
        for child in node.named_children:
            self.statement(child)
        # Unknown calls can invalidate outer identities even while hidden by
        # a local binding. A block must not resurrect these trusted identities.
        poisoned = len(self.limitations) > start_limitations
        for attr, prior in zip(("env", "bindings", "dom_tags", "functions"), saved):
            current = getattr(self, attr)
            for name in locals_:
                current.pop(name, None)
            if attr == "env":
                current.update({k: replace(v, unknown=True) if poisoned else v for k,v in prior.items()})
            elif not poisoned:
                current.update(prior)

    def register_function(self, node):
        name = self.text(self.field(node, "name"))
        self.env[name] = Value(unknown=True)
        self.functions[name] = node

    def pure_expression(self, node, local_names: set[str]) -> bool:
        if node is None:
            return False
        if node.type == "identifier":
            # A helper's closure must not accidentally read a caller's
            # same-named local binding. Unresolved free variables abstain.
            return self.text(node) in local_names
        if node.type in {"string", "number", "true", "false", "null", "undefined"}:
            return True
        if node.type in {"member_expression", "subscript_expression"}:
            path=self.path(node)
            return self.source(path) and path.split('.')[0] not in self.env
        if node.type in {"parenthesized_expression", "array", "object", "pair", "property_identifier"}:
            return all(self.pure_expression(c,local_names) for c in node.named_children)
        if node.type == "binary_expression":
            return self.text(self.field(node,"operator")) == "+" and all(self.pure_expression(c,local_names) for c in node.named_children)
        if node.type == "call_expression":
            call = self.path(self.field(node, "function"))
            args = self.field(node, "arguments")
            builtin = call in {"encodeURIComponent", "decodeURIComponent", "String"} and call not in self.env
            helper = call in self.functions and call not in local_names
            return ((builtin or helper) and args is not None
                    and len(args.named_children) <= 4
                    and (helper or len(args.named_children) == 1)
                    and all(self.pure_expression(arg,local_names) for arg in args.named_children))
        return False

    def local_call(self, node, fn, values) -> Value:
        params = self.field(fn, "parameters")
        body = self.field(fn, "body")
        args = params.named_children if params is not None else []
        statements = [c for c in body.named_children if c.type != "comment"] if body else []
        local_names={self.text(p) for p in args if p.type == "identifier"}
        for stmt in statements[:-1]:
            if stmt.type == "lexical_declaration":
                for decl in stmt.named_children:
                    ident=self.field(decl,"name") if decl.type == "variable_declarator" else None
                    if ident is not None and ident.type == "identifier":local_names.add(self.text(ident))
        identity=(fn.start_byte,fn.end_byte)
        supported = (len(args) <= 4 and len(args) == len(values)
                     and self.helper_calls < 64 and identity not in self.active_functions
                     and all(p.type == "identifier" for p in args)
                     and 1 <= len(statements) <= 12
                     and statements[-1].type == "return_statement"
                     and len(statements[-1].named_children) == 1
                     and self.pure_expression(statements[-1].named_children[0],local_names))
        for stmt in statements[:-1]:
            supported = supported and stmt.type == "lexical_declaration"
            for decl in stmt.named_children:
                name = self.field(decl,"name") if decl.type == "variable_declarator" else None
                supported = supported and name is not None and name.type == "identifier" and self.pure_expression(self.field(decl,"value"),local_names)
        if not supported:
            self.limitation(node,"local function exceeds bounded straight-line return review")
            self.invalidate()
            return join(*values,Value(unknown=True))
        saved = (dict(self.env),dict(self.bindings),dict(self.dom_tags),dict(self.functions))
        initial_limitations=len(self.limitations)
        self.call_depth += 1
        self.helper_calls += 1
        self.active_functions.append(identity)
        try:
            # Initialize the helper's locals at function entry, including TDZ,
            # and remove caller bindings with the same name before any read.
            for name in local_names:
                self.env[name]=Value(unknown=True)
                self.bindings.pop(name,None);self.dom_tags.pop(name,None);self.functions.pop(name,None)
            for param,value in zip(args,values):
                name=self.text(param)
                self.env[name]=replace(value,trace=value.trace+(name,))
                self.bindings.pop(name,None); self.dom_tags.pop(name,None); self.functions.pop(name,None)
            for stmt in statements[:-1]:
                self.statement(stmt)
            result=self.expression(statements[-1].named_children[0])
            return replace(result,trace=result.trace+(self.text(self.field(fn,'name'))+' return',))
        finally:
            self.call_depth -= 1
            self.active_functions.pop()
            self.env,self.bindings,self.dom_tags,self.functions=saved
            if len(self.limitations)>initial_limitations:self.invalidate()

    def html_composition(self, node) -> bool:
        # Preserve percent-encoding only at HTML text positions, never in
        # attributes, script/style bodies, or partially decoded/raw values.
        parts=[]; markers=[]
        def walk(n):
            if n.type == "binary_expression" and self.text(self.field(n,"operator")) == "+":
                return walk(self.field(n,"left")) and walk(self.field(n,"right"))
            literal=self.literal_string(n)
            if literal is not None:
                parts.append(literal); return True
            value=None
            if n.type == "identifier":
                value=self.env.get(self.text(n))
            elif n.type == "call_expression" and self.path(self.field(n,"function")) == "encodeURIComponent" and "encodeURIComponent" not in self.env:
                arguments=self.field(n,"arguments")
                if arguments and len(arguments.named_children)==1:
                    arg=arguments.named_children[0]
                    if arg.type == "identifier": value=self.env.get(self.text(arg))
                    elif self.source(self.path(arg)) and self.path(arg).split('.')[0] not in self.env: value=Value((self.path(arg),))
                    if value is not None and not value.unknown: value=replace(value,sanitizer="encodeURIComponent:html-markup")
            if value is None or value.unknown or value.sanitizer != "encodeURIComponent:html-markup": return False
            marker='XSSENCODEDMARKER'+str(len(markers))+'END'
            markers.append(marker); parts.append(marker); return True
        if not walk(node) or not markers: return False
        # Restrict the static skeleton to text and inert, attribute-free wrapper
        # tags. No HTML-parser/browser disagreement, raw-text or attr context
        # is generalized into an encoding guarantee.
        skeleton=''.join(parts)
        wrappers=r"div|span|article|section|p|strong|b|em|i|main|aside|br"
        return re.fullmatch(r"(?:[^<>]|</?(?:"+wrappers+r")\s*>)*",skeleton,re.I) is not None

    def text(self, node) -> str:
        return self.code[node.start_byte:node.end_byte].decode() if node else ""

    def limitation(self, node, message: str):
        self.limitations.append(f"line {node.start_point.row + 1}: {message}")
        # Unreviewed effects cannot preserve a function's previously known identity.
        self.functions.clear()

    def field(self, node, name):
        return node.child_by_field_name(name)

    def path(self, node) -> str:
        if node is None:
            return ""
        if node.type in ("identifier", "property_identifier"):
            return self.text(node)
        if node.type == "member_expression":
            return self.path(self.field(node, "object")) + "." + self.path(self.field(node, "property"))
        if node.type == "subscript_expression":
            index = self.field(node, "index")
            if index and index.type == "string":
                return self.path(self.field(node, "object")) + "." + self.text(index)[1:-1]
        return ""

    def source(self, path: str) -> bool:
        return path in {
            "location.hash", "location.search", "location.href",
            "window.location.hash", "window.location.search", "window.location.href",
            "document.URL", "document.documentURI", "document.referrer", "document.cookie",
            "document.location.hash", "document.location.search", "document.location.href",
            "window.name",
        } or any(path == p or path.startswith(p + ".") for p in ("req.query", "req.body", "req.params"))

    def recognized_dom_tag(self, node) -> str | None:
        """Literal DOM creator/selector only; dynamic selectors are unknown."""
        if node is None or node.type != "call_expression":
            return None
        fn = self.path(self.field(node, "function"))
        arguments = self.field(node, "arguments")
        args = arguments.named_children if arguments else []
        if len(args) != 1 or args[0].type != "string":
            return None
        literal = self.text(args[0])[1:-1].strip().lower()
        if fn.split('.')[0] in self.env:
            return None
        tags={"script", "a", "area", "iframe", "div", "span", "img", "p", "button"}
        if fn == "document.createElement" and literal in tags:
            return literal
        if fn == "document.querySelector" and literal in tags:
            return literal
        return None

    def callback(self, call_node, cb, *, source: str | None = None,
                 bound_value: Value | None = None) -> bool:
        """Review bounded callbacks with either event input or resolved Promise input.

        The event could arrive later; this only establishes potential static
        paths and is NEVER proof that browser execution occurred.
        """
        if cb is not None and cb.type == "identifier":
            # Only the still-known declaration is reviewable. Assignments,
            # branches and unknown effects invalidate this registry.
            cb=self.functions.get(self.text(cb))
        if cb is None or cb.type not in ("arrow_function", "function_expression", "function_declaration"):
            self.limitation(call_node, "callback body or function identity unresolved")
            return False
        param = self.field(cb, "parameter")
        params = self.field(cb, "parameters")
        if param is None and params is not None:
            candidates = params.named_children
            param = candidates[0] if len(candidates) == 1 else None
        if param is None:
            # Some tree-sitter versions expose the single arrow parameter
            # without a field name; there must be exactly one identifier.
            candidates = [c for c in cb.named_children if c.type == "identifier"]
            param = candidates[0] if len(candidates) == 1 else None
        body = self.field(cb, "body")
        destructured = False
        if param is not None and param.type == "object_pattern" and source == "message-event.data":
            properties = param.named_children
            if len(properties) == 1:
                item = properties[0]
                if item.type == "shorthand_property_identifier_pattern" and self.text(item) == "data":
                    param = item; destructured = True
                elif item.type == "pair_pattern" and self.text(self.field(item,"key")) == "data":
                    param = self.field(item,"value"); destructured = param is not None and param.type == "identifier"
        if param is None or (param.type != "identifier" and not destructured) or body is None:
            self.limitation(call_node, "callback parameter/body not resolvable")
            return False
        name = self.text(param)
        initial_sink_count=len(self.sinks)
        previous_env = dict(self.env)
        previous_bindings = dict(self.bindings)
        previous_tags = dict(self.dom_tags)
        previous_functions = dict(self.functions)
        initial_limitations = len(self.limitations)
        # A callback may execute after later assignments, or in a different
        # caller scope. Do not certify a captured constant/identity as safe.
        # Plain tracked taint still establishes a potential dangerous path.
        self.env={k:replace(v,unknown=v.unknown or not v.sources or bool(v.sanitizer) or bool(v.properties),
                            sanitizer=None,properties=()) for k,v in self.env.items()}
        self.bindings={};self.dom_tags={};self.functions={}
        # var declarations belong to the callback, including nested blocks;
        # declarations in a nested function belong to that nested function.
        callback_locals = {name}
        def collect_vars(n):
            for child in n.named_children:
                if child.type in {"function_declaration","function_expression","arrow_function"}: continue
                if child.type == "variable_declaration":
                    for decl in child.named_children:
                        ident=self.field(decl,"name")
                        if ident is not None and ident.type == "identifier":callback_locals.add(self.text(ident))
                collect_vars(child)
        collect_vars(body)
        for local in callback_locals:
            self.env[local]=Value(unknown=True)
            self.bindings.pop(local,None); self.dom_tags.pop(local,None); self.functions.pop(local,None)
        if bound_value is not None:
            self.observed_sources.update(bound_value.sources)
            self.env[name] = replace(bound_value,trace=bound_value.trace+(name,))
        elif source is not None:
            self.observed_sources.add(source)
            self.env[name] = Value((source,), (source, name))
        else:
            self.limitation(call_node, "callback input origin unknown")
            self.env[name] = Value(unknown=True)
        callback_initial_env=dict(self.env)
        previous_capture_frame=self.callback_capture_frame
        captures=set()
        self.callback_capture_frame=(callback_initial_env,callback_locals,captures)
        try:
            if body.type == "statement_block":
                self.statement(body)
            else:
                self.expression(body)
        finally:
            self.callback_capture_frame=previous_capture_frame
        # For a direct program-level registration, a global callback sees
        # later synchronous writes when the async turn runs. Review captures
        # after completing the program, never at registration-time values.
        parent=call_node.parent
        top_level=(parent is not None and parent.type == "expression_statement"
                   and parent.parent is not None and parent.parent.type == "program")
        global_definition=(cb.type != "function_declaration" or
                           cb.parent is not None and cb.parent.type == "program")
        if captures and top_level and global_definition and not self.in_deferred_review:
            if len(self.deferred_callbacks)<32:
                self.deferred_callbacks.append((call_node,cb,source,bound_value,initial_limitations))
                # Provisional closure paths must not count as separate alerts
                # or survive a later safe overwrite. Parameter-only callbacks
                # remain reviewed normally; final capture paths replace these.
                del self.sinks[initial_sink_count:]
            else:
                self.limitation(call_node,"deferred callback review exceeds 32 registrations")
                self.invalidate()
        # A callback runs asynchronously: writes to surrounding bindings may
        # happen before or after other statements, so they cannot be proven
        # safe. Preserve only the pre-registration local state with a warning.
        mutated = any(
            k in previous_env and self.env.get(k) != callback_initial_env.get(k)
            for k in self.env if k not in callback_locals
        )
        if mutated:
            self.limitation(call_node, "callback writes to outer state; scheduling is unresolved")
        self.env = previous_env
        self.bindings = previous_bindings
        self.dom_tags = previous_tags
        self.functions = previous_functions
        if mutated or len(self.limitations) > initial_limitations:
            self.invalidate()
        return True

    def sink(self, node, value: Value, context: str):
        # Exact imported identity AND an explicit audited-module policy are required.
        # Sanitizer/encoding identity is meaningful ONLY for compatible
        # output contexts. A text node is not a sanitizer and an encoded URL
        # component does not make JavaScript source safe.
        compatible = (
            context == "html" and
            value.sanitizer in {"dompurify:default-html",
                                "encodeURIComponent:html-markup"}
        ) or (context == "url" and value.sanitizer in {"fixed-relative-url", "fixed-navigation-url"})
        # A text-only DOM output API is never an HTML execution sink.
        # Preserve the input provenance even when the output is safe.
        verdict = "INCONCLUSIVE" if value.unknown else (
            "SAFE" if context == "text" else
            "CANDIDATE" if value.sources and not compatible else "SAFE"
        )
        self.sinks.append({
            "sink": self.text(node), "line": node.start_point.row + 1,
            "context": context, "sources": list(value.sources),
            "flow": list(value.trace) + [self.text(node)],
            "sanitizer": value.sanitizer, "sanitizer_compatible": compatible,
            "verdict": verdict, "confirmed": False,
        })

    def expression(self, node) -> Value:
        if node is None:
            return Value(unknown=True)
        kind = node.type
        if (node.start_byte,node.end_byte) in self.counter_updates:
            # Only validated top-level literal numeric increments in a
            # reviewed loop body are eligible; the loop owns their values.
            return Value()
        path = self.path(node)
        if self.source(path) and path.split('.')[0] not in self.env:
            self.observed_sources.add(path)
            return Value((path,), (path,))
        if self.source(path) and path.split('.')[0] in self.env:
            self.limitation(node,"source root is shadowed; browser identity unresolved")
            return Value(unknown=True)
        if kind in ("string", "number", "true", "false", "null", "undefined"):
            return Value()
        if kind == "identifier":
            if self.callback_capture_frame is not None:
                initial,locals_,captures=self.callback_capture_frame
                if path not in locals_ and (path not in self.env or
                    path in initial and self.env.get(path) is initial[path]):
                    captures.add(path)
            return self.env.get(path, Value(unknown=True))
        if kind in ("member_expression", "subscript_expression"):
            if path in self.env:
                return self.env[path]
            base = self.expression(self.field(node, "object"))
            if base.properties and not base.unknown:
                prop=self.field(node,"property") if kind == "member_expression" else self.field(node,"index")
                key=self.text(prop) if kind == "member_expression" else self.literal_string(prop)
                if key in dict(base.properties):
                    value=dict(base.properties)[key]
                    return replace(value,trace=value.trace+(path or self.text(node),))
                return Value(unknown=True)
            # A field of a tainted JSON object, URL wrapper, or similar
            # explicitly propagated container remains attacker-influenced.
            # We do not assert fields of untainted/unknown objects are safe.
            if base.sources and not base.unknown:
                return Value(base.sources, base.trace + (path or self.text(node),),
                             base.sanitizer if path.endswith(".href")
                             and base.sanitizer == "fixed-relative-url" else None,
                             unknown=False)
            return join(base, Value(unknown=True))
        if kind in ("array", "array_expression"):
            value = join(*(self.expression(child) for child in node.named_children))
            return Value(value.sources, value.trace + ("array_literal",),
                         unknown=value.unknown)
        if kind == "object":
            properties=[]
            for child in node.named_children:
                if child.type != "pair" or self.field(child,"key").type not in {"property_identifier","string"}:
                    self.limitation(node,"object getter/spread/computed property is unresolved")
                    self.invalidate();return Value(unknown=True)
                key_node=self.field(child,"key")
                key=self.literal_string(key_node) if key_node.type == "string" else self.text(key_node)
                if key is None or key in {"__proto__","constructor","prototype"}:
                    self.limitation(node,"object prototype semantics unresolved")
                    self.invalidate();return Value(unknown=True)
                properties.append((key,self.expression(self.field(child,"value"))))
            value=join(*(v for _,v in properties))
            return replace(value,properties=tuple(properties))
        if kind == "new_expression":
            ctor = self.path(self.field(node, "constructor"))
            params = self.field(node, "arguments")
            values = [self.expression(arg) for arg in params.named_children] if params else []
            if ctor in ("URL", "URLSearchParams") and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + ("new " + ctor,),
                             unknown=value.unknown)
            if ctor == "URL" and params and len(values) == 2:
                args = params.named_children
                origin = self.path(args[1])
                if (origin in ("location.origin", "window.location.origin")
                        and origin.split(".")[0] not in self.env
                        and "URL" not in self.env
                        and values[0].sanitizer == "fixed-relative-url"
                        and not values[0].unknown):
                    return Value(values[0].sources,
                                 values[0].trace + ("new URL relative origin",),
                                 "fixed-relative-url", unknown=False)
            if ctor == "Function":
                self.sink(node, values[0] if values else Value(unknown=True), "javascript")
                return Value(unknown=True)
            self.limitation(node, "unresolved constructor: " + (ctor or self.text(node)))
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
            return join(*values, Value(unknown=True))
        if kind == "parenthesized_expression":
            return self.expression(node.named_children[0])
        if kind == "template_string":
            values = [self.expression(c.named_children[0]) for c in node.named_children
                      if c.type == "template_substitution" and c.named_children]
            return join(*values)
        if kind == "binary_expression":
            left = self.expression(self.field(node, "left"))
            right = self.expression(self.field(node, "right"))
            # Composition invalidates sanitizer guarantees (including sanitized fragments).
            value = join(left, right)
            operator = self.text(self.field(node, "operator"))
            # Nullish coalescing with a known-safe literal does not erase
            # the possibility of tainted data taking the left branch.
            if operator not in ("+", "??"):
                self.limitation(node, "non-concatenation operator/control effects are not resolved")
                self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
                return join(value, Value(unknown=True))
            # A fixed, root-relative path followed by a single percent-encoded
            # value cannot create a javascript: scheme. Do not generalize this
            # policy to arbitrary concatenation, multiple raw values or other
            # URI contexts.
            if operator == "+":
                left_node = self.field(node, "left")
                literal = self.literal_string(left_node)
                relative = literal is not None and bool(re.match(r"(?:/[A-Za-z0-9_.~-]|\./|\.\./)",literal))
                # Keep the existing encoded URL-constructor protection narrow.
                if (relative and right.sanitizer == "encodeURIComponent:html-markup" and not value.unknown):
                    return Value(value.sources, value.trace,
                                 "fixed-relative-url", unknown=False)
                if literal is not None and not value.unknown and (
                    relative or re.match(r"https?://[A-Za-z0-9.-]+(?::[0-9]+)?/",literal)
                ):
                    return Value(value.sources,value.trace,"fixed-navigation-url")
                if not value.unknown and self.html_composition(node):
                    return Value(value.sources,value.trace,"encodeURIComponent:html-markup")
            return Value(value.sources, value.trace, unknown=value.unknown)
        if kind == "ternary_expression":
            # Conditions may contain assignments or sinks; inspect them too.
            self.expression(self.field(node, "condition"))
            value = join(self.expression(self.field(node, "consequence")),
                         self.expression(self.field(node, "alternative")))
            self.limitation(node, "conditional expression effects are not resolved")
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
            return join(value, Value(unknown=True))
        if kind in ("assignment_expression", "augmented_assignment_expression"):
            left = self.field(node, "left")
            name = self.path(left)
            if name == "window.onmessage" and "window" not in self.env:
                if self.callback(node,self.field(node,"right"),source="message-event.data"):
                    return Value()
            value = self.expression(self.field(node, "right"))
            if kind == "augmented_assignment_expression":
                combined = join(self.expression(left), value)
                value = Value(combined.sources, combined.trace, unknown=combined.unknown)
            suffix = name.rsplit(".", 1)[-1]
            if suffix in ("innerHTML", "outerHTML", "srcdoc"):
                self.sink(left, value, "html")
            elif suffix in ("textContent", "innerText"):
                self.sink(left, value, "text")
            elif suffix in ("href", "src"):
                obj = self.field(left, "object")
                owner = self.path(obj)
                tag = self.dom_tags.get(owner) or self.recognized_dom_tag(obj)
                is_location = name in ("location.href", "window.location.href",
                                       "document.location.href")
                if suffix == "href" and (is_location or tag in {"a","area"}):
                    self.sink(left, value, "url")
                elif suffix == "href" and tag in {"div","span","img","p","button"}:
                    self.sink(left,value,"text")
                elif suffix == "src" and tag == "script":
                    self.sink(left, value, "remote_script")
                else:
                    self.limitation(left, "untyped href/src destination requires DOM element identity")
                    self.env = {k: join(v, Value(unknown=True)) for k,v in self.env.items()}
            elif left.type == "identifier":
                self.dom_tags.pop(name, None)
                self.bindings.pop(name, None)
                self.functions.pop(name, None)
                self.env[name] = replace(value,trace=value.trace+(name,))
            else:
                self.limitation(left, "object mutation/aliasing is not resolved")
                self.bindings.clear()
                self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
            return value
        if kind == "call_expression":
            function = self.field(node, "function")
            call = self.path(function)
            args_node = self.field(node, "arguments")
            args = args_node.named_children if args_node else []
            if call in ("window.eval", "window.setTimeout", "window.setInterval") and "window" in self.env:
                self.limitation(node, "shadowed window API; execution semantics unknown")
                return Value(unknown=True)
            # Don't evaluate a callback lambda as an ordinary expression:
            # doing that incorrectly poisons the environment before the
            # handler can be inspected.
            if call in ("addEventListener", "window.addEventListener"):
                if (call == "addEventListener" and "addEventListener" in self.env) or (
                        call == "window.addEventListener" and "window" in self.env):
                    self.limitation(node, "event listener API is shadowed")
                    return Value(unknown=True)
                options_ok=(len(args)==2 or (len(args)==3 and args[2].type in {"true","false"}))
                if (options_ok and self.text(args[0]) in ("'message'", '"message"')
                        and self.callback(node, args[1], source="message-event.data")):
                    return Value()
                self.limitation(node, "unresolved event listener/callback")
                return Value(unknown=True)
            if function.type == "member_expression":
                obj = self.field(function, "object")
                prop = self.path(self.field(function, "property"))
                if (prop == "then" and len(args) == 1
                        and obj is not None and obj.type == "call_expression"
                        and self.path(self.field(obj, "function")) == "Promise.resolve"
                        and "Promise" not in self.env):
                    previous = self.expression(obj)
                    if self.callback(node, args[0], bound_value=previous):
                        return Value()
                    return Value(unknown=True)
            if (call in ("setTimeout", "setInterval", "window.setTimeout",
                         "window.setInterval") and args
                    and args[0].type in ("arrow_function", "function_expression")):
                self.limitation(node, "timer function callback not statically resolved")
                return Value(unknown=True)
            values = [self.expression(a) for a in args]
            if call in self.functions:
                return self.local_call(node,self.functions[call],values)
            # Narrow, audited taint-preserving operations. These are NOT
            # sanitizers and never prove a dangerous sink safe.
            if call in ("decodeURIComponent", "decodeURI", "encodeURIComponent",
                        "encodeURI", "String", "JSON.stringify", "JSON.parse",
                        "URLSearchParams") and len(values) == 1:
                if call.split('.')[0] in self.env:
                    self.limitation(node,"transform API is shadowed")
                    self.invalidate();return join(*values,Value(unknown=True))
                value = values[0]
                # Percent-encoding an entire untrusted value prevents forming
                # HTML delimiters in direct HTML parser text insertion. This
                # is NOT suitable for JS/URL schemes, and loses its protection
                # if later decoded or combined with raw untrusted data.
                encoder = (
                    "encodeURIComponent:html-markup"
                    if call == "encodeURIComponent" and not value.unknown
                    else None
                )
                return Value(value.sources, value.trace + (call,),
                             encoder, value.unknown)
            if call == "document.createElement" and self.recognized_dom_tag(node):
                return Value()
            if call == "document.querySelector" and self.recognized_dom_tag(node):
                return Value()
            if call in ("console.log", "console.info", "console.warn",
                        "console.error", "console.debug") and "console" not in self.env:
                # Browser console methods read their arguments but do not
                # normally mutate lexical bindings. Reject shadowed aliases.
                return Value()
            if call == "Promise.resolve" and len(values) == 1 and "Promise" not in self.env:
                value = values[0]
                return Value(value.sources, value.trace + ("Promise.resolve",),
                             value.sanitizer, value.unknown)
            if call == "document.createTextNode" and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + (call,),
                             "dom-text-node" if not value.unknown else None,
                             value.unknown)
            if function.type == "member_expression":
                obj = self.field(function, "object")
                prop = self.path(self.field(function, "property"))
                if prop in ("slice", "substring", "trim", "toString", "split") and not values:
                    # trim/toString may be argument-free; slice/substring
                    # also accept numeric position arguments, checked below.
                    receiver = self.expression(obj)
                    return Value(receiver.sources, receiver.trace + (prop,),
                                 unknown=receiver.unknown)
                if prop in ("slice", "substring", "trim", "toString", "split"):
                    if all(a.type in ("number", "string") for a in args):
                        receiver = self.expression(obj)
                        return Value(receiver.sources, receiver.trace + (prop,),
                                     unknown=receiver.unknown)
                if prop in ("get", "getAll") and obj.type in ("new_expression", "member_expression", "call_expression"):
                    receiver = self.expression(obj)
                    return Value(receiver.sources, receiver.trace + (prop,),
                                 unknown=receiver.unknown)
                if prop == "join" and obj.type in ("identifier", "array", "array_expression"):
                    receiver = self.expression(obj)
                    if all(a.type == "string" for a in args):
                        return Value(receiver.sources, receiver.trace + ("join",),
                                     unknown=receiver.unknown)
            if call in ("document.write", "document.writeln", "res.send"):
                self.sink(function, join(*values), "html")
                return Value(unknown=True)
            if call.endswith(".insertAdjacentHTML") and len(values) == 2:
                self.sink(function, values[1], "html")
                return Value(unknown=True)
            if call.endswith(".insertAdjacentText") and len(values) == 2:
                self.sink(function, values[1], "text")
                return Value(unknown=True)
            if (call.endswith(".replaceChildren") and values
                    and all(v.sanitizer == "dom-text-node" and not v.unknown
                            for v in values)):
                self.sink(function, join(*values), "text")
                return Value(unknown=True)
            if (call.endswith(".appendChild") and len(values) == 1 and
                    values[0].sanitizer == "dom-text-node" and
                    not values[0].unknown):
                # Only an explicitly tracked Text node is proven inert;
                # arbitrary appendChild nodes can execute as scripts.
                self.sink(function, values[0], "text")
                return Value(unknown=True)
            if call.endswith(".setAttribute") and len(args) == 2:
                attr = self.text(args[0]).strip()
                if len(attr) >= 2 and attr[0] in ("'", '"') and attr[-1] == attr[0]:
                    key = attr[1:-1].lower()
                    if key.startswith("on") and len(key) > 2:
                        self.sink(function, values[1], "javascript")
                        return Value(unknown=True)
                    if key == "href":
                        receiver=self.field(function,"object")
                        tag=self.dom_tags.get(self.path(receiver)) or self.recognized_dom_tag(receiver)
                        if tag in {"a","area"}: self.sink(function,values[1],"url")
                        elif tag in {"div","span","img","p","button"}: self.sink(function,values[1],"text")
                        else:self.limitation(node,"href attribute requires a proven DOM element kind")
                        return Value(unknown=True)
                    if key == "src":
                        receiver = self.field(function, "object")
                        owner = self.path(receiver)
                        tag = self.dom_tags.get(owner) or self.recognized_dom_tag(receiver)
                        if tag == "script":
                            self.sink(function, values[1], "remote_script")
                            return Value(unknown=True)
                    if (key in {"title", "alt", "class", "id", "role"}
                            or key.startswith("aria-") or
                            (key.startswith("data-") and len(key) > 5)):
                        self.sink(function, values[1], "text")
                        return Value(unknown=True)
                # Dynamic attributes/URLs require context-aware review.
                self.limitation(node, "attribute name/context not safely resolved")
                return Value(unknown=True)
            if call in ("eval", "window.eval", "setTimeout", "setInterval",
                        "window.setTimeout", "window.setInterval"):
                self.sink(function, values[0] if values else Value(unknown=True), "javascript")
                return Value(unknown=True)
            owner = call.removesuffix(".sanitize")
            if call.endswith(".sanitize") and owner in self.bindings and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + (call,), self.bindings[owner], value.unknown)
            self.limitation(node, f"unresolved call: {call or self.text(function)}")
            # Unknown calls can mutate objects or overwrite bindings through closures.
            self.invalidate()
            return join(*values, Value(unknown=True))
        self.limitation(node, f"unsupported expression: {kind}")
        self.dom_tags.clear()
        self.bindings.clear()
        self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
        return Value(unknown=True)

    def statement(self, node):
        kind = node.type
        if kind == "statement_block":
            self.block(node)
        elif kind == "program":
            for child in node.named_children:
                if child.type == "function_declaration":self.register_function(child)
            for child in node.named_children:
                self.statement(child)
        elif kind == "function_declaration":
            # Registered at scope entry, matching JavaScript hoisting.
            return
        elif kind == "comment":
            return
        elif kind == "import_statement":
            source = self.field(node, "source")
            module = self.text(source)[1:-1]
            clause = next((c for c in node.named_children if c.type == "import_clause"), None)
            if module == "dompurify" and module in self.trusted_modules and clause:
                identifiers = [c for c in clause.named_children if c.type == "identifier"]
                if len(identifiers) == 1:
                    self.bindings[self.text(identifiers[0])] = "dompurify:default-html"
        elif kind in ("lexical_declaration", "variable_declaration"):
            for declaration in node.named_children:
                if declaration.type != "variable_declarator":
                    continue
                name = self.field(declaration, "name")
                value = self.expression(self.field(declaration, "value"))
                if name.type != "identifier":
                    self.limitation(name, "destructuring is not resolved")
                    continue
                key = self.text(name)
                self.bindings.pop(key, None)
                self.functions.pop(key, None)
                tag = self.recognized_dom_tag(self.field(declaration, "value"))
                self.dom_tags.pop(key, None)
                if tag is not None:
                    self.dom_tags[key] = tag
                self.env[key] = replace(value,trace=value.trace+(key,))
        elif kind == "expression_statement":
            for child in node.named_children:
                self.expression(child)
        elif kind == "if_statement":
            self.expression(self.field(node, "condition"))
            initial = dict(self.env)
            initial_bindings = dict(self.bindings)
            initial_tags = dict(self.dom_tags)
            initial_functions = dict(self.functions)
            self.statement(self.field(node, "consequence"))
            consequence, consequence_bindings = dict(self.env), dict(self.bindings)
            consequence_tags = dict(self.dom_tags)
            consequence_functions = dict(self.functions)
            self.env, self.bindings, self.dom_tags = (
                dict(initial), dict(initial_bindings), dict(initial_tags)
            )
            self.functions = dict(initial_functions)
            alternative = self.field(node, "alternative")
            if alternative:
                self.statement(alternative)
            other = self.env
            self.env = {k: join(consequence.get(k, Value(unknown=True)), other.get(k, Value(unknown=True)))
                        for k in consequence.keys() | other.keys()}
            self.bindings = {k: v for k, v in consequence_bindings.items() if self.bindings.get(k) == v}
            self.dom_tags = {k: v for k, v in consequence_tags.items() if self.dom_tags.get(k) == v}
            self.functions = {k: v for k, v in consequence_functions.items() if self.functions.get(k) == v}
        elif kind == "else_clause":
            for child in node.named_children:
                self.statement(child)
        elif kind == "for_statement":
            # Execute only literal, monotonically increasing numeric loops.
            # This is a bounded AST walk, not arbitrary JavaScript execution.
            code = self.text(node)
            header = re.match(
                r"for\s*\(\s*(?:let|var)\s+([A-Za-z_$][\w$]*)"
                r"\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\d+)\s*;"
                r"\s*(?:\1\s*\+\+|\+\+\s*\1)\s*\)",
                code,
            )
            body = self.field(node, "body")
            if header is None or body is None:
                self.limitation(node, "loop effects/iteration count not statically bounded")
                self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
                self.bindings.clear()
                self.dom_tags.clear()
                return
            variable, initial, limit = header.group(1), int(header.group(2)), int(header.group(3))
            # Literal top-level body increments can be combined with the
            # header's ++. Conditional/dynamic writes and shadowed counters
            # do not establish a numerical bound.
            updates=set()
            stride=1
            body_statements=body.named_children if body.type == "statement_block" else [body]
            for stmt in body_statements:
                if stmt.type != "expression_statement" or len(stmt.named_children)!=1:continue
                expr=stmt.named_children[0]
                target=self.field(expr,"left") or self.field(expr,"argument")
                if self.path(target)!=variable:continue
                operator=self.text(self.field(expr,"operator"))
                amount=None
                if expr.type == "update_expression" and operator == "++":amount=1
                if expr.type == "augmented_assignment_expression" and operator == "+=":
                    right=self.field(expr,"right")
                    if right is not None and right.type == "number" and re.fullmatch(r"[0-9]+",self.text(right)):
                        amount=int(self.text(right))
                if amount is not None and 1<=amount<=8:
                    stride+=amount;updates.add((expr.start_byte,expr.end_byte))
            def unresolved_counter_effect(n):
                if n.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
                    target=self.field(n,"left") or self.field(n,"argument")
                    if self.path(target) == variable and (n.start_byte,n.end_byte) not in updates:return True
                if n.type == "variable_declarator" and self.path(self.field(n,"name")) == variable:return True
                if updates and n.type in {"call_expression","new_expression"}:
                    # Arbitrary synchronous code may mutate the counter via
                    # a closure or direct eval. Do not assume independence.
                    return True
                return any(unresolved_counter_effect(c) for c in n.named_children)
            if unresolved_counter_effect(body):
                self.limitation(node,"loop counter is mutated in body; iteration bound unresolved")
                self.invalidate();return
            iterations = max(0, (limit - initial + stride - 1)//stride)
            if iterations > 8:
                self.limitation(node, "loop exceeds conservative eight-iteration bound")
                self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
                self.bindings.clear()
                self.dom_tags.clear()
                return
            saved={attr:getattr(self,attr).get(variable) for attr in ('env','bindings','dom_tags','functions')}
            initial_limitations=len(self.limitations)
            for attr in ('bindings','dom_tags','functions'):getattr(self,attr).pop(variable,None)
            self.env[variable] = Value()  # The header is a numeric local.
            prior_updates=set(self.counter_updates)
            self.counter_updates.update(updates)
            try:
                for _ in range(iterations):
                    if self.loop_steps>=64:
                        self.limitation(node,"nested loop review exceeds 64 total iterations")
                        self.invalidate();return
                    self.loop_steps+=1
                    self.statement(body)
            finally:
                self.counter_updates=prior_updates
            if re.match(r"for\s*\(\s*var\b",code):
                self.env[variable] = Value(unknown=True)
                self.bindings.pop(variable,None);self.dom_tags.pop(variable,None);self.functions.pop(variable,None)
            else:
                for attr,old in saved.items():
                    current=getattr(self,attr);current.pop(variable,None)
                    if old is not None:
                        if attr == 'env':current[variable]=replace(old,unknown=True) if len(self.limitations)>initial_limitations else old
                        elif len(self.limitations)==initial_limitations:current[variable]=old
        else:
            self.limitation(node, f"unsupported statement: {kind}")
            # Never carry a SAFE value through unanalysed side effects/control flow.
            self.dom_tags.clear()
            self.bindings.clear()
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}

    def run(self) -> dict:
        root = self.parser.parse(self.code).root_node
        if root.has_error:
            self.limitations.append("parse error: only JavaScript is supported (no HTML/TS/JSX)")
        else:
            self.statement(root)
            synchronous_limitations=len(self.limitations)
            self.in_deferred_review=True
            for call,cb,source,bound_value,registration_limitations in self.deferred_callbacks:
                # An unknown effect can remove a listener or alter callback
                # scheduling. A later known value assignment does not restore
                # evidence that the registered callback remains reachable.
                if synchronous_limitations>registration_limitations:
                    self.limitation(call,"deferred callback reachability affected by unsupported effects")
                    continue
                self.callback(call,cb,source=source,bound_value=bound_value)
            self.in_deferred_review=False
        verdicts = {s["verdict"] for s in self.sinks}
        verdict = "CANDIDATE" if "CANDIDATE" in verdicts else (
            "INCONCLUSIVE" if self.limitations or "INCONCLUSIVE" in verdicts or not self.sinks else "SAFE"
        )
        return {"engine": "xss-taint-v1", "verdict": verdict, "confirmed": False,
                "requires_oracle": verdict != "SAFE", "sinks": self.sinks,
                "limitations": list(dict.fromkeys(self.limitations)),
                "scope": "bounded local JavaScript flow and helper review",
                "observed_sources": sorted(self.observed_sources),
                "trusted_modules": list(self.trusted_modules)}


def analyze(code: str, *, trusted_modules: tuple[str, ...] = (), risk_scores: dict | None = None) -> dict:
    result = Analyzer(code, trusted_modules).run()
    # Advisory routing never changes static verdict or skips sink review.
    result["risk_router"] = risk_scores
    result["review_priority"] = "high" if result["verdict"] == "CANDIDATE" else "normal"
    if risk_scores and risk_scores.get("XSS", 0) >= 0.85:
        result["review_priority"] = "high"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Local JavaScript file; no URL inputs")
    parser.add_argument("--trusted-module", action="append", default=[],
                        help="Audited dependency identity; currently supports dompurify default HTML only")
    parser.add_argument("--relation-model", type=Path, help="Optional advisory JSON flow-relation model")
    parser.add_argument("--relation-record", type=Path, help="Reviewed relation spans bound to the input SHA256")
    args = parser.parse_args()
    if bool(args.relation_model) != bool(args.relation_record):
        parser.error("--relation-model and --relation-record must be provided together")
    code = args.file.read_text()
    result = analyze(code, trusted_modules=tuple(args.trusted_module))
    if args.relation_model:
        import hashlib
        from xss_specialist.flow_relations import FlowRelationAdvisor, advise_review
        record = json.loads(args.relation_record.read_text())
        if record.get("snippet_sha256") != hashlib.sha256(code.encode()).hexdigest():
            parser.error("relation record is not bound to this JavaScript input")
        result = advise_review(result, FlowRelationAdvisor(args.relation_model).predict(record))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
