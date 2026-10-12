"""Offline JavaScript AST review. Never executes code or contacts a target.

Bounded intraprocedural analysis: unsupported syntax and unknown calls abstain.
SAFE means supported expressions at reviewed sinks, not whole-program safety.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
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

    def text(self, node) -> str:
        return self.code[node.start_byte:node.end_byte].decode() if node else ""

    def limitation(self, node, message: str):
        self.limitations.append(f"line {node.start_point.row + 1}: {message}")

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
        if fn == "document.createElement" and literal in {"script", "a", "iframe"}:
            return literal
        if fn == "document.querySelector" and literal in {"script", "a", "iframe"}:
            return literal
        return None

    def callback(self, call_node, cb, *, source: str) -> bool:
        """Review a bounded callback body under a known untrusted event source.

        The event could arrive later; this only establishes potential static
        paths and is NEVER proof that browser execution occurred.
        """
        if cb is None or cb.type not in ("arrow_function", "function_expression"):
            self.limitation(call_node, "callback body or function identity unresolved")
            return False
        param = self.field(cb, "parameter")
        params = self.field(cb, "parameters")
        if param is None and params is not None:
            candidates = [c for c in params.named_children if c.type == "identifier"]
            param = candidates[0] if len(candidates) == 1 else None
        if param is None:
            # Some tree-sitter versions expose the single arrow parameter
            # without a field name; there must be exactly one identifier.
            candidates = [c for c in cb.named_children if c.type == "identifier"]
            param = candidates[0] if len(candidates) == 1 else None
        body = self.field(cb, "body")
        if param is None or param.type != "identifier" or body is None:
            self.limitation(call_node, "callback parameter/body not resolvable")
            return False
        name = self.text(param)
        previous_env = dict(self.env)
        previous_bindings = dict(self.bindings)
        previous_tags = dict(self.dom_tags)
        self.observed_sources.add(source)
        self.env[name] = Value((source,), (source, name))
        if body.type == "statement_block":
            self.statement(body)
        else:
            self.expression(body)
        # A callback runs asynchronously: writes to surrounding bindings may
        # happen before or after other statements, so they cannot be proven
        # safe. Preserve only the pre-registration local state with a warning.
        mutated = any(
            k in previous_env and self.env.get(k) != previous_env[k]
            for k in self.env if k != name
        )
        if mutated:
            self.limitation(call_node, "callback writes to outer state; scheduling is unresolved")
        self.env = previous_env
        self.bindings = previous_bindings
        self.dom_tags = previous_tags
        if mutated:
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
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
        ) or (context == "url" and value.sanitizer == "fixed-relative-url")
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
        path = self.path(node)
        if self.source(path) and path.split('.')[0] not in self.env:
            self.observed_sources.add(path)
            return Value((path,), (path,))
        if kind in ("string", "number", "true", "false", "null", "undefined"):
            return Value()
        if kind == "identifier":
            return self.env.get(path, Value(unknown=True))
        if kind in ("member_expression", "subscript_expression"):
            if path in self.env:
                return self.env[path]
            base = self.expression(self.field(node, "object"))
            # A field of a tainted JSON object, URL wrapper, or similar
            # explicitly propagated container remains attacker-influenced.
            # We do not assert fields of untainted/unknown objects are safe.
            if base.sources and not base.unknown:
                return Value(base.sources, base.trace + (path or self.text(node),),
                             unknown=False)
            return join(base, Value(unknown=True))
        if kind in ("array", "array_expression"):
            value = join(*(self.expression(child) for child in node.named_children))
            return Value(value.sources, value.trace + ("array_literal",),
                         unknown=value.unknown)
        if kind == "new_expression":
            ctor = self.path(self.field(node, "constructor"))
            params = self.field(node, "arguments")
            values = [self.expression(arg) for arg in params.named_children] if params else []
            if ctor in ("URL", "URLSearchParams") and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + ("new " + ctor,),
                             unknown=value.unknown)
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
                literal = self.text(left_node)
                if (left_node is not None and left_node.type == "string"
                        and literal.startswith(("'/", '"/'))
                        and not literal.startswith(("'//", '"//'))
                        and right.sanitizer == "encodeURIComponent:html-markup"
                        and not value.unknown):
                    return Value(value.sources, value.trace,
                                 "fixed-relative-url", unknown=False)
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
                if suffix == "href" and (is_location or tag == "a"):
                    self.sink(left, value, "url")
                elif suffix == "src" and tag == "script":
                    self.sink(left, value, "remote_script")
                else:
                    self.limitation(left, "untyped href/src destination requires DOM element identity")
                    self.env = {k: join(v, Value(unknown=True)) for k,v in self.env.items()}
            elif left.type == "identifier":
                self.dom_tags.pop(name, None)
                self.bindings.pop(name, None)
                self.env[name] = Value(value.sources, value.trace + (name,), value.sanitizer, value.unknown)
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
            # Don't evaluate a callback lambda as an ordinary expression:
            # doing that incorrectly poisons the environment before the
            # handler can be inspected.
            if call in ("addEventListener", "window.addEventListener"):
                if (call == "addEventListener" and "addEventListener" in self.env) or (
                        call == "window.addEventListener" and "window" in self.env):
                    self.limitation(node, "event listener API is shadowed")
                    return Value(unknown=True)
                if (len(args) == 2 and self.text(args[0]) in ("'message'", '"message"')
                        and self.callback(node, args[1], source="message-event.data")):
                    return Value()
                self.limitation(node, "unresolved event listener/callback")
                return Value(unknown=True)
            values = [self.expression(a) for a in args]
            # Narrow, audited taint-preserving operations. These are NOT
            # sanitizers and never prove a dangerous sink safe.
            if call in ("decodeURIComponent", "decodeURI", "encodeURIComponent",
                        "encodeURI", "String", "JSON.stringify", "JSON.parse",
                        "URLSearchParams") and len(values) == 1:
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
                        self.sink(function, values[1], "url")
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
            if call in ("eval", "window.eval", "setTimeout", "setInterval"):
                self.sink(function, values[0] if values else Value(unknown=True), "javascript")
                return Value(unknown=True)
            owner = call.removesuffix(".sanitize")
            if call.endswith(".sanitize") and owner in self.bindings and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + (call,), self.bindings[owner], value.unknown)
            self.limitation(node, f"unresolved call: {call or self.text(function)}")
            # Unknown calls can mutate objects or overwrite bindings through closures.
            self.bindings.clear()
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
            return join(*values, Value(unknown=True))
        self.limitation(node, f"unsupported expression: {kind}")
        self.bindings.clear()
        self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
        return Value(unknown=True)

    def statement(self, node):
        kind = node.type
        if kind in ("program", "statement_block"):
            for child in node.named_children:
                self.statement(child)
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
                tag = self.recognized_dom_tag(self.field(declaration, "value"))
                self.dom_tags.pop(key, None)
                if tag is not None:
                    self.dom_tags[key] = tag
                self.env[key] = Value(value.sources, value.trace + (key,), value.sanitizer, value.unknown)
        elif kind == "expression_statement":
            for child in node.named_children:
                self.expression(child)
        elif kind == "if_statement":
            self.expression(self.field(node, "condition"))
            initial = dict(self.env)
            initial_bindings = dict(self.bindings)
            self.statement(self.field(node, "consequence"))
            consequence, consequence_bindings = dict(self.env), dict(self.bindings)
            self.env, self.bindings = dict(initial), dict(initial_bindings)
            alternative = self.field(node, "alternative")
            if alternative:
                self.statement(alternative)
            other = self.env
            self.env = {k: join(consequence.get(k, Value(unknown=True)), other.get(k, Value(unknown=True)))
                        for k in consequence.keys() | other.keys()}
            self.bindings = {k: v for k, v in consequence_bindings.items() if self.bindings.get(k) == v}
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
            iterations = max(0, limit - initial)
            if iterations > 8:
                self.limitation(node, "loop exceeds conservative eight-iteration bound")
                self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}
                self.bindings.clear()
                self.dom_tags.clear()
                return
            old = self.env.get(variable)
            self.env[variable] = Value()  # The header is a numeric local.
            for _ in range(iterations):
                self.statement(body)
            if old is None:
                self.env.pop(variable, None)
            else:
                self.env[variable] = old
        else:
            self.limitation(node, f"unsupported statement: {kind}")
            # Never carry a SAFE value through unanalysed side effects/control flow.
            self.bindings.clear()
            self.env = {k: join(v, Value(unknown=True)) for k, v in self.env.items()}

    def run(self) -> dict:
        root = self.parser.parse(self.code).root_node
        if root.has_error:
            self.limitations.append("parse error: only JavaScript is supported (no HTML/TS/JSX)")
        else:
            self.statement(root)
        verdicts = {s["verdict"] for s in self.sinks}
        verdict = "CANDIDATE" if "CANDIDATE" in verdicts else (
            "INCONCLUSIVE" if self.limitations or "INCONCLUSIVE" in verdicts or not self.sinks else "SAFE"
        )
        return {"engine": "xss-taint-v1", "verdict": verdict, "confirmed": False,
                "requires_oracle": verdict != "SAFE", "sinks": self.sinks,
                "limitations": list(dict.fromkeys(self.limitations)),
                "scope": "bounded intraprocedural JavaScript sink review",
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
