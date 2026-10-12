"""Offline JavaScript AST review. Never executes code or contacts a target.

Bounded intraprocedural analysis: unsupported syntax and unknown calls abstain.
SAFE means supported expressions at reviewed sinks, not whole-program safety.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
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

    def sink(self, node, value: Value, context: str):
        # Exact imported identity AND an explicit audited-module policy are required.
        compatible = value.sanitizer is not None and context == "html"
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
            elif left.type == "identifier":
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
            values = [self.expression(a) for a in args]
            # Narrow, audited taint-preserving operations. These are NOT
            # sanitizers and never prove a dangerous sink safe.
            if call in ("decodeURIComponent", "decodeURI", "encodeURIComponent",
                        "encodeURI", "String", "JSON.stringify", "JSON.parse",
                        "URLSearchParams") and len(values) == 1:
                value = values[0]
                return Value(value.sources, value.trace + (call,),
                             unknown=value.unknown)
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
            if call.endswith(".setAttribute") and len(args) == 2:
                attr = self.text(args[0]).strip()
                if len(attr) >= 2 and attr[0] in ("'", '"') and attr[-1] == attr[0]:
                    key = attr[1:-1].lower()
                    if key.startswith("on") and len(key) > 2:
                        self.sink(function, values[1], "javascript")
                        return Value(unknown=True)
                    if key in {"title", "alt", "class", "id", "role"} or key.startswith("aria-"):
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
