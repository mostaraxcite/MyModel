"""Freeze original external sources for review; upstream alerts are not labels.

This prepares source context, not a certified external accuracy benchmark.
No JavaScript executes and no static scoring happens during intake.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_javascript


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def prepare(sources, engine_revision):
    if not re.fullmatch(r'[0-9a-f]{40}', engine_revision):
        raise ValueError('Engine revision must be immutable SHA')
    parser = Parser(Language(tree_sitter_javascript.language()))
    inventory = []
    candidates = []
    seen = set()
    for source in sources:
        if not re.fullmatch(r'[0-9a-f]{40}', source['revision']):
            raise ValueError('Source revision must be immutable SHA')
        if not source.get('id') or not source.get('repository') or not source.get('path'):
            raise ValueError('Incomplete source provenance')
        identity = (source['repository'], source['revision'], source['path'])
        if identity in seen:
            raise ValueError('Duplicate immutable source')
        seen.add(identity)
        code = source['code']
        raw = code.encode('utf-8')
        sha = digest(code)
        if source.get('content_sha256', sha) != sha:
            raise ValueError('Source content hash mismatch')
        root = parser.parse(raw).root_node
        inventory.append({k: v for k, v in source.items() if k != 'code'} | {
            'content_sha256': sha, 'bytes': len(raw), 'parse_error': root.has_error,
        })

        def walk(node):
            # Candidate sink locations only; source connectivity/reachability,
            # framework behavior, protection and labels require review.
            interesting = False
            if node.type in {'member_expression', 'subscript_expression'}:
                prop = node.child_by_field_name('property') or node.child_by_field_name('index')
                if prop is not None:
                    name = raw[prop.start_byte:prop.end_byte].decode('utf-8').strip("'\"")
                    parent = node.parent
                    write = parent is not None and parent.type in {'assignment_expression', 'augmented_assignment_expression'} and parent.child_by_field_name('left') == node
                    call = parent is not None and parent.type == 'call_expression' and parent.child_by_field_name('function') == node
                    interesting = (write and name in {'innerHTML', 'outerHTML', 'srcdoc'}) or (call and name in {'html', 'append', 'prepend', 'write', 'writeln', 'insertAdjacentHTML', 'setAttribute'})
            if interesting:
                context = node
                while context.parent is not None and context.type not in {'function_declaration', 'function_expression', 'arrow_function', 'method_definition', 'program'}:
                    context = context.parent
                statement = node
                while statement.parent is not None and statement.type not in {'expression_statement', 'return_statement', 'lexical_declaration', 'variable_declaration', 'program'}:
                    statement = statement.parent
                candidates.append({
                    'id': f"{source['id']}-L{node.start_point.row + 1}-B{node.start_byte}",
                    'source_id': source['id'], 'source_sha256': sha,
                    'line': node.start_point.row + 1,
                    'sink_expression': raw[node.start_byte:node.end_byte].decode('utf-8'),
                    'statement': raw[statement.start_byte:statement.end_byte].decode('utf-8'),
                    'context_start_byte': context.start_byte, 'context_end_byte': context.end_byte,
                    'context_sha256': hashlib.sha256(raw[context.start_byte:context.end_byte]).hexdigest(),
                    'label': 'needs_review', 'review_status': 'pending',
                    'browser_status': 'not_tested', 'static_status': 'NOT_TESTED',
                    'upstream_annotations_are_ground_truth': False,
                })
            for child in node.named_children:
                walk(child)
        walk(root)
    canonical = json.dumps(inventory, sort_keys=True, separators=(',', ':'))
    return {
        'schema_version': 1, 'evaluation_kind': 'external_source_intake',
        'engine_revision': engine_revision, 'source_inventory_sha256': digest(canonical),
        'source_repositories': len({s['repository'] for s in inventory}),
        'sources': inventory, 'review_candidates': candidates,
        'reviewed_unsafe': 0, 'reviewed_safe': 0,
        'target_reviewed_unsafe': 100, 'target_reviewed_safe': 100,
        'independence_verified': False, 'model_evaluated': False,
        'accuracy': None, 'promotion': 'DO_NOT_PROMOTE',
        'adjudication_requirements': [
            'Review complete original file, caller/input control and library versions.',
            'Record independent reviewer identity, evidence reference and semantic reason.',
            'Unsafe: demonstrate connected attacker-controlled input and execution in isolated browser.',
            'Safe: prove context-compatible defense or noninterpreting sink; nonexecution alone is insufficient.',
            'Freeze reviewed cases, runtime fixtures and sampling plan before first scoring.',
        ],
        'limitations': [
            'Selected public sources are not a representative sampling frame.',
            'Repository annotations and absent alerts are not adjudicated XSS labels.',
            'Potential sinks are review locations, not vulnerabilities or independent samples.',
            'Original complete sources and function context must be reviewed before extracting scored cases.',
            'Complete development/training inventory and independent label review remain unverified.',
            'Once results inform development the resulting partition becomes exposed regression.',
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--sources', type=Path, required=True)
    p.add_argument('--engine-revision', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = prepare(json.loads(args.sources.read_text()), args.engine_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'sources': len(report['sources']), 'repositories': report['source_repositories'],
                      'review_candidates': len(report['review_candidates']),
                      'reviewed_cases': 0, 'accuracy': None}))


if __name__ == '__main__':
    main()
