"""Multi-file source analysis with Python AST alias and constant resolution."""
import ast
import hashlib
import json
from pathlib import PurePosixPath
from .polyglot_scanner import scan_polyglot_code

EXTENSIONS = {'.py': 'python', '.java': 'java', '.c': 'c_cpp', '.h': 'c_cpp', '.cpp': 'c_cpp', '.hpp': 'c_cpp', '.go': 'golang', '.js': 'javascript', '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript'}
LANGUAGES = {'python', 'java', 'c_cpp', 'golang', 'javascript'}


class Resolve(ast.NodeTransformer):
    def __init__(self, imported_constants=None):
        self.aliases = {}
        self.constants = dict(imported_constants or {})

    def visit_Import(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name.split('.')[0]] = entry.name if entry.asname else entry.name.split('.')[0]
        return node

    def visit_ImportFrom(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name] = f'{node.module}.{entry.name}'
        return node

    def visit_Assign(self, node):
        node = self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.constants.pop(target.id, None)
                self.aliases.pop(target.id, None)
                if isinstance(node.value, ast.Constant):
                    self.constants[target.id] = node.value.value
        return node

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load):
            return node
        if node.id in self.constants:
            return ast.copy_location(ast.Constant(self.constants[node.id]), node)
        if node.id in self.aliases:
            qualified = self.aliases[node.id]
            if qualified in self.constants:
                return ast.copy_location(ast.Constant(self.constants[qualified]), node)
            return ast.copy_location(ast.parse(qualified, mode='eval').body, node)
        return node

    def visit_Attribute(self, node):
        node = self.generic_visit(node)
        key = ast.unparse(node)
        if key in self.constants:
            return ast.copy_location(ast.Constant(self.constants[key]), node)
        return node

    def visit_FunctionDef(self, node):
        old_constants, old_aliases = self.constants.copy(), self.aliases.copy()
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for arg in args + [a for a in (node.args.vararg, node.args.kwarg) if a]:
            self.constants.pop(arg.arg, None)
            self.aliases.pop(arg.arg, None)
        node = self.generic_visit(node)
        self.constants, self.aliases = old_constants, old_aliases
        return node

    visit_AsyncFunctionDef = visit_FunctionDef


def python_findings(source, constants):
    from .ast_scanner import CryptoASTVisitor
    tree = ast.parse(source)
    tree = Resolve(constants).visit(tree)
    ast.fix_missing_locations(tree)
    visitor = CryptoASTVisitor(source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def scan_sources(files):
    findings, coverage, dependencies = [], [], []
    constants = {}
    # Resolve simple module-level constants across uploaded Python modules.
    for file in files:
        if file['path'].endswith('.py'):
            try:
                module = file['path'][:-3].replace('/', '.')
                for node in ast.parse(file['content']).body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                constants[f'{module}.{target.id}'] = node.value.value
            except SyntaxError:
                pass
    for file in files:
        path, source = file['path'], file['content']
        lang = file.get('language') or EXTENSIONS.get(PurePosixPath(path).suffix.lower())
        if path.endswith('requirements.txt'):
            for line in source.splitlines():
                line = line.strip()
                if line and not line.startswith(('#', '-')):
                    dependencies.append({'file': path, 'requirement': line, 'scope': 'python'})
            coverage.append({'file': path, 'status': 'inventory', 'engine': 'manifest'})
            continue
        if path.endswith('package.json'):
            try:
                package = json.loads(source)
                for group in ('dependencies', 'devDependencies'):
                    for name, version in package.get(group, {}).items():
                        dependencies.append({'file': path, 'name': name, 'version': version, 'scope': group})
                coverage.append({'file': path, 'status': 'inventory', 'engine': 'manifest'})
            except (ValueError, AttributeError):
                coverage.append({'file': path, 'status': 'error', 'error': 'Invalid package manifest'})
            continue
        if lang not in LANGUAGES:
            coverage.append({'file': path, 'status': 'unsupported', 'engine': None})
            continue
        try:
            if lang == 'python':
                found = python_findings(source, constants)
                engine = 'python-ast'
            else:
                found = scan_polyglot_code(source, lang)['findings']
                engine = 'regex-heuristic'
            coverage.append({'file': path, 'language': lang, 'status': 'scanned', 'engine': engine})
            for finding in found:
                finding.update(file=path, language=lang, engine=engine,
                               confidence='medium' if lang == 'python' else 'low',
                               source_hash=hashlib.sha256(source.encode()).hexdigest())
                findings.append(finding)
        except SyntaxError as exc:
            coverage.append({'file': path, 'status': 'error', 'engine': 'python-ast', 'error': str(exc)})
    return {'findings': findings, 'total_findings': len(findings),
            'critical_count': sum(f['severity'] == 'CRITICAL' for f in findings),
            'high_count': sum(f['severity'] == 'HIGH' for f in findings),
            'coverage': coverage, 'dependencies': dependencies,
            'status': 'partial' if any(c['status'] in ('error', 'unsupported') for c in coverage) else 'success',
            'limitations': ['Non-Python rules are heuristic; no general interprocedural dataflow or dependency vulnerability database.'],
            'remediation': ''}
