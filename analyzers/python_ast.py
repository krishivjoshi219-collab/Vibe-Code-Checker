"""VCC Python AST Analyzer — Deep static analysis for logical, security, async, and resource bugs.

Fast, zero-dependency, pure stdlib AST inspection with full scope resolution.
"""
from __future__ import annotations

import ast
import builtins
import re
from typing import Any

# Standard builtins + dunders + runtime typing primitives
BUILTIN_NAMES = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__package__", "__spec__",
    "__loader__", "__path__", "__annotations__", "__builtins__",
    "__all__", "__class__", "__slots__", "self", "cls",
    # Common type annotations
    "Any", "Union", "Optional", "List", "Dict", "Set", "Tuple",
    "Callable", "Iterator", "Generator", "Iterable", "Mapping",
    "Sequence", "TypeVar", "Generic", "Literal", "Protocol"
}

SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.I),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
]

SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE"}


def get_snippet(lines: list[str], lineno: int, col_offset: int = 0, ctx: int = 2) -> str:
    start = max(0, lineno - ctx - 1)
    end = min(len(lines), lineno + ctx)
    out = []
    for i in range(start, end):
        ln = i + 1
        line_text = lines[i]
        prefix = ">" if ln == lineno else " "
        out.append(f"{prefix} {ln:4d} | {line_text}")
        if ln == lineno and col_offset > 0:
            indent = " " * (col_offset + 9)
            out.append(f"{indent}^")
    return "\n".join(out)


class Scope:
    def __init__(self, kind: str, parent: Scope | None = None):
        self.kind = kind  # "module", "class", "function", "comp"
        self.parent = parent
        self.defined: set[str] = set()
        self.nonlocals: set[str] = set()
        self.globals: set[str] = set()
        self.first_assigned: dict[str, int] = {}
        self.has_wildcard_import = False

    def is_defined(self, name: str) -> bool:
        if name in self.defined or name in self.globals or name in self.nonlocals:
            return True
        if self.has_wildcard_import:
            return True
        if self.parent:
            # In class scope, class attributes are not visible inside nested methods
            if self.parent.kind == "class":
                return self.parent.parent.is_defined(name) if self.parent.parent else False
            return self.parent.is_defined(name)
        return False


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str], rules: dict):
        self.path = path
        self.lines = lines
        self.rules = rules
        self.sev = rules.get("severity", {})
        self.categories = rules.get("categories", {})
        self.findings: list[dict] = []
        self.module_scope = Scope("module")
        self.current_scope = self.module_scope
        self.async_depth = 0
        self.async_funcs: set[str] = set()
        self.all_imports: dict[str, int] = {}  # symbol -> lineno
        self.used_symbols: set[str] = set()
        self.has_future_annotations = False

    def add(
        self,
        rule: str,
        node: ast.AST,
        title: str,
        description: str = "",
        fix_suggestion: str = "",
        confidence: str = "high",
        lineno: int | None = None,
        col_offset: int | None = None,
    ):
        line = lineno or getattr(node, "lineno", 1)
        col = col_offset if col_offset is not None else getattr(node, "col_offset", 0)

        # Check inline suppression (# noqa, # vcc:ignore, # vcc:disable=<rule>)
        if 1 <= line <= len(self.lines):
            line_str = self.lines[line - 1]
            if "# noqa" in line_str or "# vcc:ignore" in line_str or f"# vcc:disable={rule}" in line_str:
                return

        sev = self.sev.get(rule, "P2")
        cat = self.categories.get(rule, "logic")
        evidence = get_snippet(self.lines, line, col)
        self.findings.append({
            "rule": rule,
            "severity": sev,
            "category": cat,
            "file": self.path,
            "line": line,
            "col": col,
            "title": title,
            "description": description or title,
            "evidence": evidence,
            "confidence": confidence,
            "fix_suggestion": fix_suggestion,
        })

    def pre_scan_module(self, tree: ast.AST):
        """Pre-scans top-level statements so forward references in functions are recognized."""
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.module_scope.defined.add(node.name)
                if isinstance(node, ast.AsyncFunctionDef):
                    self.async_funcs.add(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    self.module_scope.defined.add(name)
            elif isinstance(node, ast.ImportFrom):
                if node.names and node.names[0].name == "*":
                    self.module_scope.has_wildcard_import = True
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.module_scope.defined.add(name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            self.module_scope.defined.add(n.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.module_scope.defined.add(node.target.id)

    def visit_Assert(self, node: ast.Assert):
        if isinstance(node.test, ast.Tuple) and node.msg is None:
            self.add(
                "assert-on-tuple",
                node,
                "Assertion of non-empty tuple always evaluates to True",
                description="`assert (x, 'msg')` tests if the tuple is truthy (which it always is), instead of asserting condition with message.",
                fix_suggestion="Remove parentheses around condition and message: `assert cond, 'message'`.",
                confidence="high",
            )
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        # Coroutine called as statement without await
        if isinstance(node.value, ast.Call):
            func_name = None
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr

            is_async_call = (
                func_name in self.async_funcs
                or (
                    func_name == "sleep"
                    and isinstance(getattr(node.value.func, "value", None), ast.Name)
                    and getattr(node.value.func.value, "id", None) == "asyncio"
                )
            )
            if is_async_call:
                self.add(
                    "coroutine-not-awaited",
                    node,
                    f"Coroutine `{func_name}()` called as statement without `await`",
                    description="Calling an async coroutine without `await` creates an unexecuted coroutine object and triggers a RuntimeWarning.",
                    fix_suggestion=f"Add `await {ast.unparse(node.value)}` or wrap with `asyncio.create_task()`.",
                    confidence="high",
                )
        self.generic_visit(node)

    def _bind_name(self, name: str, lineno: int):
        self.current_scope.defined.add(name)
        if name not in self.current_scope.first_assigned:
            self.current_scope.first_assigned[name] = lineno
        else:
            self.current_scope.first_assigned[name] = min(self.current_scope.first_assigned[name], lineno)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._bind_name(name, node.lineno)
            self.all_imports[name] = node.lineno
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "__future__" and any(a.name == "annotations" for a in node.names):
            self.has_future_annotations = True
        for alias in node.names:
            if alias.name == "*":
                self.current_scope.has_wildcard_import = True
            else:
                name = alias.asname or alias.name
                self._bind_name(name, node.lineno)
                self.all_imports[name] = node.lineno
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Register store targets
        for target in node.targets:
            for n in ast.walk(target):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    self._bind_name(n.id, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.target, ast.Name):
            self._bind_name(node.target.id, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name):
            self._bind_name(node.target.id, node.lineno)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr):
        # Walrus operator := binds in function or module scope
        if isinstance(node.target, ast.Name):
            target_scope = self.current_scope
            while target_scope.kind == "comp" and target_scope.parent:
                target_scope = target_scope.parent
            target_scope.defined.add(node.target.id)
            if node.target.id not in target_scope.first_assigned:
                target_scope.first_assigned[node.target.id] = node.lineno
        self.generic_visit(node)

    def visit_For(self, node: ast.For | ast.AsyncFor):
        for n in ast.walk(node.target):
            if isinstance(n, ast.Name):
                self._bind_name(n.id, node.lineno)

        # Mutation of collection during iteration
        iter_name = node.iter.id if isinstance(node.iter, ast.Name) else None
        if iter_name:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Delete):
                    for target in sub.targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == iter_name:
                            self.add(
                                "collection-mutation-during-iteration",
                                sub,
                                f"Mutating collection `{iter_name}` during iteration (`del {iter_name}[...]`)",
                                description="Modifying a collection while iterating over it causes skipped items or RuntimeError.",
                                fix_suggestion=f"Iterate over a copy using `list({iter_name})` or a list comprehension.",
                                confidence="high",
                            )
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if isinstance(sub.func.value, ast.Name) and sub.func.value.id == iter_name:
                        if sub.func.attr in ("remove", "pop", "clear", "append", "extend"):
                            self.add(
                                "collection-mutation-during-iteration",
                                sub,
                                f"Mutating collection `{iter_name}` during iteration (`{iter_name}.{sub.func.attr}()`)",
                                description="Modifying a list/dict during iteration causes unpredictable behaviour or crash.",
                                fix_suggestion=f"Iterate over a shallow copy (`list({iter_name})`).",
                                confidence="high",
                            )
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With | ast.AsyncWith):
        for item in node.items:
            if item.optional_vars:
                for n in ast.walk(item.optional_vars):
                    if isinstance(n, ast.Name):
                        self._bind_name(n.id, node.lineno)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_ListComp(self, node: ast.ListComp):
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp):
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp):
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._visit_comprehension(node)

    def _visit_comprehension(self, node: ast.AST):
        old_scope = self.current_scope
        self.current_scope = Scope("comp", old_scope)
        for gen in getattr(node, "generators", []):
            for n in ast.walk(gen.target):
                if isinstance(n, ast.Name):
                    self.current_scope.defined.add(n.id)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_Global(self, node: ast.Global):
        for name in node.names:
            self.current_scope.globals.add(name)
            self.add(
                "global-mutation",
                node,
                f"Global variable `{name}` mutated in function",
                description="Mutating globals introduces race conditions and makes testing difficult.",
                fix_suggestion="Refactor to pass state explicitly or use a class/state object.",
                confidence="med",
            )

    def visit_Nonlocal(self, node: ast.Nonlocal):
        for name in node.names:
            self.current_scope.nonlocals.add(name)

    def visit_ClassDef(self, node: ast.ClassDef):
        self._bind_name(node.name, node.lineno)
        old_scope = self.current_scope
        self.current_scope = Scope("class", old_scope)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        is_async = isinstance(node, ast.AsyncFunctionDef)
        if is_async:
            self.async_funcs.add(node.name)

        # Builtin shadow
        if node.name in ("list", "dict", "set", "id", "type", "filter", "input", "open", "all", "any", "next", "map"):
            self.add(
                "builtin-shadow",
                node,
                f"Function `{node.name}` shadows Python built-in",
                fix_suggestion=f"Rename `{node.name}` to avoid shadowing builtins.",
                confidence="high",
            )

        # Check mutable defaults
        for d in node.args.defaults + node.args.kw_defaults:
            if d is not None and isinstance(d, (ast.List, ast.Dict, ast.Set)):
                self.add(
                    "mutable-default",
                    d,
                    f"Mutable default argument `{ast.unparse(d)}` in `{node.name}()`",
                    description="Default arguments are evaluated once when the function is defined, causing state to leak across calls.",
                    fix_suggestion="Use `None` as default and initialize inside function body.",
                    confidence="high",
                )

        # Check duplicate arguments
        arg_names = [a.arg for a in node.args.args + node.args.posonlyargs + node.args.kwonlyargs]
        if len(arg_names) != len(set(arg_names)):
            self.add(
                "undefined-name",
                node,
                f"Duplicate argument name in `{node.name}()` signature",
                fix_suggestion="Ensure each argument name is unique.",
            )

        self._bind_name(node.name, node.lineno)
        old_scope = self.current_scope
        self.current_scope = Scope("function", old_scope)
        if is_async:
            self.async_depth += 1

        # Register params in function scope
        for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self._bind_name(a.arg, node.lineno)
        if node.args.vararg:
            self._bind_name(node.args.vararg.arg, node.lineno)
        if node.args.kwarg:
            self._bind_name(node.args.kwarg.arg, node.lineno)

        # Pre-scan body for store assignments to avoid false undefined-names
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                self._bind_name(child.id, child.lineno)

        # Check dead code and missing return branch
        self._check_dead_code_in_body(node.body)
        self._check_return_paths(node)

        self.generic_visit(node)

        if is_async:
            self.async_depth -= 1
        self.current_scope = old_scope

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_dead_code_in_body(self, body: list[ast.stmt]):
        terminators = (ast.Return, ast.Raise, ast.Break, ast.Continue)
        for i, stmt in enumerate(body):
            if isinstance(stmt, terminators) and i + 1 < len(body):
                next_stmt = body[i + 1]
                self.add(
                    "dead-code",
                    next_stmt,
                    f"Unreachable statement after `{stmt.__class__.__name__.lower()}`",
                    description="Statements following a return, raise, break, or continue will never execute.",
                    fix_suggestion="Remove unreachable dead code or correct indentation.",
                )
                break
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                for sub in getattr(stmt, "body", []):
                    if isinstance(sub, list):
                        self._check_dead_code_in_body(sub)
                for sub in getattr(stmt, "orelse", []):
                    if isinstance(sub, list):
                        self._check_dead_code_in_body(sub)

    def _check_return_paths(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        has_val = any(r.value is not None for r in returns)
        has_bare = any(r.value is None for r in returns)
        if has_val and has_bare:
            self.add(
                "missing-return-branch",
                node,
                f"Inconsistent return in `{node.name}()`: mixes valued returns and bare `return`",
                description="Some code paths return an explicit value while others return None, leading to unexpected NoneType errors.",
                fix_suggestion="Ensure all return statements return a value or raise an exception.",
                confidence="high",
            )

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.used_symbols.add(node.id)
            if node.id not in BUILTIN_NAMES and not self.current_scope.is_defined(node.id):
                self.add(
                    "undefined-name",
                    node,
                    f"Undefined name `{node.id}`",
                    description=f"Name `{node.id}` is referenced before definition or without an import.",
                    fix_suggestion=f"Import `{node.id}` or define it before use.",
                    confidence="high",
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        # NaN compare: x == float('nan')
        for op, comp in zip(node.ops, node.comparators):
            is_nan_call = (
                isinstance(comp, ast.Call)
                and isinstance(comp.func, ast.Name)
                and comp.func.id == "float"
                and comp.args
                and isinstance(comp.args[0], ast.Constant)
                and str(comp.args[0].value).lower() == "nan"
            )
            is_math_nan = (
                isinstance(comp, ast.Attribute)
                and isinstance(comp.value, ast.Name)
                and comp.value.id == "math"
                and comp.attr == "nan"
            )
            if is_nan_call or is_math_nan:
                self.add(
                    "float-nan-compare",
                    node,
                    "Comparison with NaN always evaluates to False in IEEE 754",
                    description="NaN does not equal anything, not even itself. Use `math.isnan(x)` instead.",
                    fix_suggestion=f"Use `math.isnan({ast.unparse(node.left)})` instead of direct comparison.",
                    confidence="high",
                )

            # Identity compare on literals: x is 123, x is "str"
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant):
                if not isinstance(comp.value, (bool, type(None))):
                    self.add(
                        "identity-compare-literal",
                        node,
                        f"Identity comparison (`is`) on literal `{comp.value!r}`",
                        description="`is` checks memory address identity. In Python, literal interning is an implementation detail.",
                        fix_suggestion="Use `==` or `!=` for value comparison.",
                        confidence="high",
                    )

            # None compare: x is None -> x is None
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                kw = "is None" if isinstance(op, ast.Eq) else "is not None"
                self.add(
                    "none-eq-compare",
                    node,
                    f"Comparison with `None` using `{'==' if isinstance(op, ast.Eq) else '!='}`",
                    description="Comparison with None should always use identity (`is None`) because `__eq__` can be overridden.",
                    fix_suggestion=f"Replace with `{ast.unparse(node.left)} {kw}`.",
                    confidence="high",
                )

            # Bool compare: x / False
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and isinstance(comp.value, bool):
                self.add(
                    "bool-compare",
                    node,
                    f"Redundant comparison with `{comp.value}`",
                    description="Comparing explicitly to True/False is redundant and unpythonic.",
                    fix_suggestion=f"Use `{ast.unparse(node.left)}` directly.",
                    confidence="high",
                )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        # Division by zero
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                self.add(
                    "zero-div",
                    node,
                    "Literal division or modulo by zero (ZeroDivisionError)",
                    description="Dividing by zero will crash at runtime.",
                    fix_suggestion="Guard against zero denominator before dividing.",
                    confidence="high",
                )
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        seen_keys: set[Any] = set()
        for k in node.keys:
            if k is not None and isinstance(k, ast.Constant):
                if k.value in seen_keys:
                    self.add(
                        "duplicate-dict-key",
                        k,
                        f"Duplicate dictionary key `{k.value!r}`",
                        description="Earlier key-value pair is silently overwritten by the later duplicate key.",
                        fix_suggestion=f"Remove duplicate key `{k.value!r}`.",
                        confidence="high",
                    )
                else:
                    seen_keys.add(k.value)
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        is_true = isinstance(node.test, ast.Constant) and bool(node.test.value) is True
        if is_true:
            has_break = any(isinstance(n, (ast.Break, ast.Return, ast.Raise)) for n in ast.walk(node))
            if not has_break:
                self.add(
                    "infinite-loop-risk",
                    node,
                    "Potential infinite loop: `while True` has no break, return, or raise",
                    description="Loop body contains no exit condition, which may hang the thread or process.",
                    fix_suggestion="Add a break condition or timeout guard.",
                    confidence="high",
                )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            self._bind_name(node.name, node.lineno)

        if node.type is None:
            self.add(
                "bare-except",
                node,
                "Bare `except:` catches KeyboardInterrupt and SystemExit",
                description="Bare except hides critical termination signals and bugs. Use `except Exception:` instead.",
                fix_suggestion="Change to `except Exception:` and handle/log the error.",
                confidence="high",
            )
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            is_silent = (
                len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            )
            re_raises = any(isinstance(s, ast.Raise) and s.exc is None for s in ast.walk(node))
            if is_silent:
                self.add(
                    "silent-except-pass",
                    node,
                    f"Silent error suppression: `except {node.type.id}: pass`",
                    description="Errors are completely swallowed without logging or handling.",
                    fix_suggestion="Log the exception or re-raise with context.",
                    confidence="high",
                )
            elif not re_raises:
                self.add(
                    "broad-except",
                    node,
                    f"Broad catch: `except {node.type.id}`",
                    description="Catching broad Exception can mask programming errors and typos.",
                    fix_suggestion="Catch specific exception types (e.g. ValueError, KeyError).",
                    confidence="med",
                )

        # Check for `except Exception as e: raise e` (resets traceback)
        if node.name:
            for stmt in node.body:
                if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Name) and stmt.exc.id == node.name:
                    self.add(
                        "re-raise-reset-traceback",
                        stmt,
                        f"Re-raising `{node.name}` resets the traceback",
                        description="Calling `raise e` replaces the original error site. Use bare `raise` to preserve the traceback.",
                        fix_suggestion="Use bare `raise` instead of `raise e`.",
                        confidence="high",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check eval / exec
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.add(
                "eval-exec",
                node,
                f"Dangerous dynamic code execution via `{node.func.id}()`",
                description="eval() and exec() execute arbitrary Python code and introduce major security vulnerabilities.",
                fix_suggestion="Use `ast.literal_eval()` or safe parser instead.",
                confidence="high",
            )

        # Command injection: subprocess shell=True or os.system
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                self.add(
                    "command-injection",
                    node,
                    "Command injection risk: `os.system()` runs via shell",
                    description="`os.system` executes commands in a system subshell. Any unsanitized string argument allows arbitrary command execution.",
                    fix_suggestion="Use `subprocess.run([...], check=True)` with argument list instead of a shell string.",
                    confidence="high",
                )
            elif node.func.attr in ("run", "Popen", "call") and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.add(
                            "command-injection",
                            node,
                            "`subprocess` called with `shell=True`",
                            description="shell=True exposes the application to command injection if arguments contain user input.",
                            fix_suggestion="Pass command arguments as a list: `['cmd', 'arg1', ...]` and remove `shell=True`.",
                            confidence="high",
                        )

        # Insecure deserialization: pickle.loads, yaml.load
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "pickle" and node.func.attr in ("loads", "load"):
                    self.add(
                        "insecure-deserialization",
                        node,
                        "Insecure deserialization with `pickle`",
                        description="Pickle allows arbitrary code execution during unpickling. Never unpickle untrusted data.",
                        fix_suggestion="Use `json.loads()` or a secure schema parser.",
                        confidence="high",
                    )
                elif node.func.value.id == "yaml" and node.func.attr == "load":
                    kw_loaders = [k.value for k in node.keywords if k.arg == "Loader"]
                    if not kw_loaders or (isinstance(kw_loaders[0], ast.Attribute) and kw_loaders[0].attr == "Loader"):
                        self.add(
                            "insecure-deserialization",
                            node,
                            "Insecure `yaml.load()` without SafeLoader",
                            description="PyYAML's default loader can execute arbitrary Python objects.",
                            fix_suggestion="Use `yaml.safe_load(...)` instead.",
                            confidence="high",
                        )

        # SQL Injection
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.JoinedStr):
                    # Check if joined string looks like SQL
                    for part in arg0.values:
                        if isinstance(part, ast.Constant) and any(w in str(part.value).upper() for w in SQL_KEYWORDS):
                            self.add(
                                "sql-injection",
                                node,
                                "SQL Injection: f-string used in `execute()` query",
                                description="Directly interpolating variables into SQL queries causes SQL injection.",
                                fix_suggestion="Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE id = ?', (id,))`.",
                                confidence="high",
                            )
                            break
                elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod):
                    if isinstance(arg0.left, ast.Constant) and any(w in str(arg0.left.value).upper() for w in SQL_KEYWORDS):
                        self.add(
                            "sql-injection",
                            node,
                            "SQL Injection: string `%` formatting used in `execute()` query",
                            description="Formatting variables directly into SQL queries causes SQL injection.",
                            fix_suggestion="Use parameterized query arguments.",
                            confidence="high",
                        )

        # Weak cryptographic random
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
            if node.func.attr in ("randint", "random", "choice", "choices", "sample"):
                # Check if called in security context
                line_text = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
                if re.search(r"token|secret|key|password|auth|salt|nonce|pin|otp", line_text, re.I):
                    self.add(
                        "weak-random",
                        node,
                        f"Insecure `random.{node.func.attr}()` used in security context",
                        description="`random` is a pseudo-random generator and is not cryptographically secure.",
                        fix_suggestion="Use `secrets` module (`secrets.token_hex()`, `secrets.token_urlsafe()`).",
                        confidence="high",
                    )

        # Weak hash: hashlib.md5 / hashlib.sha1
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
            if node.func.attr in ("md5", "sha1"):
                line_text = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
                if re.search(r"pass|pwd|auth|secret|token|cred", line_text, re.I):
                    self.add(
                        "weak-hash",
                        node,
                        f"Weak cryptographic hash `hashlib.{node.func.attr}()` for credentials",
                        description="MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
                        fix_suggestion="Use SHA-256 (`hashlib.sha256()`) or Argon2 / bcrypt for passwords.",
                        confidence="high",
                    )

        # Async: time.sleep in async def
        if self.async_depth > 0:
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "time" and node.func.attr == "sleep":
                    self.add(
                        "blocking-call-in-async",
                        node,
                        "Blocking `time.sleep()` called inside `async def`",
                        description="Calling `time.sleep()` halts the entire asyncio event loop, freezing all concurrent requests.",
                        fix_suggestion="Use `await asyncio.sleep(...)` instead.",
                        confidence="high",
                    )
                elif node.func.value.id == "requests" and node.func.attr in ("get", "post", "put", "delete", "request"):
                    self.add(
                        "blocking-call-in-async",
                        node,
                        f"Blocking `requests.{node.func.attr}()` called inside `async def`",
                        description="Synchronous network requests block the asyncio event loop.",
                        fix_suggestion="Use an asynchronous HTTP client like `httpx.AsyncClient` or `aiohttp`.",
                        confidence="high",
                    )

        # Resource leak: open() not in with
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            # Check parent context
            if not self._is_inside_with(node):
                self.add(
                    "file-leak-no-with",
                    node,
                    "`open()` called without context manager (`with`)",
                    description="Files opened without `with` risk descriptor leaks if an exception occurs before `.close()`.",
                    fix_suggestion="Use `with open(...) as f:` to ensure automatic cleanup.",
                    confidence="med",
                )

        # HTTPX without timeout
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "post", "put", "delete", "request", "Client"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "httpx":
                kw_args = {k.arg for k in node.keywords}
                if "timeout" not in kw_args and "request_options" not in kw_args:
                    self.add(
                        "httpx-no-timeout",
                        node,
                        f"httpx call `{node.func.attr}()` without explicit `timeout`",
                        description="Requests without explicit timeout will hang indefinitely if remote server stalls.",
                        fix_suggestion="Specify a timeout: `timeout=10.0`.",
                        confidence="high",
                    )

        self.generic_visit(node)

    def _is_inside_with(self, target_node: ast.AST) -> bool:
        line_idx = getattr(target_node, "lineno", 0) - 1
        if 0 <= line_idx < len(self.lines):
            line_str = self.lines[line_idx].strip()
            if line_str.startswith("with ") or "with open" in line_str:
                return True
        return False

    def visit_Constant(self, node: ast.Constant):
        # Check hardcoded secrets
        if isinstance(node.value, str) and len(node.value) > 10:
            for pat in SECRET_PATTERNS:
                if pat.search(node.value):
                    self.add(
                        "hardcoded-secret",
                        node,
                        "Possible hardcoded secret or API key in source code",
                        description="Hardcoded secrets in source code risk exposure through source control and leaks.",
                        fix_suggestion="Move credentials to environment variables or a secret vault.",
                        confidence="high",
                    )
                    break
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Check off-by-one: arr[len(arr)]
        if isinstance(node.slice, ast.Call):
            if isinstance(node.slice.func, ast.Name) and node.slice.func.id == "len":
                if node.slice.args and isinstance(node.slice.args[0], ast.Name) and isinstance(node.value, ast.Name):
                    if node.slice.args[0].id == node.value.id:
                        self.add(
                            "off-by-one-index",
                            node,
                            f"Off-by-one error: `{node.value.id}[len({node.value.id})]` always raises IndexError",
                            description="Python indices are 0-based. The maximum index is `len - 1` or use `[-1]`.",
                            fix_suggestion=f"Use `{node.value.id}[-1]` to get the last element.",
                            confidence="high",
                        )
        self.generic_visit(node)


def analyze_python_ast(path: str, rules: dict) -> list[dict]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return []

    lines = content.splitlines()
    findings: list[dict] = []

    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError as e:
        sev = rules.get("severity", {}).get("syntax-error", "P0")
        line = e.lineno or 1
        col = e.offset or 0
        evidence = get_snippet(lines, line, col)
        return [{
            "rule": "syntax-error",
            "severity": sev,
            "category": "syntax",
            "file": path,
            "line": line,
            "col": col,
            "title": f"SyntaxError: {e.msg}",
            "description": f"Failed to parse Python code: {e.msg}",
            "evidence": evidence,
            "confidence": "high",
            "fix_suggestion": "Correct the syntax error.",
        }]

    visitor = PythonASTVisitor(path, lines, rules)
    visitor.pre_scan_module(tree)
    visitor.visit(tree)

    # Check unused imports
    future_features = {"annotations", "print_function", "division", "absolute_import", "unicode_literals"}
    if not path.endswith("__init__.py"):
        for name, lineno in visitor.all_imports.items():
            if name not in visitor.used_symbols and name != "_" and name not in future_features:
                # Check if present in comments or __all__
                in_all = f"'{name}'" in content or f'"{name}"' in content
                if not in_all:
                    findings.append({
                        "rule": "unused-import",
                        "severity": rules.get("severity", {}).get("unused-import", "P2"),
                        "category": "cosmetic",
                        "file": path,
                        "line": lineno,
                        "col": 0,
                        "title": f"Unused import `{name}`",
                        "description": f"Imported symbol `{name}` is never used in the file.",
                        "evidence": get_snippet(lines, lineno, 0),
                        "confidence": "high",
                        "fix_suggestion": f"Remove unused import `{name}`.",
                    })

    findings.extend(visitor.findings)

    # Deduplicate findings
    seen = set()
    deduped = []
    for f in findings:
        key = (f["rule"], f["line"], f["title"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped
