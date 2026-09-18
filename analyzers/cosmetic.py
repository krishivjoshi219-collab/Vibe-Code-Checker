"""VCC Cosmetic Analyzer — Style, formatting, hygiene, typos, and complexity.

Catches cosmetic and maintainability bugs with zero false-positives.
"""
from __future__ import annotations

import ast
import re

COMMON_TYPOS = {
    "recieve": "receive",
    "recieved": "received",
    "reciever": "receiver",
    "seperate": "separate",
    "seperated": "separated",
    "occured": "occurred",
    "occuring": "occurring",
    "succesful": "successful",
    "succesfully": "successfully",
    "lenght": "length",
    "unknwon": "unknown",
    "defualt": "default",
    "paramter": "parameter",
    "paramters": "parameters",
    "enviroment": "environment",
    "reponse": "response",
    "reponses": "responses",
    "flase": "false",
    "tru": "true",
    "adn": "and",
    "calback": "callback",
    "calbacks": "callbacks",
    "overide": "override",
    "overriden": "overridden",
    "refernce": "reference",
    "refernces": "references",
    "adress": "address",
    "adresses": "addresses",
    "maintainance": "maintenance",
    "definately": "definitely",
    "priviledge": "privilege",
    "threshhold": "threshold",
    "compatability": "compatibility",
    "dependancy": "dependency",
    "dependancies": "dependencies",
    "untill": "until",
    "writting": "writing",
    "existance": "existence",
    "guarentee": "guarantee",
    "happend": "happened",
    "noticable": "noticeable",
    "persistance": "persistence",
    "performence": "performance",
    "possession": "possession",
    "prefered": "preferred",
    "publically": "publicly",
    "refered": "referred",
    "relavent": "relevant",
    "resistence": "resistance",
    "seperator": "separator",
    "similiar": "similar",
    "sucess": "success",
    "transfered": "transferred",
    "unforseen": "unforeseen",
    "visiblity": "visibility",
    "whish": "which",
    "wierd": "weird",
    "yeild": "yield",
    "asnyc": "async",
    "synch": "sync",
    "canceld": "canceled",
}

TODO_RE = re.compile(r"(?:#|//|/\*|<!--|\*)\s*(TODO|FIXME|XXX|HACK)\b", re.I)
URL_RE = re.compile(r"https?://\S+")


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


def split_identifier(ident: str) -> list[str]:
    # Split snake_case and camelCase into individual words
    words = re.sub(r"([A-Z][a-z]+)", r" \1", ident).split()
    sub_words = []
    for w in words:
        sub_words.extend(w.split("_"))
    return [w.lower() for w in sub_words if len(w) >= 3]


def _check_comments(
    idx: int,
    line: str,
    lines: list[str],
    path: str,
    sev: dict,
    categories: dict,
) -> list[dict]:
    findings: list[dict] = []
    if "#" not in line:
        return findings

    comment_part = line.split("#", 1)[1]
    words = re.findall(r"[A-Za-z]+", comment_part)
    for w in words:
        low = w.lower()
        if low in COMMON_TYPOS:
            rule = "comment-typo"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P2"),
                "category": categories.get(rule, "cosmetic"),
                "file": path,
                "line": idx,
                "col": line.find(w),
                "title": f"Typo `{w}` in comment (did you mean `{COMMON_TYPOS[low]}`?)",
                "description": f"Misspelled word `{w}` found in comment.",
                "evidence": get_snippet(lines, idx),
                "confidence": "high",
                "fix_suggestion": f"Replace `{w}` with `{COMMON_TYPOS[low]}`.",
            })
    return findings


def _check_whitespace_and_todo(line: str, idx: int, ctx: dict) -> list[dict]:
    findings: list[dict] = []
    sev = ctx["sev"]
    categories = ctx["categories"]
    path = ctx["path"]
    lines = ctx["lines"]
    max_line_len = ctx["max_line_len"]

    if line.endswith((" ", "\t")):
        rule = "trailing-whitespace"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": idx,
            "col": len(line.rstrip(" \t")),
            "title": "Trailing whitespace at end of line",
            "description": "Trailing whitespace clutters git diffs and is against coding style standards.",
            "evidence": get_snippet(lines, idx),
            "confidence": "high",
            "fix_suggestion": "Strip trailing whitespace.",
        })

    if line.startswith(("\t ", " \t")):
        rule = "mixed-indentation"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": idx,
            "col": 0,
            "title": "Mixed tabs and spaces in line indentation",
            "description": "Mixing tabs and spaces causes indentation errors and layout inconsistencies.",
            "evidence": get_snippet(lines, idx),
            "confidence": "high",
            "fix_suggestion": "Standardize on 4 spaces for indentation.",
        })

    if len(line) > max_line_len and not URL_RE.search(line):
        rule = "line-too-long"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": idx,
            "col": max_line_len,
            "title": f"Line exceeds {max_line_len} characters ({len(line)} chars)",
            "description": "Excessively long lines reduce readability on standard displays and code reviews.",
            "evidence": get_snippet(lines, idx, max_line_len),
            "confidence": "med",
            "fix_suggestion": "Wrap line or break long statements into multiple lines.",
        })

    m_todo = TODO_RE.search(line)
    if m_todo:
        rule = "todo-marker"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": idx,
            "col": m_todo.start(),
            "title": f"Unfinished work marker `{m_todo.group(1)}` in code",
            "description": f"Marker indicates pending implementation: {line.strip()[:80]}",
            "evidence": get_snippet(lines, idx, m_todo.start()),
            "confidence": "low",
            "fix_suggestion": "Complete the task or track in issue tracker.",
        })

    return findings


def _analyze_lines(path: str, lines: list[str], sev: dict, categories: dict, max_line_len: int) -> list[dict]:
    findings: list[dict] = []
    consecutive_commented_code = 0
    comment_block_start = 0
    ctx = {"path": path, "lines": lines, "sev": sev, "categories": categories, "max_line_len": max_line_len}

    for idx, line in enumerate(lines, 1):
        if "# noqa" in line or "# vcc:ignore" in line:
            continue

        findings.extend(_check_whitespace_and_todo(line, idx, ctx))

        stripped = line.strip()
        is_comment_code = stripped.startswith("#") and bool(
            re.search(r"^#\s*(def |return |import |from |for |if |class |elif |else:)", stripped)
        )
        if is_comment_code:
            if consecutive_commented_code == 0:
                comment_block_start = idx
            consecutive_commented_code += 1
        else:
            if consecutive_commented_code >= 3:
                rule = "commented-out-code"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": categories.get(rule, "cosmetic"),
                    "file": path,
                    "line": comment_block_start,
                    "col": 0,
                    "title": f"Block of commented-out code ({consecutive_commented_code} lines)",
                    "description": "Commented-out code increases noise and rots over time. Use Git history instead.",
                    "evidence": get_snippet(lines, comment_block_start),
                    "confidence": "high",
                    "fix_suggestion": "Delete commented-out code.",
                })
            consecutive_commented_code = 0

        findings.extend(_check_comments(idx, line, lines, path, sev, categories))

    return findings


def _check_fn_node(node: ast.FunctionDef | ast.AsyncFunctionDef, ctx: dict) -> list[dict]:
    findings: list[dict] = []
    lines = ctx["lines"]
    path = ctx["path"]
    sev = ctx["sev"]
    categories = ctx["categories"]
    max_fn_len = ctx["max_fn_len"]
    max_args = ctx["max_args"]

    end = getattr(node, "end_lineno", node.lineno)
    fn_len = end - node.lineno
    line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
    ignored = "# noqa" in line_text or "# vcc:ignore" in line_text

    if fn_len > max_fn_len and not ignored:
        rule = "long-function"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": node.lineno,
            "col": node.col_offset,
            "title": f"Function `{node.name}()` is {fn_len} lines long (exceeds {max_fn_len})",
            "description": "Monolithic functions are harder to test, maintain, and reason about.",
            "evidence": get_snippet(lines, node.lineno),
            "confidence": "med",
            "fix_suggestion": "Decompose function into smaller, single-purpose helper functions.",
        })

    n_args = len(node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
    if n_args > max_args and not ignored:
        rule = "many-args"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": node.lineno,
            "col": node.col_offset,
            "title": f"Function `{node.name}()` has {n_args} arguments (exceeds {max_args})",
            "description": "Functions with many parameters increase call-site error risk and tight coupling.",
            "evidence": get_snippet(lines, node.lineno),
            "confidence": "med",
            "fix_suggestion": "Bundle arguments into a dataclass, pydantic model, or configuration object.",
        })

    for word in split_identifier(node.name):
        if word in COMMON_TYPOS:
            rule = "identifier-typo"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P2"),
                "category": categories.get(rule, "cosmetic"),
                "file": path,
                "line": node.lineno,
                "col": node.col_offset,
                "title": f"Typo in function name `{node.name}`: `{word}` -> `{COMMON_TYPOS[word]}`",
                "description": f"Identifier contains misspelled word `{word}`.",
                "evidence": get_snippet(lines, node.lineno),
                "confidence": "high",
                "fix_suggestion": f"Rename to include `{COMMON_TYPOS[word]}`.",
            })
    return findings


def _check_nesting(
    tree: ast.AST,
    lines: list[str],
    path: str,
    sev: dict,
    categories: dict,
    max_nesting: int,
) -> list[dict]:
    findings: list[dict] = []
    block_types = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)

    def walk(curr: ast.AST, depth: int = 0) -> bool:
        is_block = isinstance(curr, block_types)
        new_depth = depth + 1 if is_block else depth
        if is_block and new_depth > max_nesting:
            lineno = getattr(curr, "lineno", 1)
            rule = "deep-nesting"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P2"),
                "category": categories.get(rule, "cosmetic"),
                "file": path,
                "line": lineno,
                "col": getattr(curr, "col_offset", 0),
                "title": f"Deeply nested control flow ({new_depth} levels deep, exceeds {max_nesting})",
                "description": "Deeply nested control flow increases cognitive load and branch complexity.",
                "evidence": get_snippet(lines, lineno),
                "confidence": "high",
                "fix_suggestion": "Invert conditions to return early (guard clauses) or extract helper functions.",
            })
            return True
        for child in ast.iter_child_nodes(curr):
            if walk(child, new_depth):
                return True
        return False

    walk(tree)
    return findings


def _analyze_python_ast(
    path: str,
    text: str,
    lines: list[str],
    sev: dict,
    categories: dict,
    thresholds: dict,
) -> list[dict]:
    findings: list[dict] = []
    max_fn_len = int(thresholds.get("long_function_lines", 80))
    max_args = int(thresholds.get("many_args_count", 6))
    max_nesting = int(thresholds.get("deep_nesting_levels", 4))

    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError):
        return []

    fn_ctx = {
        "lines": lines,
        "path": path,
        "sev": sev,
        "categories": categories,
        "max_fn_len": max_fn_len,
        "max_args": max_args,
    }

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_check_fn_node(node, fn_ctx))

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            for word in split_identifier(node.id):
                if word in COMMON_TYPOS:
                    rule = "identifier-typo"
                    findings.append({
                        "rule": rule,
                        "severity": sev.get(rule, "P2"),
                        "category": categories.get(rule, "cosmetic"),
                        "file": path,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "title": f"Typo in variable `{node.id}`: `{word}` -> `{COMMON_TYPOS[word]}`",
                        "description": f"Variable identifier contains misspelled word `{word}`.",
                        "evidence": get_snippet(lines, node.lineno),
                        "confidence": "high",
                        "fix_suggestion": f"Rename to `{COMMON_TYPOS[word]}`.",
                    })

    findings.extend(_check_nesting(tree, lines, path, sev, categories, max_nesting))
    return findings


def analyze_cosmetic(path: str, rules: dict) -> list[dict]:
    findings: list[dict] = []
    sev = rules.get("severity", {})
    categories = rules.get("categories", {})
    thresholds = rules.get("thresholds", {})
    max_line_len = int(thresholds.get("line_length_limit", 120))

    try:
        with open(path, "rb") as f:
            raw_bytes = f.read()
    except OSError:
        return []

    # Missing final newline check
    if raw_bytes and not raw_bytes.endswith(b"\n"):
        rule = "missing-final-newline"
        findings.append({
            "rule": rule,
            "severity": sev.get(rule, "P2"),
            "category": categories.get(rule, "cosmetic"),
            "file": path,
            "line": len(raw_bytes.splitlines()) or 1,
            "col": 0,
            "title": "Missing final newline at end of file",
            "description": "POSIX standards specify that text files should end with a newline (\\n) character.",
            "evidence": "[End of File without newline]",
            "confidence": "high",
            "fix_suggestion": "Add a newline at the end of the file.",
        })

    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()

    findings.extend(_analyze_lines(path, lines, sev, categories, max_line_len))

    if path.endswith((".py", ".pyi")):
        findings.extend(_analyze_python_ast(path, text, lines, sev, categories, thresholds))

    return findings
