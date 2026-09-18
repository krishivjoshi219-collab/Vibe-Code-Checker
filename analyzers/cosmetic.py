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


def analyze_cosmetic(path: str, rules: dict) -> list[dict]:
    findings: list[dict] = []
    sev = rules.get("severity", {})
    categories = rules.get("categories", {})
    thresholds = rules.get("thresholds", {})
    max_line_len = int(thresholds.get("line_length_limit", 120))
    max_fn_len = int(thresholds.get("long_function_lines", 80))
    max_args = int(thresholds.get("many_args_count", 6))
    max_nesting = int(thresholds.get("deep_nesting_levels", 4))

    try:
        with open(path, "rb") as f:
            raw_bytes = f.read()
    except Exception:
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

    # Line-by-line checks
    consecutive_commented_code = 0
    comment_block_start = 0

    for idx, line in enumerate(lines, 1):
        if "# noqa" in line or "# vcc:ignore" in line:
            continue

        # Trailing whitespace
        if line.endswith(" ") or line.endswith("\t"):
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

        # Mixed indentation
        if line.startswith("\t ") or line.startswith(" \t"):
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

        # Line too long
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

        # TODO marker
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

        # Commented-out code blocks
        stripped = line.strip()
        if stripped.startswith("#") and re.search(r"^#\s*(def |return |import |from |for |if |class |elif |else:)", stripped):
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
                    "description": "Commented-out code increases noise and rots over time. Rely on Git version history instead.",
                    "evidence": get_snippet(lines, comment_block_start),
                    "confidence": "high",
                    "fix_suggestion": "Delete commented-out code.",
                })
            consecutive_commented_code = 0

        # Typos in comments
        if "#" in line:
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

    # AST-based complexity and naming checks for Python
    if path.endswith((".py", ".pyi")):
        try:
            tree = ast.parse(text, filename=path)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Long function
                    end = getattr(node, "end_lineno", node.lineno)
                    fn_len = end - node.lineno
                    if fn_len > max_fn_len:
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

                    # Many arguments
                    n_args = len(node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
                    if n_args > max_args:
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

                    # Typo in function name
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

                # Check variable name typos
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

            # Check deep indentation / nesting
            for idx, line in enumerate(lines, 1):
                indent = len(line) - len(line.lstrip(" "))
                if indent >= (max_nesting + 1) * 4 and line.strip() and not line.strip().startswith(("#", '"', "'")):
                    rule = "deep-nesting"
                    findings.append({
                        "rule": rule,
                        "severity": sev.get(rule, "P2"),
                        "category": categories.get(rule, "cosmetic"),
                        "file": path,
                        "line": idx,
                        "col": indent,
                        "title": f"Deeply nested code ({indent // 4} levels deep, exceeds {max_nesting})",
                        "description": "Deeply nested code significantly increases cognitive load and branch complexity.",
                        "evidence": get_snippet(lines, idx, indent),
                        "confidence": "low",
                        "fix_suggestion": "Invert conditions to return early (guard clauses) or extract helper functions.",
                    })
                    break  # Flag at most one per file to avoid noise

        except Exception:
            pass

    return findings
