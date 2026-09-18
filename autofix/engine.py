"""VCC Deterministic Auto-Fixer.

Safely fixes cosmetic, formatting, and simple mechanical code bugs without risking regressions.
"""
from __future__ import annotations

import re

NONE_EQ_RE = re.compile(r"(\b\w+)\s*==\s*None\b")
NONE_NE_RE = re.compile(r"(\b\w+)\s*!=\s*None\b")
BOOL_EQ_TRUE_RE = re.compile(r"(\b\w+)\s*==\s*True\b")
BOOL_EQ_FALSE_RE = re.compile(r"(\b\w+)\s*==\s*False\b")


def fix_file(path: str) -> list[str]:
    """Applies deterministic, safe fixes to a file. Returns list of applied fix descriptions."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return []

    fixes: list[str] = []
    modified = False

    # 1. Missing final newline
    if raw and not raw.endswith(b"\n"):
        raw += b"\n"
        fixes.append("Added missing final newline")
        modified = True

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return fixes

    lines = text.splitlines(keepends=True)
    new_lines = []

    # 2. Trailing whitespace
    has_trailing = False
    for line in lines:
        cleaned = line.rstrip(" \t\r\n") + ("\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "")
        if cleaned != line:
            has_trailing = True
        new_lines.append(cleaned)

    if has_trailing:
        fixes.append("Removed trailing whitespace")
        lines = new_lines
        modified = True

    text = "".join(lines)

    # 3. Python specific deterministic syntax improvements
    if path.endswith((".py", ".pyi")):
        # == None -> is None
        if NONE_EQ_RE.search(text):
            text, n = NONE_EQ_RE.subn(r"\1 is None", text)
            if n > 0:
                fixes.append(f"Replaced {n} instance(s) of `== None` with `is None`")
                modified = True

        # != None -> is not None
        if NONE_NE_RE.search(text):
            text, n = NONE_NE_RE.subn(r"\1 is not None", text)
            if n > 0:
                fixes.append(f"Replaced {n} instance(s) of `!= None` with `is not None`")
                modified = True

        # == True
        if BOOL_EQ_TRUE_RE.search(text):
            text, n = BOOL_EQ_TRUE_RE.subn(r"\1", text)
            if n > 0:
                fixes.append(f"Simplified {n} instance(s) of `== True`")
                modified = True

        # == False
        if BOOL_EQ_FALSE_RE.search(text):
            text, n = BOOL_EQ_FALSE_RE.subn(r"not \1", text)
            if n > 0:
                fixes.append(f"Simplified {n} instance(s) of `== False` to `not ...`")
                modified = True

    if modified:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            return [f"Failed to write: {e}"]

    return fixes


def run_safe_autofix(files: list[str]) -> dict:
    """Runs deterministic autofix across all specified files."""
    results = {}
    total_fixes = 0

    for file_path in files:
        applied = fix_file(file_path)
        if applied:
            results[file_path] = applied
            total_fixes += len(applied)

    return {
        "files_modified": len(results),
        "total_fixes": total_fixes,
        "details": results,
    }
