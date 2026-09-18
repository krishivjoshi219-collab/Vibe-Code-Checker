"""VCC Multi-Language & Config Analyzer.

Detects bugs and bad practices in JSON, YAML, TOML, JS/TS, HTML, CSS, Dockerfile, and Shell scripts.
"""
from __future__ import annotations

import json
import os
import re

try:
    import tomllib
except ImportError:
    tomllib = None

# Regex patterns for various file types
JS_LOOSE_EQ = re.compile(r"(?<![!=<>&|])==(?![=])|(?<![!=])!=(?![=])")
JS_DEBUGGER = re.compile(r"\bdebugger\s*;?")
JS_EVAL = re.compile(r"\beval\s*\(")
JS_CONSOLE = re.compile(r"\bconsole\.(log|debug|info)\s*\(")
JS_VAR = re.compile(r"\bvar\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=")

HTML_IMG_NO_ALT = re.compile(r"<img\b(?![^>]*\balt=)[^>]*>", re.I)
HTML_EMPTY_HREF = re.compile(r'<a\b[^>]*\bhref=["\'](?:#|javascript:void\(0\)|)["\'][^>]*>', re.I)
HTML_INLINE_EVENT = re.compile(r'\b(on(?:click|load|error|change|submit|mouseover|keydown))\s*=\s*["\']', re.I)

CSS_EMPTY_RULE = re.compile(r"([^{}]+)\s*\{\s*\}")
CSS_INVALID_HEX = re.compile(r"#(?:[0-9a-fA-F]{1,2}|[0-9a-fA-F]{5}|[0-9a-fA-F]{7}|[0-9a-fA-F]{9,})\b")

DOCKER_LATEST = re.compile(r"^\s*FROM\s+([^\s:]+)(?::latest)?\s*$", re.I)
DOCKER_APT_DIRTY = re.compile(r"apt-get\s+update\b(?!.*rm\s+-rf\s+/var/lib/apt/lists)", re.I | re.DOTALL)
DOCKER_SENSITIVE = re.compile(r"^\s*(?:COPY|ADD)\s+.*\b(\.env|\.pem|\.key|id_rsa|credentials)\b", re.I)

SHELL_DANGEROUS_RM = re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+\$([a-zA-Z_][a-zA-Z0-9_]*)")


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


def analyze_multilang(path: str, rules: dict) -> list[dict]:
    findings: list[dict] = []
    sev = rules.get("severity", {})
    categories = rules.get("categories", {})
    fname = os.path.basename(path).lower()
    ext = os.path.splitext(path)[1].lower()

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return []

    lines = content.splitlines()

    # --- JSON Files ---
    if ext == ".json":
        try:
            json.loads(content)
        except json.JSONDecodeError as e:
            rule = "broken-json-syntax"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P0"),
                "category": "syntax",
                "file": path,
                "line": e.lineno,
                "col": e.colno,
                "title": f"Invalid JSON syntax: {e.msg}",
                "description": f"Failed to parse JSON: {e.msg} at line {e.lineno}, column {e.colno}.",
                "evidence": get_snippet(lines, e.lineno, e.colno),
                "confidence": "high",
                "fix_suggestion": "Fix JSON syntax error (check for trailing commas, unquoted keys, single quotes).",
            })
        return findings

    # --- YAML Files ---
    if ext in (".yaml", ".yml"):
        for idx, line in enumerate(lines, 1):
            if "\t" in line and (line.startswith("\t") or re.match(r"^\s*\t", line)):
                rule = "broken-yaml-syntax"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P0"),
                    "category": "syntax",
                    "file": path,
                    "line": idx,
                    "col": line.find("\t"),
                    "title": "Tab indentation in YAML file (strictly forbidden by YAML spec)",
                    "description": "YAML specification does not allow tab characters for indentation. Tabs cause YAML parsers to fail.",
                    "evidence": get_snippet(lines, idx, line.find("\t")),
                    "confidence": "high",
                    "fix_suggestion": "Replace all tabs with spaces.",
                })
        return findings

    # --- TOML Files ---
    if ext == ".toml" and tomllib is not None:
        try:
            tomllib.loads(content)
        except tomllib.TOMLDecodeError as e:
            rule = "broken-toml-syntax"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P0"),
                "category": "syntax",
                "file": path,
                "line": 1,
                "col": 0,
                "title": f"Invalid TOML syntax: {e}",
                "description": f"Failed to parse TOML file: {e}",
                "evidence": content[:200],
                "confidence": "high",
                "fix_suggestion": "Correct TOML syntax.",
            })
        return findings

    # --- JavaScript / TypeScript ---
    if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Loose equality (== or !=)
            m_eq = JS_LOOSE_EQ.search(line)
            if m_eq:
                rule = "js-loose-equality"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_eq.start(),
                    "title": f"Loose equality operator `{m_eq.group(0)}` in JS/TS",
                    "description": "Loose equality (`==` and `!=`) performs implicit type coercion, leading to unexpected truthiness bugs.",
                    "evidence": get_snippet(lines, idx, m_eq.start()),
                    "confidence": "high",
                    "fix_suggestion": f"Replace `{m_eq.group(0)}` with `{'===' if '==' in m_eq.group(0) else '!=='}`.",
                })

            # Debugger statement
            m_dbg = JS_DEBUGGER.search(line)
            if m_dbg:
                rule = "js-debugger-statement"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_dbg.start(),
                    "title": "`debugger;` statement left in code",
                    "description": "Debugger statements pause code execution in browser/node debuggers and should not ship to production.",
                    "evidence": get_snippet(lines, idx, m_dbg.start()),
                    "confidence": "high",
                    "fix_suggestion": "Remove `debugger;` statement.",
                })

            # eval() usage
            m_eval = JS_EVAL.search(line)
            if m_eval:
                rule = "js-eval-usage"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_eval.start(),
                    "title": "`eval()` used in JavaScript/TypeScript",
                    "description": "eval() executes strings as code, posing serious security and performance risks.",
                    "evidence": get_snippet(lines, idx, m_eval.start()),
                    "confidence": "high",
                    "fix_suggestion": "Replace `eval()` with structured JSON parsing or functions.",
                })

        return findings

    # --- HTML Files ---
    if ext in (".html", ".htm"):
        for idx, line in enumerate(lines, 1):
            if HTML_IMG_NO_ALT.search(line):
                rule = "html-img-missing-alt"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": 0,
                    "title": "`<img>` tag missing `alt` attribute",
                    "description": "Images without `alt` attributes degrade web accessibility (WCAG) and SEO.",
                    "evidence": get_snippet(lines, idx),
                    "confidence": "high",
                    "fix_suggestion": "Add descriptive `alt=\"...\"` or `alt=\"\"` for decorative images.",
                })
            if HTML_EMPTY_HREF.search(line):
                rule = "html-empty-href"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": 0,
                    "title": "Anchor `<a>` with empty or `#` href",
                    "description": "Anchors with `#` href cause page scrolling to top. Use `<button>` for interactive actions.",
                    "evidence": get_snippet(lines, idx),
                    "confidence": "med",
                    "fix_suggestion": "Use `<button type=\"button\">` instead of `<a href=\"#\">`.",
                })
            m_ev = HTML_INLINE_EVENT.search(line)
            if m_ev:
                rule = "html-inline-event-handler"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_ev.start(),
                    "title": f"Inline event handler `{m_ev.group(1)}` in HTML",
                    "description": "Inline event handlers violate Content Security Policy (CSP) and increase XSS risk.",
                    "evidence": get_snippet(lines, idx, m_ev.start()),
                    "confidence": "high",
                    "fix_suggestion": "Attach event listeners using `.addEventListener()` in external script.",
                })
        return findings

    # --- CSS Files ---
    if ext in (".css", ".scss"):
        for idx, line in enumerate(lines, 1):
            m_empty = CSS_EMPTY_RULE.search(line)
            if m_empty:
                rule = "css-empty-ruleset"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_empty.start(),
                    "title": f"Empty CSS ruleset `{m_empty.group(1).strip()}`",
                    "description": "Empty style rulesets add dead bytes with zero visual effect.",
                    "evidence": get_snippet(lines, idx),
                    "confidence": "high",
                    "fix_suggestion": "Remove empty ruleset.",
                })
            m_hex = CSS_INVALID_HEX.search(line)
            if m_hex:
                rule = "css-invalid-hex-color"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P2"),
                    "category": "multilang",
                    "file": path,
                    "line": idx,
                    "col": m_hex.start(),
                    "title": f"Invalid hex color `{m_hex.group(0)}` in CSS",
                    "description": "Hex colors must be 3, 4, 6, or 8 hexadecimal digits.",
                    "evidence": get_snippet(lines, idx, m_hex.start()),
                    "confidence": "high",
                    "fix_suggestion": "Correct hex color length.",
                })
        return findings

    # --- Dockerfile ---
    if fname in ("dockerfile", "dockerfile.dev", "dockerfile.prod") or ext == ".dockerfile":
        has_user = False
        for idx, line in enumerate(lines, 1):
            if re.match(r"^\s*USER\s+", line, re.I) and not re.match(r"^\s*USER\s+root\b", line, re.I):
                has_user = True
            m_lat = DOCKER_LATEST.search(line)
            if m_lat:
                rule = "docker-latest-tag"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "config",
                    "file": path,
                    "line": idx,
                    "col": 0,
                    "title": f"Unpinned `:latest` or unversioned Docker image `{m_lat.group(1)}`",
                    "description": "Using `:latest` or omitting image tags causes non-deterministic builds and breaking upgrades.",
                    "evidence": get_snippet(lines, idx),
                    "confidence": "high",
                    "fix_suggestion": f"Pin image to a specific version or digest (e.g. `FROM {m_lat.group(1)}:1.2-slim`).",
                })
            m_sens = DOCKER_SENSITIVE.search(line)
            if m_sens:
                rule = "docker-sensitive-copy"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "config",
                    "file": path,
                    "line": idx,
                    "col": 0,
                    "title": f"Sensitive file `{m_sens.group(1)}` copied into Docker image",
                    "description": "Secrets, keys, or .env files copied into Docker images leak through layers and public registries.",
                    "evidence": get_snippet(lines, idx),
                    "confidence": "high",
                    "fix_suggestion": "Inject secrets at runtime via environment variables or secret mounts.",
                })

        if not has_user:
            rule = "docker-root-user"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P1"),
                "category": "config",
                "file": path,
                "line": len(lines) or 1,
                "col": 0,
                "title": "Missing non-root `USER` declaration in Dockerfile",
                "description": "Containers running as root allow container breakout risks. Define a non-root user.",
                "evidence": "[End of Dockerfile without USER declaration]",
                "confidence": "med",
                "fix_suggestion": "Add `USER nonroot` or `USER 1001` before ENTRYPOINT/CMD.",
            })
        return findings

    # --- Shell Scripts ---
    if ext in (".sh", ".bash"):
        has_set_e = any(re.match(r"^\s*set\s+-[a-zA-Z]*e", ln) for ln in lines)
        if not has_set_e:
            rule = "shell-missing-strict"
            findings.append({
                "rule": rule,
                "severity": sev.get(rule, "P1"),
                "category": "config",
                "file": path,
                "line": 1,
                "col": 0,
                "title": "Missing `set -e` or strict mode in shell script",
                "description": "Shell scripts without `set -e` continue running after failed commands, risking cascading failures.",
                "evidence": get_snippet(lines, 1),
                "confidence": "med",
                "fix_suggestion": "Add `set -euo pipefail` near the top of the script.",
            })
        for idx, line in enumerate(lines, 1):
            m_rm = SHELL_DANGEROUS_RM.search(line)
            if m_rm:
                rule = "shell-dangerous-rm"
                findings.append({
                    "rule": rule,
                    "severity": sev.get(rule, "P1"),
                    "category": "config",
                    "file": path,
                    "line": idx,
                    "col": m_rm.start(),
                    "title": f"Unquoted variable in `rm -rf ${m_rm.group(1)}`",
                    "description": f"If `${m_rm.group(1)}` is empty or unset, this executes `rm -rf /`, destroying the filesystem.",
                    "evidence": get_snippet(lines, idx, m_rm.start()),
                    "confidence": "high",
                    "fix_suggestion": f"Quote the variable: `rm -rf \"${m_rm.group(1)}\"` and check variable is set first.",
                })
        return findings

    return findings
