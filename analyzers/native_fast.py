"""VCC Native Fast Analyzer — Integrates with high-performance native linters (Ruff) if available.

Transparently accelerates Python analysis and augments VCC's custom AST engine.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

RUFF_BIN = shutil.which("ruff") or (
    os.path.expanduser("~/.local/bin/ruff") if os.path.exists(os.path.expanduser("~/.local/bin/ruff")) else None
)


def has_ruff() -> bool:
    return RUFF_BIN is not None and os.access(RUFF_BIN, os.X_OK)


def run_ruff(target: str, rules: dict) -> list[dict]:
    if not has_ruff():
        return []

    sev = rules.get("severity", {})
    categories = rules.get("categories", {})
    findings: list[dict] = []

    try:
        skip_dirs = [
            ".git", "__pycache__", ".pytest_cache", ".ruff_cache",
            ".venv", "venv", "env", ".env", "node_modules", "dist",
            "build", ".mypy_cache", "repros", "fixes", "vibe code checker"
        ]
        cmd = [
            RUFF_BIN,
            "check",
            "--output-format", "json",
            "--no-cache",
            "--select", "E,F,W,B,S,ASYNC",
            "--exclude", ",".join(skip_dirs),
            target,
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        raw_output = proc.stdout.strip()
        if not raw_output:
            return []

        data = json.loads(raw_output)
        for item in data:
            code = item.get("code", "")
            msg = item.get("message", "")
            filename = item.get("filename", "")
            location = item.get("location", {})
            row = location.get("row", 1)
            col = location.get("column", 0)

            # Map Ruff severity
            if code.startswith(("F821", "F822", "F823", "E999", "S")):
                severity = "P0"
                category = "security" if code.startswith("S") else "logic"
            elif code.startswith(("B", "ASYNC", "E711", "E712", "F")):
                severity = "P1"
                category = "async" if code.startswith("ASYNC") else "logic"
            else:
                severity = "P2"
                category = "cosmetic"

            rule_name = f"ruff-{code.lower()}" if code else "ruff-lint"
            findings.append({
                "rule": rule_name,
                "severity": sev.get(rule_name, severity),
                "category": categories.get(rule_name, category),
                "file": filename,
                "line": row,
                "col": col,
                "title": f"[{code}] {msg}",
                "description": f"Ruff reported: {msg}",
                "evidence": f"Line {row}, Col {col}: {msg}",
                "confidence": "high",
                "fix_suggestion": item.get("fix", {}).get("message", "Review and fix lint warning."),
            })

    except Exception:
        pass

    return findings
