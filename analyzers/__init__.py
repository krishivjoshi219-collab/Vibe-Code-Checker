"""VCC Analyzers package — Unified entry point for all analyzers."""
from __future__ import annotations

import os

from . import cosmetic, multilang, native_fast, python_ast, walker


def scan_file(path: str, rules: dict) -> list[dict]:
    """Scans a single file with relevant analyzers based on file extension."""
    findings: list[dict] = []
    ext = os.path.splitext(path)[1].lower()
    fname = os.path.basename(path).lower()

    # 1. Python AST Analyzer
    if ext in (".py", ".pyi"):
        findings.extend(python_ast.analyze_python_ast(path, rules))

    # 2. Multi-Language / Config Analyzer
    if ext in (
        ".json", ".yaml", ".yml", ".toml", ".js", ".jsx", ".ts", ".tsx",
        ".mjs", ".cjs", ".html", ".htm", ".css", ".scss", ".sh", ".bash"
    ) or fname in ("dockerfile", "dockerfile.dev", "dockerfile.prod") or ext == ".dockerfile":
        findings.extend(multilang.analyze_multilang(path, rules))

    # 3. Cosmetic / Hygiene Analyzer (runs across all text files)
    findings.extend(cosmetic.analyze_cosmetic(path, rules))

    return findings


__all__ = [
    "scan_file",
    "cosmetic",
    "multilang",
    "native_fast",
    "python_ast",
    "walker",
]
