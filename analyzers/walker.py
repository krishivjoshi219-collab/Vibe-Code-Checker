"""VCC File Walker — Fast, smart directory traversal ignoring caches, venvs, and build artifacts."""
from __future__ import annotations

import os

DEFAULT_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".tox",
    ".eggs",
    "site-packages",
    "repros",
    "fixes",
    ".idea",
    ".vscode",
}

DEFAULT_SKIP_FILES = {
    "report.json",
    "report.md",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

DEFAULT_EXTENSIONS = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sh",
    ".bash",
}


def discover_files(target: str, rules: dict) -> list[str]:
    allow = rules.get("allowlist", {})
    skip_dirs = set(allow.get("dirs", DEFAULT_SKIP_DIRS)) | DEFAULT_SKIP_DIRS
    skip_files = set(allow.get("files", DEFAULT_SKIP_FILES)) | DEFAULT_SKIP_FILES
    extensions = set(allow.get("extensions", DEFAULT_EXTENSIONS)) | DEFAULT_EXTENSIONS

    target_abs = os.path.abspath(target)
    if os.path.isfile(target_abs):
        return [target_abs]

    found: list[str] = []
    for root, dirs, names in os.walk(target_abs):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

        for n in names:
            if n in skip_files:
                continue
            ext = os.path.splitext(n)[1].lower()
            is_special = n.lower() in ("dockerfile", "dockerfile.dev", "dockerfile.prod")
            if ext in extensions or is_special:
                p = os.path.join(root, n)
                # Avoid scanning vibe code checker's internal generated repros or fixes
                if "vibe code checker" in p and any(x in p for x in ("/repros/", "/fixes/", "\\repros\\", "\\fixes\\")):
                    continue
                found.append(p)

    return sorted(found)
