"""VCC Reporter — Structured report.json and executive report.md with LLM fix prompts."""
from __future__ import annotations

import json
import os
import time

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2}

GENERIC_PROMPT = """Fix this bug in `{file}`. Keep changes minimal and preserve existing formatting.

Bug ID: {id} [{severity}] [{category}] Rule: {rule}
Location: {file}:{line}:{col}
Title: {title}
Description: {description}

Evidence / Snippet:
```
{evidence}
```

Suggested Fix:
{fix}

Instructions:
1. Provide the exact replacement code block or diff.
2. Explain in 1 sentence what caused the bug and how your fix resolves it.
"""


def build_fix_prompt(b: dict) -> str:
    return GENERIC_PROMPT.format(
        id=b.get("id", "?"),
        severity=b.get("severity", "?"),
        category=b.get("category", "?"),
        rule=b.get("rule", "?"),
        file=b.get("file", "?"),
        line=b.get("line", "?"),
        col=b.get("col", "?"),
        title=b.get("title", "?"),
        description=b.get("description", ""),
        evidence=b.get("evidence", "")[:2000],
        fix=b.get("fix_suggestion", "Apply standard fix."),
    )


def write_reports(
    base_dir: str,
    target: str,
    file_count: int,
    duration_s: float,
    findings: list[dict],
) -> tuple[str, str]:
    # Sort findings by severity (P0 first), then file, then line
    sorted_findings = sorted(
        findings,
        key=lambda b: (
            SEV_ORDER.get(b.get("severity", "P2"), 9),
            b.get("file", ""),
            b.get("line", 0),
        ),
    )

    # Assign clean IDs and prompts
    p0_count = sum(1 for b in sorted_findings if b.get("severity") == "P0")
    p1_count = sum(1 for b in sorted_findings if b.get("severity") == "P1")
    p2_count = sum(1 for b in sorted_findings if b.get("severity") == "P2")

    for i, b in enumerate(sorted_findings, 1):
        sev = b.get("severity", "P2")
        b["id"] = f"VCC-{sev}-{i:03d}"
        b["fix_prompt"] = build_fix_prompt(b)

    cat_counts: dict[str, int] = {}
    for b in sorted_findings:
        cat = b.get("category", "other")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # 1. Write report.json
    json_path = os.path.join(base_dir, "report.json")
    report_data = {
        "tool": "vibe-code-checker",
        "version": "2.0.0",
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": round(duration_s * 1000, 2),
        "files_scanned": file_count,
        "summary": {
            "total": len(sorted_findings),
            "P0_critical": p0_count,
            "P1_major": p1_count,
            "P2_minor": p2_count,
            "categories": cat_counts,
        },
        "findings": sorted_findings,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # 2. Write report.md
    md_path = os.path.join(base_dir, "report.md")
    time_str = f"{duration_s * 1000:.1f}ms" if duration_s < 1.0 else f"{duration_s:.2f}s"

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# ⚡ Vibe Code Checker — Production Report\n\n")
        f.write("## 📊 Executive Summary\n\n")
        f.write(f"- **Target Directory:** `{target}`\n")
        f.write(f"- **Files Scanned:** `{file_count}` in `{time_str}` (⚡ Instant)\n")
        f.write(f"- **Total Findings:** `{len(sorted_findings)}`\n\n")

        f.write("| Severity | Count | Impact |\n")
        f.write("| :--- | :---: | :--- |\n")
        f.write(f"| 🚨 **P0 Critical** | `{p0_count}` | Crash, security vulnerability, data loss, or syntax failure |\n")
        f.write(f"| ⚠️ **P1 Major** | `{p1_count}` | High-probability bug, resource leak, or unhandled async condition |\n")
        f.write(f"| ℹ️ **P2 Minor / Cosmetic** | `{p2_count}` | Style violation, typo, dead code, or maintainability smell |\n\n")

        f.write("### Category Breakdown\n\n")
        for cat, count in sorted(cat_counts.items()):
            f.write(f"- **{cat.capitalize()}:** {count}\n")
        f.write("\n---\n\n")

        current_sev = None
        for b in sorted_findings:
            sev = b.get("severity", "P2")
            if sev != current_sev:
                current_sev = sev
                label = "🚨 P0 — Critical Issues" if sev == "P0" else ("⚠️ P1 — Major Bugs" if sev == "P1" else "ℹ️ P2 — Minor & Cosmetic Issues")
                f.write(f"## {label}\n\n")

            f.write(f"### `{b['id']}` {b['title']}\n\n")
            f.write(f"- **File:** `{b['file']}:{b['line']}:{b['col']}`\n")
            f.write(f"- **Rule:** `{b['rule']}` | **Category:** `{b.get('category', 'logic')}` | **Confidence:** `{b.get('confidence', 'high')}`\n")
            if b.get("description"):
                f.write(f"- **Description:** {b['description']}\n")

            if b.get("evidence"):
                f.write("\n```\n")
                f.write(b["evidence"])
                f.write("\n```\n")

            if b.get("fix_suggestion"):
                f.write(f"\n💡 **Recommended Fix:** {b['fix_suggestion']}\n\n")

            f.write("<details><summary>🤖 LLM Autofix Prompt</summary>\n\n")
            f.write("```\n")
            f.write(b["fix_prompt"])
            f.write("\n```\n\n</details>\n\n---\n\n")

    return json_path, md_path
