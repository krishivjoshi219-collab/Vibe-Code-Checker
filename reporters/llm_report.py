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


def write_json_report(
    path: str,
    target: str,
    stats: dict,
    sorted_findings: list[dict],
) -> None:
    """Writes machine-readable report.json."""
    report_data = {
        "tool": "vibe-code-checker",
        "version": "2.0.1",
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": round(stats.get("duration_s", 0.0) * 1000, 2),
        "files_scanned": stats.get("file_count", 0),
        "summary": {
            "total": len(sorted_findings),
            "P0_critical": stats.get("p0", 0),
            "P1_major": stats.get("p1", 0),
            "P2_minor": stats.get("p2", 0),
            "categories": stats.get("categories", {}),
        },
        "findings": sorted_findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)


def write_md_report(
    path: str,
    target: str,
    stats: dict,
    sorted_findings: list[dict],
) -> None:
    """Writes human-readable report.md."""
    dur = stats.get("duration_s", 0.0)
    time_str = f"{dur * 1000:.1f}ms" if dur < 1.0 else f"{dur:.2f}s"
    with open(path, "w", encoding="utf-8") as f:
        f.write("# ⚡ Vibe Code Checker — Production Report\n\n")
        f.write("## 📊 Executive Summary\n\n")
        f.write(f"- **Target Directory:** `{target}`\n")
        f.write(f"- **Files Scanned:** `{stats.get('file_count', 0)}` in `{time_str}` (⚡ Instant)\n")
        f.write(f"- **Total Findings:** `{len(sorted_findings)}`\n\n")

        f.write("| Severity | Count | Impact |\n")
        f.write("| :--- | :---: | :--- |\n")
        f.write(f"| 🚨 **P0 Critical** | `{stats.get('p0', 0)}` | Crash, security flaw, data loss, syntax failure |\n")
        f.write(f"| ⚠️ **P1 Major** | `{stats.get('p1', 0)}` | High-probability bug, resource leak, async flaw |\n")
        f.write(f"| ℹ️ **P2 Minor** | `{stats.get('p2', 0)}` | Style violation, typo, dead code, maintainability |\n\n")

        f.write("### Category Breakdown\n\n")
        for cat, count in sorted(stats.get("categories", {}).items()):
            f.write(f"- **{cat.capitalize()}:** {count}\n")
        f.write("\n---\n\n")

        current_sev = None
        for b in sorted_findings:
            sev = b.get("severity", "P2")
            if sev != current_sev:
                current_sev = sev
                label = "🚨 P0 — Critical" if sev == "P0" else ("⚠️ P1 — Major" if sev == "P1" else "ℹ️ P2 — Minor")
                f.write(f"## {label}\n\n")

            f.write(f"### `{b['id']}` {b['title']}\n\n")
            f.write(f"- **File:** `{b['file']}:{b['line']}:{b['col']}`\n")
            f.write(
                f"- **Rule:** `{b['rule']}` | **Category:** `{b.get('category', 'logic')}` "
                f"| **Confidence:** `{b.get('confidence', 'high')}`\n"
            )
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

    stats = {
        "duration_s": duration_s,
        "file_count": file_count,
        "p0": p0_count,
        "p1": p1_count,
        "p2": p2_count,
        "categories": cat_counts,
    }

    json_path = os.path.join(base_dir, "report.json")
    write_json_report(json_path, target, stats, sorted_findings)

    md_path = os.path.join(base_dir, "report.md")
    write_md_report(md_path, target, stats, sorted_findings)

    return json_path, md_path
