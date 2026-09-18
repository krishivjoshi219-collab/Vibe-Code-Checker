#!/usr/bin/env python3
"""Vibe Code Checker (VCC) — Production-Grade Instant Bug Engine.

Catches logical, security, async, resource, syntax, multi-language, and cosmetic bugs.
Runs blazingly fast using pure stdlib with zero required dependencies.

Usage:
    python check.py [--target PATH] [--severity P0|P1|P2] [--category CAT]
    python check.py --fix                # Automatically fix cosmetic and mechanical issues
    python check.py --autofix            # Interactive AI autofix using Zen FREE models
    python check.py --fail-on P0         # CI/CD gate: exits with 1 if P0 issues exist
    python check.py --format compact     # GCC/ESLint-style one-line output
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from analyzers import native_fast, scan_file, walker  # noqa: E402
from autofix import engine as autofix_engine, gate, zen_client  # noqa: E402
from reporters import llm_report, terminal  # noqa: E402


def load_rules(rules_path: str | None = None) -> dict:
    path = rules_path or os.path.join(BASE_DIR, "rules.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def run_analysis(
    target: str,
    rules: dict,
    use_ruff: bool = True,
    workers: int | None = None,
) -> tuple[list[dict], int, float]:
    start_time = time.perf_counter()
    files = walker.discover_files(target, rules)
    findings: list[dict] = []

    worker_count = workers or min(16, os.cpu_count() or 4)

    def scan_single(fpath: str) -> list[dict]:
        try:
            return scan_file(fpath, rules)
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        for file_findings in executor.map(scan_single, files):
            findings.extend(file_findings)

    # Optionally merge native Ruff checks if available
    if use_ruff and native_fast.has_ruff():
        try:
            ruff_findings = native_fast.run_ruff(target, rules)
            findings.extend(ruff_findings)
        except Exception:
            pass

    # Deduplicate findings by (file, line, rule)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("rule"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    duration = time.perf_counter() - start_time
    return unique_findings, len(files), duration


def cmd_fix(target: str, rules: dict) -> int:
    print(f"\n{terminal.BOLD}{terminal.CYAN}⚡ Running Safe Deterministic Auto-Fixer on:{terminal.RESET} {target}")
    files = walker.discover_files(target, rules)
    result = autofix_engine.run_safe_autofix(files)

    print(f"Files inspected: {len(files)}")
    print(f"Files modified:  {terminal.GREEN}{result['files_modified']}{terminal.RESET}")
    print(f"Total fixes:     {terminal.GREEN}{result['total_fixes']}{terminal.RESET}\n")

    for fpath, fix_list in result["details"].items():
        rel = os.path.relpath(fpath, os.getcwd())
        print(f"  {terminal.BOLD}{rel}{terminal.RESET}")
        for fix_desc in fix_list:
            print(f"    ✓ {terminal.GREEN}{fix_desc}{terminal.RESET}")

    return 0


def cmd_autofix(args) -> int:
    jp = os.path.join(BASE_DIR, "report.json")
    if not os.path.exists(jp):
        print("No report.json found. Please run analysis first: python check.py")
        return 1

    with open(jp, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    if not findings:
        print("No findings in report.json to fix.")
        return 0

    items = findings[: args.limit]
    print(f"\nFound {len(findings)} total findings. Processing up to {len(items)} (limit={args.limit}).")
    print(f"{terminal.YELLOW}Note: AI auto-fix uses Zen FREE models. Never transmit confidential keys or data.{terminal.RESET}")

    if not gate.ask_yes_no("Launch AI auto-fix with Zen FREE model?"):
        print("Cancelled — no external calls made.")
        return 0

    sel = gate.pick_model(args.model)
    if not sel:
        print("Cancelled — no model selected.")
        return 0

    model, endpoint, kind = sel
    key = zen_client.get_key()
    if not key:
        print("Cancelled — no API key provided.")
        return 0

    fixes_dir = os.path.join(BASE_DIR, "fixes")
    os.makedirs(fixes_dir, exist_ok=True)

    for b in items:
        print(f"\n{terminal.BOLD}--- [{b.get('id', '?')}] {b.get('file')}:{b.get('line')} [{b.get('rule')}] ---{terminal.RESET}")
        try:
            prompt = b.get("fix_prompt", "")
            response = zen_client.complete(model, endpoint, kind, key, prompt)
        except Exception as e:
            print(f"Call failed: {e}")
            continue

        fix_path = os.path.join(fixes_dir, f"{b.get('id', 'fix')}.suggestion.md")
        with open(fix_path, "w", encoding="utf-8") as f:
            f.write(f"# Fix for {b.get('id')} ({b.get('file')}:{b.get('line')})\nModel: {model}\n\n{response}\n")

        print(f"Saved suggestion: {terminal.GREEN}{os.path.relpath(fix_path, BASE_DIR)}{terminal.RESET}")
        preview = response[:1200] + ("..." if len(response) > 1200 else "")
        print(f"{terminal.DIM}{preview}{terminal.RESET}")

        if not gate.ask_yes_no("Continue to next finding?"):
            break

    print(f"\n{terminal.GREEN}Done! Suggestions saved in `{os.path.relpath(fixes_dir, os.getcwd())}/`.{terminal.RESET}")
    return 0


def cmd_list_rules(rules: dict):
    print(f"\n{terminal.BOLD}{terminal.CYAN}Supported Rules & Severity Taxonomy:{terminal.RESET}\n")
    sev_map = rules.get("severity", {})
    cat_map = rules.get("categories", {})

    print(f"{'Rule ID':<35} {'Severity':<10} {'Category':<12}")
    print("-" * 60)
    for rule, sev in sorted(sev_map.items()):
        cat = cat_map.get(rule, "other")
        sev_color = terminal.SEV_COLORS.get(sev, terminal.WHITE)
        print(f"{rule:<35} {sev_color}{sev:<10}{terminal.RESET} {cat:<12}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Vibe Code Checker (VCC) — Production-Grade Instant Bug Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target_pos", nargs="?", default=None, help="Target directory or file to scan (default: .)")
    parser.add_argument("--target", "-t", default=None, help="Target directory or file to scan")
    parser.add_argument("--severity", "-s", choices=["P0", "P1", "P2"], default=None, help="Minimum severity to report")
    parser.add_argument("--category", "-c", default=None, help="Filter by category (logic, security, async, resource, cosmetic, syntax, config)")
    parser.add_argument("--fail-on", choices=["P0", "P1", "P2", "none"], default="P0", help="Exit with 1 if issues >= severity are found (default: P0)")
    parser.add_argument("--format", "-f", choices=["pretty", "compact", "json"], default="pretty", help="Terminal output format")
    parser.add_argument("--fix", action="store_true", help="Apply safe deterministic fixes to cosmetic/mechanical bugs")
    parser.add_argument("--autofix", action="store_true", help="Launch interactive AI autofix using Zen FREE models")
    parser.add_argument("--model", default=None, help="Zen FREE model ID for --autofix")
    parser.add_argument("--limit", type=int, default=5, help="Max items to process in --autofix")
    parser.add_argument("--workers", "-w", type=int, default=None, help="Number of parallel worker threads")
    parser.add_argument("--no-ruff", action="store_true", help="Disable native Ruff accelerator even if available")
    parser.add_argument("--rule-list", action="store_true", help="Display all supported rules and exit")
    parser.add_argument("--output-dir", default=BASE_DIR, help="Directory to save report.json and report.md")

    args = parser.parse_args(argv)
    rules = load_rules()

    if args.rule_list:
        cmd_list_rules(rules)
        return 0

    # Resolve target path (treat redundant 'check' keyword as self-alias)
    raw_target = args.target or args.target_pos or "."
    if raw_target == "check" and (not os.path.exists("check") or os.path.abspath(raw_target) == os.path.join(BASE_DIR, "check")):
        raw_target = "."
    target = os.path.abspath(raw_target)

    if args.fix:
        return cmd_fix(target, rules)

    if args.autofix:
        return cmd_autofix(args)

    if args.format == "pretty":
        terminal.print_banner()

    findings, file_count, duration_s = run_analysis(
        target=target,
        rules=rules,
        use_ruff=not args.no_ruff,
        workers=args.workers,
    )

    # Filter findings based on CLI flags
    filtered = findings
    if args.severity:
        sev_rank = {"P0": 0, "P1": 1, "P2": 2}
        target_rank = sev_rank[args.severity]
        filtered = [f for f in filtered if sev_rank.get(f["severity"], 2) <= target_rank]

    if args.category:
        cat_lower = args.category.lower()
        filtered = [f for f in filtered if f.get("category", "").lower() == cat_lower]

    # Save reports
    jp, mp = llm_report.write_reports(
        base_dir=args.output_dir,
        target=target,
        file_count=file_count,
        duration_s=duration_s,
        findings=filtered,
    )

    # Render output
    if args.format == "pretty":
        for f in filtered:
            terminal.render_card(f)
        terminal.render_summary(target, file_count, duration_s, filtered)
        print(f"📄 Reports generated in: {terminal.BOLD}{args.output_dir}{terminal.RESET}")
        print(f"   • {terminal.CYAN}report.json{terminal.RESET}  (Machine-readable AST diagnostics & fix prompts)")
        print(f"   • {terminal.CYAN}report.md{terminal.RESET}    (Executive markdown report with full details)\n")
        print(f"💡 Run {terminal.BOLD}python check.py --fix{terminal.RESET} to auto-resolve cosmetic/mechanical issues.")
        print(f"🤖 Run {terminal.BOLD}python check.py --autofix{terminal.RESET} for AI-assisted fixes.\n")
    elif args.format == "compact":
        terminal.render_compact(filtered)
    elif args.format == "json":
        print(json.dumps({"target": target, "count": len(filtered), "findings": filtered}, indent=2))

    # Exit code determination
    if args.fail_on != "none":
        sev_rank = {"P0": 0, "P1": 1, "P2": 2}
        fail_rank = sev_rank[args.fail_on]
        has_failure = any(sev_rank.get(f["severity"], 2) <= fail_rank for f in filtered)
        if has_failure:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
