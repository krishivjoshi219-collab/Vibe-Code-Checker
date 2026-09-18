"""VCC Terminal Reporter — Beautiful, high-density terminal output with ANSI colors and snippet rendering."""
from __future__ import annotations

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
UNDERLINE = "\033[4m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"

BG_RED = "\033[41m\033[97m"
BG_YELLOW = "\033[43m\033[30m"
BG_CYAN = "\033[46m\033[30m"
BG_MAGENTA = "\033[45m\033[97m"

SEV_BADGES = {
    "P0": f"{BG_RED} P0 CRITICAL {RESET}",
    "P1": f"{BG_YELLOW} P1 MAJOR {RESET}",
    "P2": f"{BG_CYAN} P2 MINOR {RESET}",
}

SEV_COLORS = {
    "P0": RED,
    "P1": YELLOW,
    "P2": CYAN,
}

CAT_COLORS = {
    "logic": MAGENTA,
    "security": RED,
    "async": BLUE,
    "resource": YELLOW,
    "cosmetic": CYAN,
    "syntax": RED,
    "config": WHITE,
    "multilang": BLUE,
}


def print_banner():
    banner = f"""
{BOLD}{CYAN}╔════════════════════════════════════════════════════════════════════════════╗
║             ⚡ {WHITE}VIBE CODE CHECKER{CYAN} — Production-Grade Bug Engine ⚡             ║
╚════════════════════════════════════════════════════════════════════════════╝{RESET}"""
    print(banner)


def render_card(finding: dict):
    sev = finding.get("severity", "P2")
    cat = finding.get("category", "logic").upper()
    rule = finding.get("rule", "unknown")
    file_path = finding.get("file", "")
    line = finding.get("line", 1)
    col = finding.get("col", 0)
    title = finding.get("title", "")
    desc = finding.get("description", "")
    evidence = finding.get("evidence", "")
    fix = finding.get("fix_suggestion", "")

    badge = SEV_BADGES.get(sev, f"[{sev}]")
    cat_color = CAT_COLORS.get(cat.lower(), WHITE)
    loc_str = f"{UNDERLINE}{file_path}{RESET}:{BOLD}{line}{RESET}:{col}"

    print(f"\n{badge} {cat_color}[{cat}]{RESET} {BOLD}{rule}{RESET}  {loc_str}")
    print(f"  {BOLD}{WHITE}{title}{RESET}")
    if desc and desc != title:
        print(f"  {DIM}{desc}{RESET}")

    if evidence:
        print(f"  {GRAY}┌── Code Snippet ────────────────────────────────────────────────────────┐{RESET}")
        for ev_line in evidence.splitlines():
            if ev_line.startswith(">"):
                print(f"  {GRAY}│{RESET} {RED}{ev_line}{RESET}")
            else:
                print(f"  {GRAY}│{RESET} {ev_line}")
        print(f"  {GRAY}└── Suggestions & Fix ───────────────────────────────────────────────────┘{RESET}")

    if fix:
        print(f"  💡 {GREEN}{BOLD}Fix:{RESET} {GREEN}{fix}{RESET}")


def render_compact(findings: list[dict]):
    for f in findings:
        sev = f.get("severity", "P2")
        sev_col = SEV_COLORS.get(sev, WHITE)
        rule = f.get("rule", "")
        file_path = f.get("file", "")
        line = f.get("line", 1)
        col = f.get("col", 0)
        title = f.get("title", "")
        print(f"{file_path}:{line}:{col}: {sev_col}[{sev}]{RESET} [{rule}] {title}")


def render_summary(
    target: str,
    file_count: int,
    duration_s: float,
    findings: list[dict],
):
    p0 = sum(1 for f in findings if f["severity"] == "P0")
    p1 = sum(1 for f in findings if f["severity"] == "P1")
    p2 = sum(1 for f in findings if f["severity"] == "P2")

    p0_color = RED if p0 > 0 else GREEN
    p1_color = YELLOW if p1 > 0 else GREEN
    p2_color = CYAN if p2 > 0 else GREEN

    time_str = f"{duration_s * 1000:.1f}ms" if duration_s < 1.0 else f"{duration_s:.2f}s"

    print("\n" + f"{GRAY}═" * 76 + f"{RESET}")
    print(f"{BOLD}Target:{RESET} {target}")
    print(f"{BOLD}Files Scanned:{RESET} {file_count} in {BOLD}{GREEN}{time_str}{RESET} (⚡ Instant)")
    print(
        f"{BOLD}Findings:{RESET} Total: {BOLD}{len(findings)}{RESET} | "
        f"{p0_color}{BOLD}P0 Critical: {p0}{RESET} | "
        f"{p1_color}{BOLD}P1 Major: {p1}{RESET} | "
        f"{p2_color}{BOLD}P2 Minor/Cosmetic: {p2}{RESET}"
    )

    # Category counts
    cats = {}
    for f in findings:
        c = f.get("category", "other").capitalize()
        cats[c] = cats.get(c, 0) + 1

    if cats:
        cat_strs = [f"{k}: {v}" for k, v in sorted(cats.items())]
        print(f"{DIM}Categories: {' | '.join(cat_strs)}{RESET}")
    print(f"{GRAY}═" * 76 + f"{RESET}\n")
