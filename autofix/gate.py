"""VCC TUI gate — consent + model dropdown. stdlib only."""
from __future__ import annotations

FREE_MODELS = [
    ("big-pickle", "https://opencode.ai/zen/v1/chat/completions", "chat"),
    ("mimo-v2.5-free", "https://opencode.ai/zen/v1/chat/completions", "chat"),
    ("ling-3.0-flash-fin-free", "https://opencode.ai/zen/v1/chat/completions", "chat"),
    ("nemotron-3-ultra-free", "https://opencode.ai/zen/v1/chat/completions", "chat"),
    ("nemotron-3.5-lightning-free", "https://opencode.ai/zen/v1/chat/completions", "chat"),
    ("muse-spark-1.3-contributor-free", "https://opencode.ai/zen/v1/responses", "responses"),
]

FREE_IDS = {m[0] for m in FREE_MODELS}


def ask_yes_no(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


def pick_model(preselected: str | None = None) -> tuple[str, str, str] | None:
    if preselected:
        for m in FREE_MODELS:
            if m[0] == preselected:
                return m
        print(f"Blocked: '{preselected}' is not an always-FREE Zen model.")
        return None
    print("\nSelect Zen FREE model (dropdown):")
    for i, (mid, _, _) in enumerate(FREE_MODELS, 1):
        print(f"  {i}) {mid}")
    try:
        raw = input("Enter number [1-6] (ENTER cancels): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return None
    try:
        idx = int(raw) - 1
        return FREE_MODELS[idx] if 0 <= idx < len(FREE_MODELS) else None
    except ValueError:
        return None
