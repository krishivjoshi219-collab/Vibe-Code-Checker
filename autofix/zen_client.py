"""VCC Zen client — OpenCode Zen FREE-models only. stdlib urllib. No key stored."""
from __future__ import annotations

import getpass
import json
import os
import urllib.request

from .gate import FREE_IDS


def get_key() -> str:
    for env in ("OPENCODE_ZEN_API_KEY", "OPENCODE_API_KEY", "ZEN_API_KEY"):
        v = os.getenv(env, "").strip()
        if v:
            return v
    try:
        return getpass.getpass("Paste OpenCode Zen key (hidden, ENTER cancels): ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _post(url: str, key: str, payload: dict, timeout: int = 60) -> dict:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid URL scheme for endpoint: {url}")
    req = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode())


def _extract_response_text(data: dict) -> str:
    """Best-effort text extractor from varying response shapes."""
    try:
        chunks = [
            c.get("text", "")
            for item in data.get("output", [])
            for c in item.get("content", [])
            if c.get("type") in ("output_text", "text")
        ]
        if chunks:
            return "\n".join(chunks)
    except (KeyError, TypeError, AttributeError, ValueError):
        pass
    return json.dumps(data)[:4000]


def complete(model: str, endpoint: str, kind: str, key: str, prompt: str) -> str:
    if model not in FREE_IDS:
        raise ValueError(f"Blocked non-free model: {model}")
    if kind == "responses":
        data = _post(endpoint, key, {"model": model, "input": prompt, "max_output_tokens": 1200})
        return _extract_response_text(data)
    data = _post(endpoint, key, {
        "model": model,
        "messages": [{"role": "user", "content": prompt[:6000]}],
        "temperature": 0.2, "max_tokens": 1200,
    })
    return data["choices"][0]["message"]["content"]
