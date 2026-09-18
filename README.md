# ⚡ Vibe Code Checker (VCC) v2.0

> **Instant, Production-Grade Bug Engine for Any Codebase.**
> Pure standard-library core with zero required external dependencies. Catches logical, security, async, resource, syntax, multi-language, and cosmetic bugs in milliseconds.

---

## 🚀 Key Highlights

- **⚡ Blazingly Fast**: Parallel multi-worker AST traversal scanning entire repositories in milliseconds.
- **🎯 Pinpoint Accuracy**: Zero noise. Replaces naive regex heuristics with full AST scope resolution and compiler-grade diagnostics.
- **🛡️ Full-Spectrum Bug Detection**:
  - **Logical Bugs**: Undefined names, division by zero, float NaN comparisons (`x == float('nan')`), collection mutations during iteration, mutable default arguments, off-by-one errors, infinite loops, dead code, missing return paths.
  - **Security Vulnerabilities**: SQL injection (f-strings / `%` / `.format()`), command injection (`shell=True`, `os.system`), hardcoded API keys / tokens / private keys, insecure deserialization (`pickle.loads`), weak randomness (`random` for crypto/tokens), weak hashing (`md5`/`sha1`).
  - **Async & Concurrency**: Coroutines called without `await`, blocking calls inside `async def` (`time.sleep`, synchronous requests), global mutations across threads.
  - **Resource Leaks**: `open()` outside of `with` context manager, unclosed database connections, missing HTTP timeouts.
  - **Multi-Language & Config**: Broken JSON / YAML (tabs forbidden) / TOML syntax, JS loose equality (`==` vs `===`), JS debugger statements, unpinned Dockerfile images (`:latest`), missing non-root Docker `USER`, shell scripts missing `set -e` or unquoted `rm -rf $VAR`.
  - **Cosmetic & Code Hygiene**: Trailing whitespace, missing final newlines, mixed tabs/spaces, 60+ common programmer typos in identifiers and comments, overly complex functions (>80 lines), excessive parameters (>6), deep nesting (>4 levels).
- **🔧 Dual Autofix**:
  - `--fix`: Instant, safe deterministic auto-fixer (fixes trailing whitespace, EOF newlines, `== None` -> `is None`, `== True`, etc.).
  - `--autofix`: Gated AI assistant using OpenCode Zen FREE models for complex logical refactoring.
- **📊 Production Reports**: Outputs machine-readable `report.json` and executive `report.md` with ready-to-use LLM fix prompts.

---

## 💻 Quickstart

### 1. Instant Scan
Scan the current directory or any project target:
```bash
python check.py --target /path/to/any/project
```

### 2. Auto-Fix Cosmetic & Mechanical Bugs
Automatically resolve trailing whitespace, missing final newlines, and comparison syntax safely:
```bash
python check.py --fix
```

### 3. Filter by Severity or Category
```bash
# Only show critical blockers (P0)
python check.py --severity P0

# Only show security vulnerabilities
python check.py --category security

# Only show async / concurrency bugs
python check.py --category async
```

### 4. CI/CD Gate
Fail the build (exit code 1) if any P0 or P1 bugs exist:
```bash
python check.py --fail-on P0
```

### 5. IDE / Pipeline Format
Produce one-line compiler diagnostics (compatible with GitHub Actions, VSCode, GCC error parsers):
```bash
python check.py --format compact
```

### 6. Interactive AI Auto-Fix (Zen FREE Models)
```bash
python check.py --autofix --limit 5
```
Supported always-free models: `big-pickle`, `mimo-v2.5-free`, `ling-3.0-flash-fin-free`, `nemotron-3-ultra-free`, `nemotron-3.5-lightning-free`, `muse-spark-1.3-contributor-free`.

---

## 📋 Command Line Interface

| Option | Argument | Description |
| :--- | :--- | :--- |
| `--target`, `-t` | `<path>` | Target file or directory to scan (default: `.`) |
| `--severity`, `-s` | `P0`, `P1`, `P2` | Minimum severity threshold to report |
| `--category`, `-c` | `logic`, `security`, `async`, `resource`, `cosmetic`, `syntax`, `config` | Filter findings by category |
| `--fail-on` | `P0`, `P1`, `P2`, `none` | Exit code 1 if issues $\ge$ severity are found (default: `P0`) |
| `--format`, `-f` | `pretty`, `compact`, `json` | Terminal output style (default: `pretty`) |
| `--fix` | *(flag)* | Apply deterministic, safe auto-fixes |
| `--autofix` | *(flag)* | Run interactive AI auto-fix with Zen FREE models |
| `--rule-list` | *(flag)* | Display all supported rules and severity levels |
| `--workers`, `-w` | `<int>` | Parallel worker threads for scanning (default: auto) |
| `--no-ruff` | *(flag)* | Disable optional native Ruff accelerator |

---

## 🏷️ Inline Rule Suppression

Suppress false positives or intentional test fixtures using standard inline comments:

```python
# Suppress all checks on this line
api_key = "test-fixture-key"  # noqa

# Or use VCC specific tags:
val = 100 / 0  # vcc:ignore
data = x == None  # vcc:disable=none-eq-compare
```

---

## 🧪 Testing

Run the built-in test suite:
```bash
python -m unittest tests/test_vcc.py
```
