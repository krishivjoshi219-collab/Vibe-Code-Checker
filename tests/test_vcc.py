"""Unit tests for Vibe Code Checker (VCC).

Verifies detection of logical, security, async, resource, syntax, cosmetic, and multi-language bugs.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analyzers import cosmetic, multilang, python_ast
from autofix import engine as autofix_engine


class TestVCCAnalyzers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rules_path = os.path.join(BASE_DIR, "rules.json")
        with open(rules_path, "r", encoding="utf-8") as f:
            cls.rules = json.load(f)

    def _analyze_code(self, code: str, ext: str = ".py") -> list[dict]:
        with tempfile.NamedTemporaryFile(suffix=ext, mode="w", delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_path = f.name
        try:
            if ext in (".py", ".pyi"):
                return python_ast.analyze_python_ast(tmp_path, self.rules)
            else:
                return multilang.analyze_multilang(tmp_path, self.rules)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_syntax_error(self):
        findings = self._analyze_code("def foo( broken syntax")
        rules = [f["rule"] for f in findings]
        self.assertIn("syntax-error", rules)
        self.assertEqual(findings[0]["severity"], "P0")

    def test_undefined_name(self):
        findings = self._analyze_code("def foo():\n    return nonexistent_var + 1\n")
        rules = [f["rule"] for f in findings]
        self.assertIn("undefined-name", rules)

    def test_zero_division(self):
        findings = self._analyze_code("def calc():\n    return 100 / 0\n")
        rules = [f["rule"] for f in findings]
        self.assertIn("zero-div", rules)

    def test_float_nan_compare(self):
        findings = self._analyze_code("def is_nan(x):\n    return x == float('nan')\n")
        rules = [f["rule"] for f in findings]
        self.assertIn("float-nan-compare", rules)
        self.assertEqual(findings[0]["severity"], "P0")

    def test_collection_mutation_during_iteration(self):
        code = "def clean(items):\n    for x in items:\n        items.remove(x)\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("collection-mutation-during-iteration", rules)

    def test_mutable_default(self):
        findings = self._analyze_code("def append_item(val, target=[]):\n    target.append(val)\n")
        rules = [f["rule"] for f in findings]
        self.assertIn("mutable-default", rules)

    def test_dead_code_after_return(self):
        findings = self._analyze_code("def test():\n    return 1\n    print('dead code')\n")
        rules = [f["rule"] for f in findings]
        self.assertIn("dead-code", rules)

    def test_sql_injection(self):
        code = "def query_user(cursor, uid):\n    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("sql-injection", rules)

    def test_command_injection(self):
        code = "import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("command-injection", rules)

    def test_hardcoded_secret(self):
        code = 'OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"\n'
        # To test the detector directly:
        detector_code = 'API_KEY = "sk-123456789012345678901234567890"\n'  # noqa
        findings = self._analyze_code(detector_code)
        rules = [f["rule"] for f in findings]
        self.assertIn("hardcoded-secret", rules)

    def test_blocking_call_in_async(self):
        code = "import time\nasync def fetch_data():\n    time.sleep(5)\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("blocking-call-in-async", rules)

    def test_bare_except_and_silent_pass(self):
        code = "def risky():\n    try:\n        pass\n    except:\n        pass\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("bare-except", rules)

    def test_coroutine_not_awaited(self):
        code = "async def sync_remote(): pass\ndef runner():\n    sync_remote()\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("coroutine-not-awaited", rules)

    def test_assert_on_tuple(self):
        code = "def check(x):\n    assert (x > 0, 'x must be positive')\n"
        findings = self._analyze_code(code)
        rules = [f["rule"] for f in findings]
        self.assertIn("assert-on-tuple", rules)

    def test_broken_json(self):
        findings = self._analyze_code('{"key": "value",}', ext=".json")
        rules = [f["rule"] for f in findings]
        self.assertIn("broken-json-syntax", rules)

    def test_yaml_tab_indentation(self):
        findings = self._analyze_code("server:\n\tport: 8080\n", ext=".yaml")
        rules = [f["rule"] for f in findings]
        self.assertIn("broken-yaml-syntax", rules)

    def test_js_loose_equality(self):
        findings = self._analyze_code("if (a == b) { debugger; }\n", ext=".js")
        rules = [f["rule"] for f in findings]
        self.assertIn("js-loose-equality", rules)
        self.assertIn("js-debugger-statement", rules)

    def test_dockerfile_latest_tag(self):
        with tempfile.NamedTemporaryFile(suffix=".dockerfile", mode="w", delete=False) as f:
            f.write("FROM python:latest\nRUN apt-get update\n")
            tmp_path = f.name
        try:
            findings = multilang.analyze_multilang(tmp_path, self.rules)
            rules = [f["rule"] for f in findings]
            self.assertIn("docker-latest-tag", rules)
            self.assertIn("docker-root-user", rules)
        finally:
            os.remove(tmp_path)


class TestCosmeticAndAutofix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rules_path = os.path.join(BASE_DIR, "rules.json")
        with open(rules_path, "r", encoding="utf-8") as f:
            cls.rules = json.load(f)

    def test_cosmetic_detection(self):
        code = "def calculate_lenght(paramter):   \n    # this is a typo in comment: recieve  \n    return paramter\n"  # noqa
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = f.name
        try:
            findings = cosmetic.analyze_cosmetic(tmp_path, self.rules)
            rules = [f["rule"] for f in findings]
            self.assertIn("trailing-whitespace", rules)
            self.assertIn("comment-typo", rules)
            self.assertIn("identifier-typo", rules)
        finally:
            os.remove(tmp_path)

    def test_autofix_engine(self):
        bad_code = "def check(x):    \n    if x == None:    \n        return True    "
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(bad_code)
            tmp_path = f.name
        try:
            fixes = autofix_engine.fix_file(tmp_path)
            self.assertTrue(len(fixes) > 0)
            with open(tmp_path, "r") as f:
                fixed = f.read()
            self.assertIn("is None", fixed)
            self.assertFalse(fixed.endswith("    "))
            self.assertTrue(fixed.endswith("\n"))
        finally:
            os.remove(tmp_path)

    def test_cli_main_alias(self):
        import check
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = os.path.join(tmp_dir, "good.py")
            with open(test_file, "w") as f:
                f.write("def add(a: int, b: int) -> int:\n    return a + b\n")
            exit_code = check.main(["check", "--target", tmp_dir, "--fail-on", "P0", "--format", "compact"])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
