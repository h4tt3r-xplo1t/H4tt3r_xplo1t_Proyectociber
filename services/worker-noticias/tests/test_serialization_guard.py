"""Threat 33: nothing in the service may deserialise code-executing formats.

Two guards: the ruff `S` rules (S301 `pickle`, S403 import of `pickle` and
friends) stay enabled, and no module under `src/` imports `pickle`, `marshal`
or `shelve`. Messages are JSON only (ADR 0008).
"""

import ast
import tomllib
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = frozenset({"pickle", "_pickle", "cPickle", "marshal", "shelve", "dill"})
REQUIRED_RULES = ("S301", "S403")


def forbidden_uses(source: str) -> list[str]:
    """Names of forbidden serialisation modules that `source` imports."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif (
            isinstance(node, ast.Call)
            and _is_dynamic_import(node.func)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names = [node.args[0].value]
        else:
            continue
        found += [n for n in names if n.split(".")[0] in FORBIDDEN]
    return found


def _is_dynamic_import(func: ast.expr) -> bool:
    """`__import__(...)` or `<anything>.import_module(...)`."""
    return (isinstance(func, ast.Name) and func.id == "__import__") or (
        isinstance(func, ast.Attribute) and func.attr == "import_module"
    )


@pytest.mark.parametrize(
    "source",
    [
        "import pickle",
        "import os, pickle",
        "import pickle as p",
        "from pickle import loads",
        "from pickle import *",
        "import marshal",
        "from shelve import open",
        "import _pickle",
        "import dill",
        "def f():\n    import pickle",
        "__import__('pickle')",
        "import importlib\nimportlib.import_module('marshal')",
    ],
)
def test_the_scanner_detects_forbidden_imports(source):
    assert forbidden_uses(source)


@pytest.mark.parametrize(
    "source",
    [
        "import json",
        "from json import loads",
        "import picklish",
        "x = 'pickle'",
        "# import pickle",
    ],
)
def test_the_scanner_ignores_harmless_code(source):
    assert forbidden_uses(source) == []


def test_no_module_under_src_uses_a_code_executing_serialiser():
    offenders = {
        str(path.relative_to(SERVICE_ROOT)): found
        for path in (SERVICE_ROOT / "src").rglob("*.py")
        if (found := forbidden_uses(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}


def _ruff_config() -> dict:
    pyproject = tomllib.loads((SERVICE_ROOT / "pyproject.toml").read_text("utf-8"))
    return pyproject["tool"]["ruff"]["lint"]


def test_ruff_selects_the_bandit_rules():
    assert "S" in _ruff_config()["select"]


def test_no_ruff_setting_disables_the_pickle_rules():
    config = _ruff_config()
    disabled = set(config.get("ignore", []))
    for rules in config.get("per-file-ignores", {}).values():
        disabled |= set(rules)
    for rule in REQUIRED_RULES:
        assert not {rule, "S3", "S4", "S"} & disabled, rule
