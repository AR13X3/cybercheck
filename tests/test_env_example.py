"""Every setting the code reads from the environment is listed in .env.example.

CONTRIBUTING.md asks a module that needs a new setting to add it to .env.example (commented, with its
default), because that file is where people running CyberCheck look for what they can change. This test
keeps the two in step: it reads the source of `cybercheck/` (without importing or running it) and fails
when a setting name appears in the code but not in .env.example.

How a "setting" is found, in each module:
- a string literal passed to `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or to
  `.get(...)` on a mapping named `env` (the injectable-environment pattern in cybercheck/reporting);
- a string literal passed as the first argument to a function in the same module that reads the
  environment itself (`_env`, `_int`, `_env_int`, ...) or calls such a function (czds.py's nested
  `num()` calls `env()`, which calls `os.environ.get`).

Names built at runtime (`f"JOB_{name}_ENABLED"`) or kept in a variable first cannot be seen this way; the
scanner simply does not report them, so they never fail the test. Document them by hand.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTING = re.compile(r"^[A-Z][A-Z0-9_]*$")
# An entry in .env.example, set or commented out: "NAME=value" or "# NAME=value".
EXAMPLE_ENTRY = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=", re.MULTILINE)

# Read by the code but deliberately not in .env.example. Keep the reason next to each name.
NOT_SETTINGS = {
    # the system search path, passed on to the `sort` program by czds.py; not a CyberCheck setting
    "PATH",
    # test-only: the integration tests set it to "" to prove the code is right outside UTC (db.py says so)
    "CYBERCHECK_DB_OPTIONS",
}


def _is_os_env(node: ast.AST) -> bool:
    """True for the expressions `os.environ` and `os.getenv`."""
    return (isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv")
            and isinstance(node.value, ast.Name) and node.value.id == "os")


def _reads_env_directly(func: ast.AST) -> bool:
    return any(_is_os_env(n) for n in ast.walk(func))


def _env_reader_names(tree: ast.Module) -> set[str]:
    """Names of the functions in one module that read the environment, directly or through each other.

    Matched by name only, nested functions included: good enough for small `_env`-style helpers, and a
    false match could only add names to check, never hide one."""
    funcs: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(node.name, []).append(node)
    readers = {name for name, defs in funcs.items() if any(_reads_env_directly(d) for d in defs)}
    # A helper that calls a reader is a reader too (num() -> env() -> os.environ.get). Repeat until nothing
    # new turns up, because the chain can be several functions long.
    while True:
        more = {name for name, defs in funcs.items() if name not in readers and any(
            isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in readers
            for d in defs for c in ast.walk(d))}
        if not more:
            return readers
        readers |= more


def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def settings_in_source(source: str) -> set[str]:
    """Setting names one Python module reads from the environment (see the module docstring)."""
    tree = ast.parse(source)
    readers = _env_reader_names(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Call) and node.args:
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in readers:
                name = _literal(node.args[0])
            elif isinstance(fn, ast.Attribute) and (
                    _is_os_env(fn)                                              # os.getenv("X")
                    or (fn.attr == "get" and (_is_os_env(fn.value)              # os.environ.get("X")
                                              or (isinstance(fn.value, ast.Name) and fn.value.id == "env")))):
                name = _literal(node.args[0])
        elif isinstance(node, ast.Subscript) and (
                _is_os_env(node.value) or (isinstance(node.value, ast.Name) and node.value.id == "env")):
            name = _literal(node.slice)                                         # os.environ["X"]
        if name and SETTING.match(name):
            found.add(name)
    return found


def settings_in_code() -> dict[str, list[str]]:
    """{setting name: [files that read it]} for every module under cybercheck/."""
    found: dict[str, list[str]] = {}
    for path in sorted((ROOT / "cybercheck").rglob("*.py")):
        for name in settings_in_source(path.read_text(encoding="utf-8")):
            found.setdefault(name, []).append(path.relative_to(ROOT).as_posix())
    return found


def settings_in_example() -> set[str]:
    return set(EXAMPLE_ENTRY.findall((ROOT / ".env.example").read_text(encoding="utf-8")))


def test_every_setting_read_in_code_is_in_env_example():
    in_code = settings_in_code()
    missing = sorted(set(in_code) - settings_in_example() - NOT_SETTINGS)
    assert not missing, (
        "Add these settings to .env.example, commented out, with their default and a one-line explanation "
        "(or, if one is not a real setting, to NOT_SETTINGS in this test with the reason):\n"
        + "\n".join(f"  {name}  (read in {', '.join(in_code[name])})" for name in missing))


def test_not_settings_are_still_read_somewhere():
    """An exemption for a name the code no longer reads is dead weight: remove it."""
    unused = NOT_SETTINGS - set(settings_in_code())
    assert not unused, f"no longer read in cybercheck/, remove from NOT_SETTINGS: {sorted(unused)}"


def test_scanner_finds_each_way_of_reading_a_setting():
    """The scanner itself, on made-up code: if it stopped finding names, the test above would pass
    without checking anything."""
    source = '''
import os

def _env(name, default=""):
    return os.environ.get(name, default).strip()

def _int(name, default):
    v = _env(name)
    return int(v) if v else default

def load(env=None):
    env = os.environ if env is None else env
    def num(name, default):
        return float(_env(name) or default)
    return (
        os.environ.get("DIRECT_GET"),
        os.getenv("DIRECT_GETENV"),
        os.environ["DIRECT_INDEX"],
        _env("THROUGH_HELPER"),
        _int("THROUGH_HELPER_CHAIN", 3),
        num("THROUGH_NESTED_HELPER", 1.5),
        env.get("THROUGH_ENV_MAPPING"),
        os.environ.get(f"DYNAMIC_{1}_NAME"),   # built at runtime: not seen
        os.environ.get("lowercase_name"),      # not a setting name
        print("NOT_AN_ENV_READ"),              # print() does not read the environment
    )
'''
    assert settings_in_source(source) == {
        "DIRECT_GET", "DIRECT_GETENV", "DIRECT_INDEX", "THROUGH_HELPER", "THROUGH_HELPER_CHAIN",
        "THROUGH_NESTED_HELPER", "THROUGH_ENV_MAPPING"}


def test_example_entries_are_parsed_set_or_commented():
    """Both a set value and a commented-out default count as listed; prose that merely mentions a name
    does not."""
    text = "DATABASE_URL=postgresql://example\n# AI_EFFORT=low\n#   WEB_PORT=8430   # comment\n# see FOO_BAR\n"
    assert set(EXAMPLE_ENTRY.findall(text)) == {"DATABASE_URL", "AI_EFFORT", "WEB_PORT"}
