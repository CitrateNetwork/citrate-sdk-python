"""Pins on the non-source artifacts that ship with, or gate, this package.

Each check reads a file that nothing in the runtime suite otherwise reads: the
shipped examples, the publish workflow, the lockfile and the sdist manifest.
They are text/AST checks on purpose (no network, no YAML dependency), so they
run in the same frozen environment as the rest of the suite.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 (requires-python floor)
    import tomli as tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLES = sorted((ROOT / "examples").glob("*.py"))
WORKFLOWS = ROOT / ".github" / "workflows"


# ---------------------------------------------------------------------------
# Shipped examples: the code integrators copy.
# ---------------------------------------------------------------------------

def _calls(path: pathlib.Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)]


def _attr_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def test_examples_are_present_and_parse() -> None:
    assert EXAMPLES, "examples/ is empty; the pins below would pass vacuously"
    for path in EXAMPLES:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_never_call_the_disabled_purchase_path(path: pathlib.Path) -> None:
    names = [_attr_name(c) for c in _calls(path)]
    assert "purchase_model_access" not in names, (
        f"{path.name} calls purchase_model_access, which has no on-chain route and refuses"
    )


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_encrypted_calls_name_a_recipient_key(path: pathlib.Path) -> None:
    for call in _calls(path):
        name = _attr_name(call)
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        if name == "inference":
            enc = kw.get("encrypted")
            if isinstance(enc, ast.Constant) and enc.value is True:
                assert "recipient_public_key" in kw, (
                    f"{path.name}:{call.lineno} encrypted inference without recipient_public_key"
                )
        if name == "encrypt_data":
            assert len(call.args) >= 2 or "recipient_public_key" in kw, (
                f"{path.name}:{call.lineno} encrypt_data without a recipient key"
            )


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_do_not_hand_a_generated_key_string_to_a_client(path: pathlib.Path) -> None:
    """`CitrateClient(private_key=KeyManager().get_private_key())` is the
    round-trip the examples must not model; keys come from the environment."""
    for call in _calls(path):
        if _attr_name(call) != "CitrateClient":
            continue
        for k in call.keywords:
            if k.arg == "private_key" and isinstance(k.value, ast.Call):
                assert _attr_name(k.value) != "get_private_key", (
                    f"{path.name}:{call.lineno} builds a client from get_private_key()"
                )


# ---------------------------------------------------------------------------
# Publish workflow: the release gate.
# ---------------------------------------------------------------------------

def _jobs(text: str) -> dict[str, str]:
    """Split a workflow's `jobs:` block into {job_name: body} by indentation."""
    body = text.split("\njobs:\n", 1)[1]
    out: dict[str, str] = {}
    cur: str | None = None
    for line in body.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            cur = m.group(1)
            out[cur] = ""
        elif cur is not None and (line.startswith("   ") or not line.strip()):
            out[cur] += line + "\n"
        elif line.strip():
            break
    return out


@pytest.fixture(scope="module")
def publish() -> str:
    return (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")


def test_publish_workflow_chains_test_build_publish(publish: str) -> None:
    jobs = _jobs(publish)
    assert {"test", "build", "publish"} <= set(jobs), sorted(jobs)
    assert re.search(r"^    needs: test\s*$", jobs["build"], re.M), "build must need test"
    assert re.search(r"^    needs: build\s*$", jobs["publish"], re.M), "publish must need build"


def test_publish_test_job_runs_the_suite_blocking(publish: str) -> None:
    test_job = _jobs(publish)["test"]
    assert re.search(r"run: uv run --frozen pytest\b", test_job), "test job must run pytest"
    assert "continue-on-error" not in publish
    assert "|| true" not in publish


def test_publish_uses_trusted_publishing_not_a_token(publish: str) -> None:
    job = _jobs(publish)["publish"]
    assert re.search(r"id-token: write", job)
    assert "pypa/gh-action-pypi-publish@" in job
    assert not re.search(r"^\s*(password|api[-_]token)\s*:", publish, re.M | re.I)
    assert "secrets.PYPI" not in publish


def test_manual_publish_is_main_only_and_version_checked(publish: str) -> None:
    job = _jobs(publish)["publish"]
    assert "github.ref == 'refs/heads/main'" in job
    assert "inputs.publish_version != ''" in job
    assert "Built version matches the requested version" in job


@pytest.mark.parametrize("wf", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_every_action_reference_is_pinned_to_a_commit(wf: pathlib.Path) -> None:
    refs = re.findall(r"^\s*-?\s*uses:\s*(\S+)", wf.read_text(encoding="utf-8"), re.M)
    assert refs, f"{wf.name} has no uses: lines"
    for ref in refs:
        if ref.startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", ref), f"{wf.name}: {ref} is not pinned to a commit SHA"


# ---------------------------------------------------------------------------
# Lockfile and sdist manifest.
# ---------------------------------------------------------------------------

def _locked_version(name: str) -> Version:
    text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    m = re.search(r'^\[\[package\]\]\nname = "' + re.escape(name) + r'"\nversion = "([^"]+)"', text, re.M)
    assert m, f"{name} not in uv.lock"
    return Version(m.group(1))


def test_locked_cryptography_satisfies_the_declared_range() -> None:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        deps = tomllib.load(fh)["project"]["dependencies"]
    req = next(Requirement(d) for d in deps if Requirement(d).name == "cryptography")
    locked = _locked_version("cryptography")
    assert req.specifier.contains(locked), f"uv.lock pins cryptography {locked}, pyproject wants {req.specifier}"


def test_manifest_includes_only_files_that_exist() -> None:
    for line in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if parts and parts[0] == "include":
            for name in parts[1:]:
                assert (ROOT / name).exists(), f"MANIFEST.in includes missing file {name}"
