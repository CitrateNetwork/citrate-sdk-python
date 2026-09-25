"""Provenance tripwire for what this package tells the world about itself.

THE DEFECT (2026-08-01). `citrate-labs-sdk` 0.6.0 is live on PyPI with

    Repository  = https://github.com/SaulBuilds/citrate
    Bug Tracker = https://github.com/SaulBuilds/citrate/issues
    Changelog   = https://github.com/SaulBuilds/citrate/blob/main/CHANGELOG.md

Every one of those is a 404 for the public: the repo is private, it lives on a
personal account rather than the org, and it is the pre-split monorepo that the
federation stopped using. `pip install` worked fine, so nothing ever failed —
the package just quietly stopped being auditable by anyone outside the org, and
named an individual as the home of a company artifact.

These assertions are cheap because the failure was cheap to miss. Nothing in the
build, the test suite, or the publish step reads these fields, so the only thing
standing between a wrong URL and PyPI was somebody happening to click it.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 (requires-python floor): stdlib tomllib is 3.11+
    import tomli as tomllib

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"

# The federation org. A URL under any other GitHub account is provenance drift,
# whether it resolves or not — `SaulBuilds/citrate` DID resolve, for the org.
CANONICAL_REPO = "https://github.com/CitrateNetwork/citrate-sdk-python"

# Paths retired at the federation split. Any of these in a user-visible string
# means the document was written against a layout that no longer exists.
DEAD_REFERENCES = (
    "SaulBuilds/citrate",
    "citrate-ai/citrate",
    "citrate_v0.01.1",
)


@pytest.fixture(scope="module")
def project() -> dict:
    with PYPROJECT.open("rb") as fh:
        project: dict = tomllib.load(fh)["project"]
    return project


def test_repository_url_names_the_federation_repo(project: dict) -> None:
    assert project["urls"]["Repository"] == CANONICAL_REPO


@pytest.mark.parametrize("field", ["Homepage", "Documentation", "Repository", "Bug Tracker", "Changelog"])
def test_no_project_url_points_at_a_retired_location(project: dict, field: str) -> None:
    url = project["urls"][field]
    for dead in DEAD_REFERENCES:
        assert dead not in url, (
            f"project.urls.{field} = {url!r} still references {dead!r}, which the "
            f"federation split retired. A published package whose stated source "
            f"cannot be reached is unauditable by the people who install it."
        )


def test_every_project_url_is_https(project: dict) -> None:
    for field, url in project["urls"].items():
        assert url.startswith("https://"), f"project.urls.{field} = {url!r} is not https"


def test_the_cli_entry_point_this_package_uniquely_provides_is_declared(project: dict) -> None:
    """`citrate` ships here and nowhere else — @citratelabs/sdk declares no `bin`.

    NON_CANONICAL.md tells readers to prefer the TypeScript SDK, which is right
    for library code and wrong for the command line. If this entry point is ever
    dropped, that advice silently becomes "there is no CLI" rather than "use the
    other package", so the claim is pinned here.
    """
    assert project["scripts"]["citrate"] == "citrate_sdk.cli:main"


def test_non_canonical_doc_does_not_point_readers_at_a_dead_path() -> None:
    """The file whose entire job is "the real SDK is over there" had it wrong.

    It named `citrate_v0.01.1/sdks/javascript/citrate-js/`, a monorepo path with
    no reachable equivalent — so the one document a confused reader opens first
    sent them nowhere for months.
    """
    doc = (PYPROJECT.parent / "NON_CANONICAL.md").read_text(encoding="utf-8")
    # The corrected file quotes the old path once, inside the correction note, to
    # explain what changed. Anything beyond that is a live pointer at a dead path.
    body = re.sub(r"^> .*$", "", doc, flags=re.MULTILINE)
    assert "citrate_v0.01.1" not in body, (
        "NON_CANONICAL.md still directs readers to the retired monorepo path "
        "outside of its correction note."
    )
    assert "CitrateNetwork/citrate-sdk-js" in body


def test_package_version_matches_pyproject(project: dict) -> None:
    """`citrate_sdk.__version__` must equal the version actually being built.

    THE DEFECT (found 2026-08-02): the PUBLISHED 0.6.0 wheel reports
    `__version__ == "0.5.0"`. The 0.5.0 -> 0.6.0 bump changed pyproject.toml and
    nothing else, so every runtime version check against the published package
    got an answer that was a full release stale.

    Nothing caught it because nothing compared the two. `pip show` and
    `importlib.metadata` read pyproject, while application code reads
    `__version__` — the two sources only disagree where nobody was looking, which
    is the same shape as every other finding in this repo's 2026-08-02 audit.
    """
    import citrate_sdk

    assert citrate_sdk.__version__ == project["version"], (
        f"citrate_sdk.__version__ is {citrate_sdk.__version__!r} but pyproject "
        f"declares {project['version']!r}. A bump that touches only one of these "
        f"ships a package that misreports itself at runtime."
    )


def test_issue_and_changelog_links_use_the_public_repo(project: dict) -> None:
    """citrate-sdk-python is public (2026-09-24), so readers can reach issues and
    the changelog on the canonical repo instead of a generic docs page."""
    assert project["urls"]["Bug Tracker"] == f"{CANONICAL_REPO}/issues"
    assert project["urls"]["Changelog"] == f"{CANONICAL_REPO}/blob/main/CHANGELOG.md"
