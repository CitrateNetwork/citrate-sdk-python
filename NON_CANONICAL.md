---
created: 2026-04-07T04:00:00Z
branch: quorum-execution-v1
author: Claude (zooid: architect)
sprint: level-b
status: active
---

# Non-Canonical Python SDK

**This Python SDK is NOT the canonical Citrate SDK.**

## Canonical SDK

The canonical SDK is the TypeScript one, published as **`@citratelabs/sdk`** from
**`CitrateNetwork/citrate-sdk-js`**.

All new features, bug fixes, and API changes land in the canonical SDK first.
The Python SDK may lag behind the canonical SDK by an unbounded amount.

> **Corrected 2026-08-01.** This file used to point at
> `citrate_v0.01.1/sdks/javascript/citrate-js/` — a path inside the pre-split
> monorepo, which no longer exists anywhere a reader can reach. The document that
> exists to tell you where the real SDK lives had been sending you to a dead path
> since the federation split.

## One thing this SDK is canonical for

The **`citrate` command line** ships in this package and nowhere else
(`[project.scripts]`, `citrate_sdk/cli:main`). `@citratelabs/sdk` declares no
`bin`. So "use the TypeScript SDK instead" is right for library code and wrong
for the CLI: if you want the commands, `pip install citrate-labs-sdk` is the only
way to get them, whatever language your project is in.

## When to Use Python SDK

- You are prototyping or doing data science work where Python is the only reasonable choice
- You are writing a one-off script and don't need latest features
- You already have a Python pipeline and cannot easily switch

## When NOT to Use Python SDK

- You are building a production integration — use `citrate-js` instead
- You need the latest Citrate features — they land in `citrate-js` first
- You need feature parity guarantees — this SDK has none

## Status

- Canonical: **NO**
- CI status: **runs on every push and pull request** and `pytest` is BLOCKING
  (`.github/workflows/ci.yml` -> `reusable-python-ci.yml`). Corrected
  2026-08-02: this line claimed opt-in `workflow_dispatch` CI, which was
  wrong and actively misleading — it was cited as the explanation for how
  0.6.0 shipped over seven failing security tests. The real reasons are
  worse and are recorded in the audit: this repo's last SUCCESSFUL run was
  2026-06-10 (before the K3 tests existed), every run since ~2026-07-26 is
  `startup_failure` at 0s, and the publish workflow — which correctly gates
  `build` on `needs: test` — has NEVER run, so 0.6.0 was uploaded manually
  around the gate.
- Feature parity: **not guaranteed**
- Support: **best effort only**

## Promotion Policy

The Python SDK will be promoted to canonical status only if:
1. A real pilot integrator requires Python as their primary integration
2. Full feature parity with `citrate-js` is achieved and tested
3. A Python maintainer commits to tracking `citrate-js` changes

Until all three conditions hold, treat this SDK as experimental.

## See Also

- `CitrateNetwork/citrate-sdk-js` — the canonical TypeScript SDK (`@citratelabs/sdk`)
- `.github/workflows/sdk-tests.yml` — canonical vs non-canonical CI job split
