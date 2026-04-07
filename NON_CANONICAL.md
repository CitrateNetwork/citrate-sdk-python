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

The canonical SDK is `citrate-js` (TypeScript/JavaScript) located at:

```
citrate_v0.01.1/sdks/javascript/citrate-js/
```

All new features, bug fixes, and API changes land in the canonical SDK first.
The Python SDK may lag behind the canonical SDK by an unbounded amount.

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
- CI status: opt-in only (runs on `workflow_dispatch` with `run_noncanonical=true`)
- Feature parity: **not guaranteed**
- Support: **best effort only**

## Promotion Policy

The Python SDK will be promoted to canonical status only if:
1. A real pilot integrator requires Python as their primary integration
2. Full feature parity with `citrate-js` is achieved and tested
3. A Python maintainer commits to tracking `citrate-js` changes

Until all three conditions hold, treat this SDK as experimental.

## See Also

- `citrate_v0.01.1/sdks/javascript/citrate-js/` — the canonical TypeScript SDK
- `.github/workflows/sdk-tests.yml` — canonical vs non-canonical CI job split
