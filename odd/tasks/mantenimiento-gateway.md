# mantenimiento-gateway

## Objective
Issue #27: close the follow-ups left by issue #25 (PR #26, `da5a9e7`) before E3.

## Scope
- `docs/BITACORA.md`: closure of #25 and pending items.
- `.github/rulesets/main.json` and `tests/rulesets/main_ruleset_test.sh`: `gateway` as a required status check.
- `services/gateway/`: interactive docs off by default; `httpx` replaced by `httpx2` (dev group).
- Out of scope: E3 features, other services, workflows. Applying the ruleset on GitHub is a separate remote operation after the merge.

## Constraints
- IMPLEMENTACIÓN LOCAL on `chore/27-mantenimiento-gateway`; Conventional Commits with `#27`; no AI attribution lines.
- `httpx2` verified on PyPI before adding it (AGENTS.md §3). Person chose the swap on 2026-09-30.

## TDD
Mode: strict, enabled (global user configuration). Runners: `uv run --locked pytest` in `services/gateway`; `bash tests/rulesets/main_ruleset_test.sh`.

## Route
All inline: three small, independent changes with established patterns; no open design decision.

## Tasks
- [x] **T0**: issue #27 created (person authorized), branch created.
- [x] **T1**: ruleset requires `gateway` (`528e5f4`). RED: 15 cases, 1 failed; GREEN: 0 failed.
- [x] **T2**: docs off unless `GATEWAY_DOCS_ENABLED == "true"` (`862894e`). RED: ImportError `create_app`; GREEN: 12 passed.
- [x] **T3**: `httpx2` 2.13.1 verified on PyPI (pydantic, BSD-3) plus httpcore2 and truststore 0.10.4 (MIT) (`05546d0`). Deprecation warning gone; uv audit 23 packages clean.
- [x] **T4**: BITACORA closure of #25, #27 entry, pendings updated. ADR 0001 still lists three checks: left as is (out of scope).
- [ ] **T5**: `revisor-seguridad`.
- [ ] **T6**: push and PR on request; apply the ruleset after merge on request.

## Progress
- 2026-09-30: T0 done.
