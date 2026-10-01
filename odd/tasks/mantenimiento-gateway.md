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
- [ ] **T1**: ruleset requires `gateway` (test first).
- [ ] **T2**: docs routes off by default, enabled by env var (tests first).
- [ ] **T3**: `httpx2` verified and swapped; lockfile regenerated.
- [ ] **T4**: BITACORA closure of #25 and pendings.
- [ ] **T5**: `revisor-seguridad`.
- [ ] **T6**: push and PR on request; apply the ruleset after merge on request.

## Progress
- 2026-09-30: T0 done.
