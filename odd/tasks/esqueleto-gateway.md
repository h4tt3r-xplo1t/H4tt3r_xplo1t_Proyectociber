# esqueleto-gateway

## Objective
Issue #25: E2 skeleton of the `gateway` service (FastAPI) with reproducible dependencies, tests and lint in CI, as the base for the topic-search flow (E3).

## Scope
- `services/gateway/`: `pyproject.toml`, `uv.lock`, `src/gateway/main.py` (`GET /healthz`), `tests/test_healthz.py`.
- `.github/workflows/seguridad.yml` (new `gateway` job), `.github/dependabot.yml` (uv ecosystem).
- `.gitignore`, `.claude/settings.json` (test and lint commands), `docs/BITACORA.md`, `docs/PROJECT_CONTEXT.md` (E2 status).
- Out of scope: auth, database, Vault, RabbitMQ, Dockerfile and images, full SAST (E4), other services, making `gateway` a required check in the ruleset (remote operation).

## Constraints
- IMPLEMENTACIÓN LOCAL on `feat/25-esqueleto-gateway`; local commits only; Conventional Commits with `#25`; no AI attribution lines.
- Every new dependency verified (AGENTS.md §3); actions pinned by full commit SHA; `contents: read`, `persist-credentials: false`.
- No suppressions of lint rules to get a green check.

## Verified versions (2026-09-30)
Releases re-checked with `gh api repos/<repo>/releases/latest`; PyPI metadata came from a research subagent through a summarizer (second-hand).
- CPython 3.14.7 (local interpreter; 3.14 supported by fastapi classifiers).
- uv 0.12.21 (Astral, MIT OR Apache-2.0); local uv is 0.12.19.
- astral-sh/setup-uv v10.2.0 (commit `c18668ad3cf93ea998bef934396af7bb5c839dc7`) was verified but not used: CI downloads the uv binary pinned by sha256 instead.
- fastapi 0.142.2 (MIT), pytest 9.1.1 (MIT), ruff 0.16.9 (MIT, `S` = flake8-bandit rules).
- httpx 0.28.1 (BSD-3-Clause), last release 2024-12-06: low activity; dev-only (needed by `TestClient`).
- NOT VERIFIED: Dependabot `uv` ecosystem on the supported-ecosystems page (only the options reference); advisories only checked with the experimental `uv audit` (0 known vulnerabilities in 22 packages, PARTIAL).

## TDD
Mode: strict, enabled (source: global user configuration "Strict TDD Mode: enabled"). Runner: `uv run pytest` in `services/gateway`.

## Route
- T1 inline: skeleton is three tiny files plus a generated lockfile; no design decision open.
- T2 inline: one workflow job and one dependabot entry following the existing pinned pattern.
- T3 inline: mechanical config and docs edits.
- T4 delegated: `revisor-seguridad` subagent.

## Tasks
- [x] **T0**: issue #25 created (person authorized), branch `feat/25-esqueleto-gateway`, versions verified.
- [x] **T1**: TDD skeleton, `pyproject.toml` with ruff incl. `S`, `uv.lock` (`9a80e17`). RED: `ModuleNotFoundError: gateway.main`; GREEN: 1 passed; ruff check and format clean. REFACTOR: nothing to refactor.
- [x] **T2**: `gateway` CI job with the official uv binary pinned by sha256 (setup-uv dropped, same pattern as gitleaks) and Dependabot uv entry (`9a7e5ea`). actionlint not installed locally: YAML parsed, job steps run locally and pass; actionlint runs in CI (pending).
- [x] **T3**: `.gitignore` (in `9a80e17`), settings allow rules (`483c245`), BITACORA and PROJECT_CONTEXT (`a442262`). `uv audit --locked`: no known vulnerabilities in 22 packages (experimental command: PARTIAL). guardia 164/164, ruleset 15/15.
- [x] **T4**: `revisor-seguridad`: ready for PR, 5 low. Gentle AI review (4 lenses, lineage review-627eab7a42ccd908 on 5ce60d3): approved, acknowledged. Low fixes: `e504481` (uv-bin PATH, curl retry), `b649128` (exact allow rules), `2ab7ebf` (`.python-version` 3.14.7), `372f8c9` (bitacora rotation and pendings). uv sha256 recomputed locally from the release asset: matches.
- [ ] **T5**: push and PR (only on the person's explicit request).

## Progress
- 2026-09-30: T0 done.
- 2026-09-30: T1-T3 done. `httpx2` swap blocked by the auto-mode permission classifier; kept `httpx` (deprecation warning only) and left the decision to the person. T4 running.
- 2026-09-30: T4 done. Deferred to pendings: FastAPI docs off outside dev (E3/E6), periodic refresh of sha256-pinned tools, `gateway` as required check, `httpx2` decision.
- 2026-09-30: second Gentle AI review (lineage review-0a0bf9676a2fa531, fix commits from 5ce60d3 to 648d781): approved, acknowledged. Its readability warning (ambiguous historial note) fixed in `aa55bd2` (passive). Not applied: `mkdir -p` for uv-bin (GitHub-hosted runners start with an empty RUNNER_TEMP) and a retry for the managed CPython download at `uv sync` (follow-up).
