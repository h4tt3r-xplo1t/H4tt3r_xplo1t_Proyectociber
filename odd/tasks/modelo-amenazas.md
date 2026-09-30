# modelo-amenazas

## Objective
Issue #18 (E1): threat model for H4tt3r_1nf0rm4t1v0. It covers level 0 and level 1 DFDs in OWASP Threat Dragon, STRIDE threats with controls linked to tests, residual risks, and the guide the person followed to learn the tool.

## Scope
- `docs/architecture/threat-model.json`: Threat Dragon 2.6.2 model (drawn by the person, laid out and completed by the agent).
- `docs/architecture/dfd-nivel-0.png`, `docs/architecture/dfd-nivel-1.png`: exported by the person.
- `docs/threat-model.md`: the threat model document.
- `docs/architecture/guia-threat-dragon.md`: the step-by-step guide.
- `docs/BITACORA.md`: E1 entry, including the lesson from PR #16.
- Out of scope: code, CI, infrastructure.

## Constraints
- Mode: IMPLEMENTACIÓN LOCAL on `docs/18-modelo-amenazas`; local commits only.
- Conventional Commits with `#18`; no AI attribution lines.
- Docs in Spanish (project convention). Changing facts carry a source and date, or are marked NO VERIFICADO.

## TDD / checks
There is no test runner for prose. Checks: `tests/hooks/guardia_test.sh`, `tests/rulesets/main_ruleset_test.sh`, the gitleaks hook, JSON validity and integrity of the model (flows attached, valid threat types), and a relative-link check.

## Route
- T1–T4 inline (the person drew the model; the agent edited one JSON file).
- T5 delegated writer (writer trigger: 3 non-trivial docs).

## Tasks
- [x] **T1**: install Threat Dragon 2.6.2 (AppImage, SHA-512 verified) and create the model.
- [x] **T2**: DFD level 0 (`66984ec`).
- [x] **T3**: DFD level 1: elements, flows and boundaries (`22ec909`, `4033c09`, `af080ee`, `bce99d0`).
- [x] **T4**: 30 STRIDE threats (`2403a3f` by the person, `1804afa`).
- [x] **T5**: `docs/threat-model.md`, the guide and the BITACORA entry (`81415a8`, `a0f585d`, `c28434d`).
- [x] **T6**: exported PNGs (person); level 1 re-exported without a selection artifact; threat 2 verification added (`d6fb902`).
- [ ] **T7**: `revisor-seguridad` review, then PR.

## Progress
- Issue #18 created on request. Branch from `main` at `ff33c6f`.
- Model integrity check after each manual save: no loose or dangling flows, valid ports, and names match labels.
- T5 done by delegated writer: threat model doc `81415a8`, Threat Dragon guide `a0f585d`, BITACORA entry in the third commit. PNG links in `docs/threat-model.md` are pending T6.
