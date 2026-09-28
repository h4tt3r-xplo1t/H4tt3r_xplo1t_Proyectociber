# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## 2026-09-27 · Arranque
- Prompt maestro v4 adoptado (AGENTS.md): trabajo en capas, modos por permisos, fases E0–E9, flujo GitHub.
- Configuración de Claude Code: modo plan por defecto, permisos allow/ask/deny, hook de guardia, subagente revisor-seguridad, comando /tarea.
- Referencias vigentes (verificar en cada uso): OWASP ASVS 5.0, OWASP Top 10:2025, NIST SSDF 1.1 (1.2 en borrador), SLSA v1.2, CycloneDX 1.7.x.

## 2026-09-28 · Correcciones de guardia.sh (PR #3)

La revisión de seguridad del PR #3 (rama `chore/2-configuracion-inicial`, issue #2) encontró dos formas de saltarse el hook `guardia.sh`. Ambas quedan corregidas en esta iteración, con pruebas de regresión previas (TDD estricto: RED confirmado antes de tocar el hook, GREEN después).

- **Bypass 1 — flag corto `-n` en `git commit`.** `git commit -n -m x` (y variantes combinadas como `-nm` o `-an`) equivalen a `--no-verify` pero no coincidían con la regla existente, que solo buscaba el flag largo. Se añadió una regla que bloquea cualquier `git commit` cuyo comando contenga un token de flag corto que incluya la letra `n` (patrón `-[a-zA-Z]*n[a-zA-Z]*`).
  - Efecto secundario aceptado (fail-closed): la regex no distingue el contenido de un mensaje de commit entre comillas de un flag real, así que `git commit -am "fix -n flag"` también se bloquea aunque el `-n` esté solo en el texto del mensaje. Se documenta como falso positivo aceptado porque ante la duda el hook debe bloquear, no dejar pasar un `--no-verify` real. Cubierto por `tests/hooks/guardia_test.sh`.
- **Bypass 2 — commit/merge a main mediante comando compuesto.** El hook leía la rama actual (`git branch --show-current`) *antes* de que el comando se ejecutara, así que `git switch main && git commit -am x` pasaba porque en el momento de la comprobación la rama todavía no era `main`. Se añadió una regla que bloquea cualquier comando que contenga `git switch main` o `git checkout main` junto con `git commit` o `git merge`, sin importar la rama en la que se esté al momento de evaluar.
  - Defensa adicional (defensa en profundidad, capa de git): se añadió el hook `no-commit-to-branch` (`--branch main`) del repositorio `pre-commit/pre-commit-hooks` a `.pre-commit-config.yaml`. Se ejecuta en el momento real del commit, con la rama real, y también cubre commits hechos por personas fuera de Claude Code. Verificado antes de añadirlo (AGENTS.md §3): repositorio `pre-commit/pre-commit-hooks`, licencia MIT, no archivado, última versión `v6.0.0` publicada el 2025-08-09, el hook `no-commit-to-branch` existe en ese tag.
  - Limitación conocida: esta capa de git no cubre fusiones fast-forward hechas fuera de un commit (`git merge --ff-only` que no crea un commit nuevo); la regla del hook de Claude Code sí las cubre porque inspecciona el texto del comando.

**Pendientes movidos al issue #1** (no forman parte de este PR):
- `git push -uf` (combinación de flags que evade la detección de `--force`).
- `git -C <ruta> commit ...` o rutas absolutas (`/usr/bin/git commit ...`) que evaden la detección basada en `git` al inicio del comando.
- `-c core.hooksPath=...` para apuntar a un directorio de hooks distinto.
- Falso positivo en sentido contrario: nombres de rama que contienen la palabra `main` (p. ej. `feature/main-page`) podrían activar la regla de "cambio a main" de forma indebida.
- Falta de CODEOWNERS para rutas sensibles.
- Fijar los hooks de pre-commit por SHA en vez de por tag (mayor resistencia a compromisos del upstream).
- Imágenes rotas referenciadas en `docs/PROJECT_CONTEXT.md` (`Logo.png`, `Arquitectura_IDENTIX.png`).

**Prueba de regresión:** `bash tests/hooks/guardia_test.sh` (16 casos, ver `tests/hooks/guardia_test.sh`).

## Pendientes
- [ ] Probar el kit dentro de Claude Code (/memory, /permissions, /hooks, /agents; commit en main debe bloquearse).
- [ ] Fase E0: completar docs/PROJECT_CONTEXT.md.
- [x] Contacto en SECURITY.md.
- [ ] Confirmar política institucional sobre dónde alojar el repositorio.
- [ ] Elegir lenguaje y stack; añadir sus comandos de prueba/lint a .claude/settings.json.
- [ ] Issue #1: cubrir bypasses restantes de guardia.sh (push -uf, git -C, rutas absolutas, core.hooksPath, falso positivo de nombre de rama, CODEOWNERS, pinning por SHA, imágenes rotas en PROJECT_CONTEXT.md).
