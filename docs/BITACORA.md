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

### Segunda revisión

Una revisión posterior encontró tres formas adicionales de evadir `guardia.sh`, todas corregidas con el mismo ciclo TDD estricto (RED confirmado antes de tocar el hook: 8 de 29 casos fallando; GREEN después: 29/29).

- **Bypass A — abreviaturas de `--no-verify`.** Git acepta abreviaturas únicas de opciones largas, así que `git commit --no-verif` (o `--no-veri`, `--no-ver`, etc.) también desactiva los hooks, pero la regla original solo buscaba la cadena exacta `--no-verify`. Se reemplazó por una coincidencia de prefijo (`--no-ve?r?i?f?y?` seguido de un límite que no sea letra) que cubre desde `--no-v` hasta `--no-verify` sin coincidir con opciones distintas como `--no-verbose`.
- **Bypass B — crear o pasar a `main` con flags intermedios.** `git switch -c main`, `git checkout -B main` o `git switch --create main` combinados con un commit o merge evadían la regla, que solo buscaba el literal `git switch main`/`git checkout main` sin nada en medio. Se cambió a una regla de segmento (`git (switch|checkout)[^;&|]* main([ ;&|]|$)`) que permite cualquier flag entre el subcomando y `main`, sin cruzar separadores de comando (`;`, `&`, `|`). Se verificó que `git switch -c feat/main-page` sigue permitido, porque ahí "main" está precedido por `/`, no por un espacio.
- **Bypass C — espacios repetidos o tabuladores.** `git  switch  main` (doble espacio) o el mismo comando separado por tabuladores rompían la coincidencia literal de un solo espacio. Se añadió una normalización (`tr -s '[:space:]' ' '`) inmediatamente después de leer `CMD`, antes de aplicar cualquier regla, para que toda la lógica existente opere sobre espacios simples sin importar el separador original.
- **Falso positivo D (aceptado, sin cambios de código).** `git commit -m y && git log -n 5` sigue bloqueado porque la regla de flag corto `-n` busca ese patrón en todo el comando, no solo en la porción de `git commit`; el `-n` de `git log -n 5` la activa igual. Se documenta como aceptado (fail-closed): ante la duda entre un `-n` legítimo de otro subcomando y un intento real de saltarse los hooks, el hook debe bloquear.

**Prueba de regresión (segunda revisión):** `bash tests/hooks/guardia_test.sh` (29 casos; RED: 8 fallidos antes de la corrección, GREEN: 29/29 después).

## 2026-09-28 · Issue #4: protección de main (Fase 1)

Issue #4 creado a partir del borrador de una sesión previa desde iPhone: `main`
necesita protección efectiva del lado de GitHub, porque `guardia.sh` y los
hooks de `pre-commit` solo corren en el cliente local y no se ejecutan desde
Claude Code web o móvil.

- **Hallazgo:** el ruleset existente `protege` (id `24097824`) tiene una lista
  de bypass `always` que exime al rol Admin (el propio desarrollador) y a tres
  integraciones instaladas, además de reglas de `code_scanning`
  (CodeQL/Snyk/Trivy), `code_quality` y `code_coverage` apuntando a
  herramientas que hoy no están configuradas. En la práctica no bloquea nada.
  Decisión: reemplazarlo por una definición versionada como código, sin lista
  de bypass. Detalle completo en `docs/adr/0001-proteccion-rama-main.md`.
- **CI:** se añadió `.github/workflows/seguridad.yml` con tres jobs
  (`secretos`, `workflows`, `pruebas`) usando los binarios oficiales de
  `gitleaks` (v8.30.1) y `actionlint` (v1.7.12) descargados y verificados por
  `sha256` en el propio workflow, en vez de `gitleaks/gitleaks-action`
  (licencia no-SPDX, requiere `GITHUB_TOKEN`). Se añadió también
  `.github/dependabot.yml` para mantener actualizadas las acciones de
  `github-actions`.
- **Línea base de secretos:** `gitleaks git --redact --no-banner .` sobre el
  historial completo (11 commits) → sin hallazgos.
- **Limpieza de PR #3:** confirmada. La rama local `chore/2-configuracion-inicial`
  fue borrada; en GitHub el PR #3 quedó fusionado con un commit de un solo
  padre, con árbol idéntico al de `81f9c44`.

Fase 1 (esta rama, `ci/4-proteccion-main`) queda limitada a la definición del
workflow, dependabot, el ADR y esta entrada. La Fase 2 (aplicar el `PUT` sobre
`protege`, desactivar merge commit/rebase merge y verificar el bloqueo real)
requiere operación remota y autorización explícita, según `AGENTS.md` §2.

### Apertura del PR #5 (Fase 1)

- **Falso positivo de `guardia.sh` con el push.** La regla de push (`guardia.sh:22`) busca `\bmain\b` en todo el comando, y el guion de `ci/4-proteccion-main` cuenta como límite de palabra. El push de la rama quedó bloqueado. No se eludió el hook: el push lo ejecutó una persona directamente (`! git push`). La corrección de la regla, con su prueba de regresión, pasa al pendiente del issue #1.
- **Push rechazado por GitHub por falta del scope `workflow`.** El token OAuth de `gh` no podía crear archivos en `.github/workflows/`. Se amplió con `gh auth refresh -s workflow`. Alternativa más restrictiva, no adoptada por ahora: SSH o un token fine-grained limitado a este repositorio.
- **Primer CI en rojo (`workflows` y `pruebas`).** Causa: `run: echo "... issue #4)"` iba sin comillas externas y YAML interpretó ` #4)"` como comentario, así que bash recibió una comilla sin cerrar. En local no se detectó porque actionlint solo usa shellcheck si está instalado. Corregido con `run: |` en `c639e94`. Después de la corrección, los tres checks pasan (run `36480098678`). Convención adoptada: usar siempre `run: |` para los comandos de shell.

### Revisión de seguridad previa al push final (revisor-seguridad)

Veredicto: listo para push, sin hallazgos críticos, altos ni medios.

- **B3 (corregido).** `cancel-in-progress: true` también cancelaba ejecuciones en push a `main`: dos merges seguidos podían cancelar el escaneo de secretos del primero. Ahora solo se cancela en PR (`${{ github.event_name == 'pull_request' }}`).
- **B1 (resuelto).** El token de `gh` conservaba el scope `workflow` añadido para el push; un token filtrado con ese scope podría modificar workflows. Se quitó con `gh auth refresh --remove-scopes workflow` tras el push de `4fd87eb` (CI run `36496048552` en verde). Verificado con `gh auth status`: scopes `gist`, `read:org`, `repo`. Nota: cualquier push futuro que toque `.github/workflows/` por HTTPS necesita volver a añadirlo temporalmente (o usar SSH).
- **B2 (para la Fase 2).** Los checks requeridos del ruleset deben fijar `integration_id` de GitHub Actions; sin él, cualquier app con permiso de escribir checks podría satisfacerlos.
- **I1 (verificado, 2026-09-28).** Los pines de `seguridad.yml` coinciden con las fuentes oficiales, obtenidas con `gh release download` y `gh api`:
  - gitleaks v8.30.1 `linux_x64.tar.gz`: `551f6fc8…2470eb`, igual a `gitleaks_8.30.1_checksums.txt`.
  - actionlint v1.7.12 `linux_amd64.tar.gz`: `8aca8db9…9a3d8`, igual a `actionlint_1.7.12_checksums.txt`.
  - `actions/checkout` v7.0.1: el tag apunta al commit `3d3c42e5…a90b1`, igual al pin.
  - Límite: confirma que los hashes son los publicados por cada proyecto; no protege frente a una release comprometida en origen.

## 2026-09-28 · Issue #4: protección de main (Fase 2, parte local)

Rama `ci/4-ruleset-como-codigo` (el nombre evita el falso positivo de `guardia.sh` con `-main`).

- **Ruleset como código.** `.github/rulesets/main.json` define `protege` según el ADR 0001: sin bypass, borrado y force push bloqueados, historial lineal, PR obligatorio con 0 aprobaciones, aprobaciones obsoletas descartadas, conversaciones resueltas, solo squash, y checks `secretos`/`workflows`/`pruebas` en modo `strict`.
- **Hallazgo B2 aplicado.** Cada check requerido se fija a GitHub Actions (`integration_id` 15368, leído de los check runs de `a85401a`), para que otra app o token no pueda satisfacerlo con un check del mismo nombre.
- **Esquema verificado** contra la descripción OpenAPI oficial de la REST API de GitHub (`allowed_merge_methods`, `integration_id`).
- **Prueba de política.** `tests/rulesets/main_ruleset_test.sh` (15 casos, `jq`). RED: sin archivo, y el `protege` vivo falla 10/15. GREEN: 15/15 contra el archivo. La misma prueba sirve como detector de deriva contra la salida de `gh api`.
- **Observación.** El job `pruebas` del CI sigue siendo un placeholder: ni esta prueba ni la de `guardia.sh` corren en CI. Conectarlas requiere tocar el workflow (y el scope `workflow` para el push); queda como pendiente.

- **Revisión de seguridad (revisor-seguridad):** listo para PR, sin críticos ni altos. `integration_id` 15368 verificado contra los check runs de `a85401a`. M1 (autofusión sin revisión técnica por 0 aprobaciones y sin CODEOWNERS) registrado como riesgo residual aceptado en el ADR 0001. M2 (`pruebas` placeholder como check requerido) pasa a un issue aparte. Antes del `PUT`, identificar las tres integraciones con bypass actual (IDs 946600, 1143301, 1236702; la API devolvió 403 con el token de `gh`).

Pendiente (operación remota, con autorización explícita por paso): push y PR, `PUT` del ruleset tras la fusión, desactivar merge commit y rebase merge, y las cuatro verificaciones de bloqueo.

## Pendientes
- [ ] Probar el kit dentro de Claude Code (/memory, /permissions, /hooks, /agents; commit en main debe bloquearse).
- [ ] Fase E0: completar docs/PROJECT_CONTEXT.md.
- [x] Contacto en SECURITY.md.
- [ ] Confirmar política institucional sobre dónde alojar el repositorio.
- [ ] Elegir lenguaje y stack; añadir sus comandos de prueba/lint a .claude/settings.json.
- [ ] Issue #1: cubrir bypasses restantes de guardia.sh (push -uf, git -C, rutas absolutas, core.hooksPath, CODEOWNERS, pinning por SHA, imágenes rotas en PROJECT_CONTEXT.md). El falso positivo de nombre de rama (`feature/main-page`) quedó resuelto como efecto de la corrección del Bypass B de la segunda revisión (regla de segmento que exige un espacio antes de `main`, no `/` ni `-`). **Nota (2026-09-28):** el issue #1 aparece CLOSED en GitHub, pero los bypasses restantes siguen pendientes sin corregir; hace falta reconciliar (reabrirlo o crear un issue nuevo que los cubra). Además, la regla de push de `guardia.sh` bloquea ramas cuyo nombre contiene `-main` (p. ej. `ci/4-proteccion-main`) porque `\bmain\b` coincide tras un guion; hay que exigir `main` como destino real y añadir la prueba de regresión.
- [ ] Issue #4 Fase 2: ~~ruleset como código con `integration_id` (B2)~~ hecho en local; falta PUT sobre protege + desactivar merge commit/rebase + 4 verificaciones.
- [ ] Ejecutar `tests/hooks/guardia_test.sh` y `tests/rulesets/main_ruleset_test.sh` en el job `pruebas` del CI (hoy es un placeholder).
- [x] Quitar el scope `workflow` del token de `gh` tras el push de `ci/4-proteccion-main` (hallazgo B1).
- [x] Contrastar los sha256 de gitleaks y actionlint con los `checksums.txt` oficiales antes del merge de PR #5 (hallazgo I1).
