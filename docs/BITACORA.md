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

## 2026-09-28 · Issue #4: protección de main (Fase 2, aplicación y verificación)

Fechas en hora local (UTC−5); GitHub registra estos eventos el 2026-09-29 en UTC.

- **PR #6** fusionado con squash como `b8ff3af` (CI run `36501247990` en verde). Antes del `PUT` se identificaron las integraciones con bypass: `claude` (1236702) y `copilot-swe-agent` (1143301); la 946600 no se pudo identificar. Claude y Copilot trabajan mediante PR y no necesitan escribir en `main`; para la 946600 se retiró el bypass sin poder comprobar su uso, así que hay que vigilar si algún flujo automatizado empieza a fallar.
- **`PUT` del ruleset** `protege` (id 24097824) con `.github/rulesets/main.json`. Antes: 4 actores con bypass y reglas `creation`, `update`, `required_signatures` y de escaneo sin herramienta. Después: sin bypass y solo las cinco reglas del ADR. La prueba de política contra un `GET` independiente da 15/15. La copia del ruleset anterior quedó fuera del repositorio.
- **Configuración de fusión del repositorio** (`PATCH`): merge commit y rebase merge desactivados, squash activo.
- **Verificación del bloqueo:**
  - Push directo a `main` con el usuario Admin: rechazado (`GH013`, exige PR y los 3 checks).
  - PR #7 fusionado con squash antes de los checks: rechazado.
  - Merge commit y rebase con los checks en verde: rechazados («not allowed on this repository»).
  - Force push: el intento se hizo con un commit encima de `main`, así que lo rechazó la regla de PR y no la de `non_fast_forward`. No se intentó un force push real porque, si la protección fallara, reescribiría `main`; la regla se confirma activa por la API. Queda como verificación indirecta.
  - El PR #7 se cerró sin fusionar y su rama se borró.
- **Aprendizaje:** `guardia.sh` evalúa la rama actual antes de ejecutar y bloquea cualquier comando que combine `git push` con la palabra `main` (también `gh pr create --base main` en el mismo comando). Hay que separar los comandos; no es un bypass.

## 2026-09-28 · Issue #9: pruebas reales en el job `pruebas` (M2)

Rama `ci/9-pruebas-reales`. Hallazgo M2 de la revisión de seguridad de la Fase 2 del #4. El job `pruebas` era un check obligatorio del ruleset `protege` que solo hacía `echo`, así que su verde no demostraba nada y un PR podía debilitar `.github/rulesets/main.json` o `guardia.sh` sin que fallara ningún check.

- **Cambio:** `pruebas` ejecuta ahora `tests/hooks/guardia_test.sh` (29 casos) y `tests/rulesets/main_ruleset_test.sh` (15 casos), en dos pasos separados para ver en CI cuál falla. El nombre del job no cambia, porque el ruleset lo exige por ese contexto.
- **Verificación local:** ambas suites salen con código 0; con una mutación (`"squash"` → `"merge"` en `main.json`) la del ruleset sale con 1. El YAML parsea sin errores; `actionlint` corre en el job `workflows` del CI.
- **Efecto sobre M1** (riesgo residual del ADR 0001: autofusión sin segundo revisor): con estas pruebas en CI, un PR que debilite el ruleset o el hook tiene que modificar también la prueba para quedar en verde; el cambio queda visible en el diff. No sustituye a un segundo revisor.
- **Límite:** la prueba valida el archivo `.github/rulesets/main.json`, no el ruleset aplicado en GitHub. Un cambio hecho directamente desde la interfaz web (deriva) no lo detecta este job; para eso hay que ejecutar la prueba contra la salida de `gh api .../rulesets/24097824`.

## 2026-09-28 · Issue #1 reabierto: guardia.sh falla cerrado (PR A)

El issue #1 se había cerrado como completado, pero al contrastar sus criterios con el código solo estaban hechas las pruebas del hook. Se reabrió con un comentario que lista lo pendiente, y el trabajo se divide en dos PR: A (`guardia.sh`) y B (`settings.json` y fijar gitleaks por SHA). Esta entrada cubre el A, en la rama `fix/1-guardia-fail-closed`.

- **Fallo abierto corregido.** Si faltaba `jq` o la entrada no era JSON válido, `CMD` quedaba vacío y el hook salía con 0: todas las protecciones se desactivaban sin aviso. Ahora bloquea (exit 2) en ambos casos.
- **Análisis por segmentos.** El comando se divide en segmentos (`;`, `&&`, `||`, `|`, `&` y saltos de línea) y en cada uno se localiza el primer `git`, esté donde esté. Antes se limpia una copia sin comillas ni barras invertidas y con `( ) { } $ \` !` como espacios. Con eso se detecta git detrás de `env`, `command`, `time`, `bash -c`, `sudo`, `/usr/bin/git`, `"git"`, `g\it`, subshells, grupos, `$(...)` y las opciones globales (`-C`, `-c`, `--no-pager`, `--git-dir`, `--namespace`...). Cada aparición de `git` en el segmento se evalúa por separado. No cubre la expansión del shell (ver ADR 0002).
- **Rama destino desconocida = bloqueo.** Commit, merge, cherry-pick, revert y am se bloquean en `main`, con HEAD separado, con `-C`/`--git-dir`/`--work-tree`, con `GIT_DIR=`/`GIT_WORK_TREE=` y tras un `cd`/`pushd` fuera del proyecto o no resoluble (`cd "$VAR"`).
- **`core.hooksPath`** bloqueado en cualquier forma (`-c` o `git config`). Efecto secundario aceptado: también bloquea cualquier comando que solo mencione esa cadena como texto (por ejemplo, un script que edita esta bitácora); se resuelve escribiendo el contenido en un archivo en vez de pasarlo en la línea de comandos.
- **Regla de push precisa.** Evalúa solo los tokens del `git push`. Bloquea el forzado (`--force*`, `-f` en flags combinados como `-uf`, `+refspec`), `--mirror`, `--all`, `--prune` y sus abreviaturas (git acepta prefijos únicos: `--forc`, `--mirr`), el destino `main` (`main`, `x:main`, `refs/heads/main`, `--delete main`) y el push sin refspec desde `main`. Ya no bloquea ramas con `main` en el nombre (`ci/4-proteccion-main`) ni un `gh pr create --base main` encadenado.
- **TDD, tres rondas.** Suite de 29 a 86 casos. Ronda 1: RED 20/62, GREEN 62/62. Ronda 2, tras leer el código: 17 bypasses nuevos, RED 17/83, GREEN 83/83. Ronda 3: una regresión con saltos de línea (`git status⏎git commit` en main pasaba, y el hook anterior sí lo bloqueaba), RED 3/86, GREEN 86/86. La implementación de las dos primeras rondas la hizo un subagente escritor; la tercera, inline.
- **Cuarta ronda (revisión de seguridad).** El `revisor-seguridad` no pudo ejecutar el hook y dejó sus hallazgos como sospechas; se reprodujeron 19 evasiones, todas con exit 0. Se cerraron con TDD (RED 20/112, GREEN 112/112) las familias estructural y de configuración: opciones globales con valor (`--namespace`, `--config-env`) y opciones desconocidas (fail-closed), todas las apariciones de `git` en el segmento (`sudo -u git git commit`), cambio compuesto a `main` con cherry-pick/revert/am y `symbolic-ref`, refspecs con `*`, `:` solitario y destino `.../main` (`HEAD:heads/main`), valores de `-o`/`--repo` fuera del conteo de refspecs, `SKIP=` de pre-commit, `git config`/`-c` sobre claves peligrosas (push remoto, alias, include, hooks...) y las variables de entorno `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_*`, `GIT_CONFIG_VALUE_*`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL` y `GIT_CONFIG_SYSTEM`. También falla cerrado con bash < 4, sin `realpath`/`sed`/`grep`/`tr` o sin `CLAUDE_PROJECT_DIR`, y usa el campo `cwd` que envía Claude Code: un directorio de trabajo fuera del proyecto equivale a rama destino desconocida. Tras el cambio, de las 19 evasiones siguen abiertas solo las 3 de expansión del shell y `reset --hard` en `main`.
- **Quinta ronda (pasada final de seguridad).** Veredicto: listo para PR con reservas, sin fallos abiertos nuevos. Se cerraron con TDD (RED 10/125, GREEN 125/125): entrada vacía o JSON sin `command` (ahora bloquea), `--attr-source` con valor, abreviaturas mínimas por opción (`--m` de `--mirror`), `switch -`/`checkout @{-1}` combinados con commit, las claves `remote.*.mirror`, `core.worktree` y `core.bare`, y **`gh pr merge`**: la fusión de un PR la hace una persona (AGENTS.md §5), así que el agente ya no puede ejecutarla. Una fusión mediante `gh api` no se cubre.
- **Modelo de amenaza (ADR 0002).** `guardia.sh` protege contra errores del agente, no contra un evasor deliberado: esa defensa la dan `pre-commit` (commit real) y el ruleset de GitHub (servidor). La expansión del shell (`${IFS}`, llaves, `$'...'`) queda como límite inherente.
- **Falsos positivos aceptados (fail-closed):** además de los dos ya documentados del `-n`, bloquean `echo git commit` en main, una rama destino que termine en `/main` (`feat/main`), opciones globales no reconocidas (`-C.`) y cualquier texto de mensaje o cuerpo de PR pasado en la línea de comandos que contenga comandos git, claves de config bloqueadas o `SKIP=`. Se evitan pasando ese texto por archivo (`-F`, `--body-file`).
- **Límites conocidos:** expansión del shell (`${IFS}`, llaves, `$'...'`, globs), alias y funciones de shell, `eval`, variables que contienen `git` (`$G commit`), scripts ejecutados indirectamente, `rebase` y `reset`/`update-ref`/`branch -f` sobre `main` no se cubren. Tampoco los alias de git preexistentes, editar `.git/config` directamente, `pull` en `main` ni fusionar vía `gh api`. La división en segmentos ignora las comillas, y un `cd` afecta a todos los segmentos posteriores aunque esté dentro de un subshell. El directorio de trabajo persistente sí se controla: el hook lee el campo `cwd` de la entrada. `guardia.sh` es una capa de defensa en profundidad: la protección que no depende del cliente es el ruleset de GitHub.

## 2026-09-28 · Issue #1: permisos y cadena de suministro (PR B)

Rama `fix/1-permisos-settings`. Cierra los criterios pendientes del issue #1 después del PR A (#11, `ce62919`).

- **Lectura de secretos con comandos aprobados sin confirmación.** `.claude/settings.json` permite `git diff *` y `git log *` sin preguntar. El manual de git 2.55 confirma que `git diff` compara rutas del sistema de archivos (modo `--no-index`) también de forma implícita si una ruta queda fuera del árbol de trabajo, así que `git diff /dev/null .env` imprimía `.env` sin confirmación: bloquear solo `--no-index`, como pedía el issue, no bastaba. Se añadió a `guardia.sh` una regla para `diff`, `log`, `show`, `whatchanged`, `grep`, `blame` y `cat-file`: bloquea `--no-index`, `--output` (escribe archivos) y `--ext-diff` (ejecuta un programa externo); en `diff`, cualquier ruta absoluta o con `..`; y en todos, las rutas literales a `.env`, `.env.*` (salvo `.env.example`) o `secrets/`, también en la forma `<rev>:ruta`. Se comprobó que git no acepta abreviaturas de esas tres opciones de `diff`/`log` (`--ext`, `--no-ind`, `--outp` fallan con opción desconocida). TDD: RED 9/141, GREEN 141/141.
- **Segunda ronda (revisión de seguridad).** El `revisor-seguridad` dio veredicto bloqueante con varias vías. Criterio aplicado: `.env` está en `.gitignore`, así que los pathspecs sobre contenido **registrado** (`git log -p`, `git diff --cached`, globs como `'*.env'`) no pueden alcanzarlo mientras no se commitee, y eso lo impide gitleaks; quedan como límite documentado. Sí se cerraron las vías que leen archivos **fuera de lo que git registra** o ejecutan programas: `git diff ~/…` y `git diff $…` (no-index implícito oculto por la expansión del shell), `show :0:.env` y `log -L1,9:.env` (formas de ruta no reconocidas), `blame --contents`, `grep -f`/`--file`, `grep --untracked`/`--no-exclude-standard`, `grep -O`/`--open-files-in-pager`, `cat-file --batch`, `GIT_EXTERNAL_DIFF=`, `GIT_PAGER=` y las claves `diff.external`, `diff.*.command`, `core.pager` y `pager.*`. El writer indicó que las abreviaturas de esas opciones no estaban cubiertas; al comprobarlo, `git grep` y `git blame` sí las aceptan (`--op`, `--u`, `--no-exc`, `--cont`), así que se añadió el bloqueo por prefijo mínimo. TDD: RED 13/158 y 2/164, GREEN 164/164.
- **`.env.example` sigue sin poder leerse con la herramienta Read (decisión).** La documentación oficial de Claude Code indica que una regla `allow` no puede crear excepciones a una `deny`. Para que `.env.example` fuera legible habría que sustituir `Read(./.env.*)` por una lista de variantes de secretos, y un nombre no previsto quedaría expuesto. Se mantiene la regla `deny` (falla cerrado, como el ejemplo oficial); la plantilla, que solo contiene valores ficticios, se lee bajo petición con un comando confirmado. Se descarta ese criterio del issue #1.
- **Ruta del hook entre comillas** en `settings.json`, con la forma de la documentación oficial (`"$CLAUDE_PROJECT_DIR"/.claude/hooks/guardia.sh`), para que una ruta con espacios no rompa el hook.
- **Hooks de pre-commit fijados por SHA** en vez de por etiqueta (una etiqueta se puede mover): gitleaks `83d9cd68…` (`v8.30.1`, la misma versión que la CI; antes `v8.30.0`) y pre-commit-hooks `3e8a8703…` (`v6.0.0`). Los SHA se resolvieron desde las etiquetas oficiales con `gh api`, y se comprobó que el hook `gitleaks` existe en ese commit.

## 2026-09-28 · Cierre del issue #1, configuración del repositorio y prueba del kit

- **Issue #1 cerrado.** PR #11 (PR A, `ce62919`) y PR #12 (PR B, `6919443`) fusionados con squash; el `Closes #1` del PR #12 cerró el issue como completado. Todos sus criterios quedaron cumplidos salvo uno, descartado con justificación: `.env.example` sigue sin poder leerse con la herramienta Read porque una regla `allow` no puede exceptuar una `deny` (ver entrada del PR B).
- **Borrado automático de ramas al fusionar.** `PATCH` sobre el repositorio con autorización explícita: `delete_branch_on_merge` pasó de `false` a `true`, confirmado con un `GET` independiente. GitHub borra la rama remota al fusionar un PR; la rama local se borra al actualizar `main`, tras comprobar que su árbol es idéntico.
- **Decisión: no se delega trabajo en GitHub Copilot.** Se evaluó asignar tareas elementales al agente de Copilot mediante issues para reservar las complejas a Claude Code, y se descartó. Todo el trabajo se hace en la sesión de Claude Code (directamente o con subagentes). El bypass de Copilot sobre `main` ya se había eliminado con el `PUT` del ruleset.
- **Prueba del kit dentro de Claude Code.** `/hooks`, `/agents`, `/memory` y `/permissions` son comandos interactivos que escribe la persona en el prompt; el agente no puede ejecutarlos. Se verificó con evidencia lo que esos comandos inspeccionan:
  - Hook: un `git commit` en `main` quedó bloqueado con `Bloqueado: estás en main`, y el mensaje mostró la ruta nueva entre comillas (`"$CLAUDE_PROJECT_DIR"/.claude/hooks/guardia.sh`), así que Claude Code cargó la configuración del PR B. Durante la sesión el hook bloqueó además comandos reales del agente (textos con `core.hooksPath`, `-n` junto a un commit, un push con `main` antes de la corrección de la regla).
  - Subagente: `.claude/agents/revisor-seguridad.md` existe y se invocó en cada PR (#5, #6, #8, #10, #11, #12). Limitación observada: sus herramientas (`Read`, `Grep`, `Glob`, `Bash(git diff *)`) no le permiten ejecutar el hook, así que sus hallazgos sobre el hook llegan como sospechas y el orquestador los reproduce.
  - Permisos: `defaultMode` es `plan`, y durante la sesión se denegaron comandos con `curl` y `rm -rf` según las reglas `deny`.
  - Memoria: `CLAUDE.md` y sus imports (`AGENTS.md`, `docs/PROJECT_CONTEXT.md`, `docs/BITACORA.md`) se cargaron en el contexto desde el inicio de la sesión; el agente aplicó sus reglas (modo plan al empezar, ramas `tipo/ID-descripcion`, revisor antes de cada PR, bitácora al cerrar cada tarea).
  - Confirmación visual por la persona (2026-09-28):
    - `/hooks`: `guardia.sh`, definido en `.claude/settings.json`.
    - `/agents`: `revisor-seguridad`.
    - `/context`: en *Custom agents*, `revisor-seguridad` aparece como agente del proyecto. En *Memory files* aparecen 6 archivos: `~/.claude/CLAUDE.md` (usuario), `CLAUDE.md`, `AGENTS.md`, `docs/PROJECT_CONTEXT.md` y `docs/BITACORA.md` (proyecto; los tres últimos son imports de `CLAUDE.md`) y el `MEMORY.md` de la memoria automática.
    - Nota: el comando para verificar qué archivos de instrucciones se cargaron es `/context` (sección *Memory files*); `/memory` sirve para abrirlos y editarlos.

## 2026-09-29 · Issue #15: E0, elección de la aplicación

Rama `docs/15-ficha-agregador`. Cierra la parte documental de E0: aplicación elegida, ficha, ADR y propuesta escrita.

- **Identix elegida y descartada el mismo día.** Su OSINT sobre personas reales exigía verificar la titularidad de cada identificador (OAuth, un código en la biografía), recoger consentimiento y borrar datos: una carga de protección de datos que superaba el alcance. Además, las plataformas sociales principales no ofrecen acceso legítimo y gratuito. Se renuncia a la bonificación de +1 punto, y la aplicación pasa a ser una propuesta propia que el profesor debe validar por escrito (sección 2 del enunciado).
- **Aplicación elegida: H4tt3r_1nf0rm4t1v0**, agregador de noticias y tendencias de medios colombianos y de habla hispana, con búsqueda por tema, agrupación por noticia y sentimiento. Solo se guardan titular, enlace, fecha y resumen corto.
- **Imágenes del enunciado restauradas** en `f834b9d` (`Logo.png`, `Arquitectura_IDENTIX.png`).
- **Verificación de fuentes (2026-09-29, investigación de solo lectura; los resúmenes de las herramientas son de segunda mano).** Incluidas: RCN y Semana (RSS), Caracol, Blu Radio y Citytv (sitemaps), YouTube Data API, Google Trends RSS (no oficial) y tendencias de Mastodon. Excluidas: X (sin nivel gratuito), Reddit (aprobación previa), CNN en Español (HTTP 451 y bloqueo a bots de IA), Facebook, Instagram y TikTok (sin acceso legítimo para este caso). Detalle, URL y elementos NO VERIFICADO en `docs/PROJECT_CONTEXT.md`.
- **Decisiones del usuario (2026-09-29):** (1) alojamiento en este repositorio, con el traslado a una rama del repositorio del curso como última tarea; (2) cuatro servicios desplegables, ADR 0003; (3) fuentes anteriores; (4) historia de usuario de la sustentación: búsqueda por tema; (5) licencia Apache 2.0, con la licencia del modelo de sentimiento declarada aparte; (6) K3s mediante k3d e IaC con Terraform; (7) Docker Hub `h4tt3rxplo1tt`.
- **Aviso de Docker Hub.** Existe una cuenta parecida, `h4tt3rxplo1t` (una sola t), que no está confirmada como del proyecto. Usar siempre el nombre exacto `h4tt3rxplo1tt` (riesgo de typosquatting) y publicar solo desde CI con un token de alcance mínimo.
- **Documentos añadidos:** sección de ficha en `docs/PROJECT_CONTEXT.md`, `docs/adr/0003-agrupacion-microservicios.md` y `docs/propuesta.md`.
- **Revisión de seguridad (revisor-seguridad):** listo para PR, sin hallazgos críticos, altos ni medios. Corregidos en esta rama: B1 (el `User-Agent` es propio y no suplanta a otro; una fuente que lo bloquee en `robots.txt` se desactiva) y B3 (la afirmación «sin datos personales de terceros» era demasiado fuerte: ahora dice «no se recogen como objetivo», y de Mastodon solo se usan etiquetas y enlaces en tendencia, porque `/trends/statuses` devuelve publicaciones y autores). B2, B5 y B6 pasan a pendientes de E1, E3 y E7. B4 (namespace de Docker Hub sin verificar) ya estaba resuelto: `h4tt3rxplo1tt` se comprobó en la API pública de Docker Hub y con la captura de la cuenta de la persona.
- **Decisiones posteriores al PR #16 (2026-09-29, persona):** la propuesta no se enviará al profesor por ahora (decisión propia, con el riesgo de que la aplicación no se acepte al final; sección 2 del enunciado). Los términos de uso de los 5 medios los revisó la persona y ninguno prohíbe el uso informativo con enlace. Se fija como regla la atribución: nombre del medio, autor cuando exista, fecha y enlace al original. En `docs/propuesta.md` el autor figura con el seudónimo público `H4TT3R_XPLO1T` (el mismo de la cuenta de GitHub), no con el nombre real, porque el repositorio es público.
- **Aprendizaje:** verificar el acceso a cada plataforma antes de comprometer el alcance. Identix se apoyaba en redes sociales cuyo acceso legítimo no existe o exige aprobaciones; comprobarlo al inicio habría ahorrado el desvío.

## Pendientes
- [ ] **E0 (en curso, issue #15, PR #16):** ficha, ADR 0003 y propuesta escritos. Después, añadir los comandos de prueba y lint del stack a `.claude/settings.json`.
- [x] Revisión manual de los términos de uso de RCN, Semana, Caracol, Blu Radio y Citytv (persona, 2026-09-29): ninguno prohíbe el uso informativo con enlace. Repetir antes de la entrega final.
- [ ] Verificar las versiones del stack (AGENTS.md §3) antes de fijarlas.
- [ ] **E1:** modelar el contenido de las fuentes externas como entrada no confiable (XSS, XXE en RSS y sitemaps, SSRF con lista fija de dominios) y la concentración de funciones en el gateway como amenaza de elevación de privilegios (hallazgos B2 y B6 del #15).
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).
- [ ] **E7:** referenciar las imágenes por digest, no solo por `vX.Y.Z` y `latest` (hallazgo B4 del #15).
- [ ] Traslado a una rama del repositorio del curso: última tarea del proyecto (decidido el 2026-09-29).
- [ ] CODEOWNERS para rutas sensibles (`.github/**`, `.claude/**`, `tests/**`, `docs/adr/**`), útil cuando haya un segundo revisor (mitigación de M1, ADR 0001).
- [x] Imágenes rotas referenciadas en `docs/PROJECT_CONTEXT.md` (`Logo.png`, `Arquitectura_IDENTIX.png`), restauradas en `f834b9d`.
- [x] Contacto en SECURITY.md.
- [x] Prueba del kit dentro de Claude Code: hook, subagente, permisos y archivos de memoria verificados (`/hooks`, `/agents`, `/context`).
- [x] Issue #1: `guardia.sh` falla cerrado, lectura de secretos con git, permisos y pre-commit por SHA (PR #11 y #12).
- [x] Issue #4: ruleset como código, `PUT` sobre `protege`, merge commit y rebase desactivados, bloqueo verificado (PR #5, #6 y #8).
- [x] Issue #9 (M2): el job `pruebas` ejecuta las pruebas reales (PR #10).
- [x] `delete_branch_on_merge` activado.
- [x] Quitar el scope `workflow` del token de `gh` (hallazgo B1 del PR #5).
- [x] Contrastar los sha256 de gitleaks y actionlint con los `checksums.txt` oficiales (hallazgo I1 del PR #5).
