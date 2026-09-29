#!/bin/bash
# Suite de regresión para .claude/hooks/guardia.sh (issue #2).
#
# Cada caso construye el JSON que Claude Code envía al hook
# ({"tool_input":{"command": "<cmd>"}}) con `jq -n` (evita problemas de
# escapado) y lo canaliza al hook, con CLAUDE_PROJECT_DIR apuntando a un
# repositorio git temporal cuya rama actual controlamos. Así las pruebas no
# dependen de la rama real de este repositorio.
#
# Uso: bash tests/hooks/guardia_test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOOK="$REPO_ROOT/.claude/hooks/guardia.sh"

FAILED=0
COUNT=0

# Crea un repo git temporal en la rama indicada y devuelve su ruta.
setup_repo() {
  local branch="$1"
  local dir
  dir=$(mktemp -d)
  git init -q -b "$branch" "$dir" >/dev/null
  git -C "$dir" config user.email "guardia-test@example.invalid"
  git -C "$dir" config user.name "guardia-test"
  echo "$dir"
}

# Crea un repo git temporal con un commit y HEAD separado (detached).
setup_detached_repo() {
  local dir
  dir=$(setup_repo feat/x)
  git -C "$dir" commit -q --allow-empty -m init
  git -C "$dir" checkout -q --detach
  echo "$dir"
}

# check_result <descripción> <exit esperado> <exit obtenido> <detalle>
check_result() {
  local desc="$1" expected="$2" actual="$3" detail="$4"
  COUNT=$((COUNT + 1))
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (esperado exit=$expected, obtenido exit=$actual) -- $detail"
    echo "  salida del hook: $(cat /tmp/guardia_test_out.$$)"
    FAILED=$((FAILED + 1))
  fi
  rm -f /tmp/guardia_test_out.$$
}

# run_case <descripción> <comando> <rama|DETACHED> <exit code esperado>
run_case() {
  local desc="$1" cmd="$2" branch="$3" expected="$4"
  local dir actual
  if [ "$branch" = "DETACHED" ]; then
    dir=$(setup_detached_repo)
  else
    dir=$(setup_repo "$branch")
  fi

  jq -n --arg c "$cmd" '{tool_input:{command:$c}}' \
    | CLAUDE_PROJECT_DIR="$dir" bash "$HOOK" >/tmp/guardia_test_out.$$ 2>&1
  actual=$?

  rm -rf "$dir"
  check_result "$desc" "$expected" "$actual" "cmd: $cmd"
}

# run_cwd_case <descripción> <comando> <cwd relativo al proyecto|ruta absoluta> <exit esperado>
# Añade el campo "cwd" que Claude Code envía en la entrada del hook. Un cwd
# que empieza por "/" se usa tal cual; si no, se toma relativo al proyecto.
run_cwd_case() {
  local desc="$1" cmd="$2" cwd="$3" expected="$4"
  local dir actual
  dir=$(setup_repo feat/x)
  case "$cwd" in /*) ;; *) cwd="$dir/$cwd" ;; esac

  jq -n --arg c "$cmd" --arg w "$cwd" '{cwd:$w, tool_input:{command:$c}}' \
    | CLAUDE_PROJECT_DIR="$dir" bash "$HOOK" >/tmp/guardia_test_out.$$ 2>&1
  actual=$?

  rm -rf "$dir"
  check_result "$desc" "$expected" "$actual" "cmd: $cmd (cwd: $cwd)"
}

# run_raw_case <descripción> <entrada cruda> <PATH> <exit code esperado>
# Envía la entrada tal cual (sin construirla con jq) y permite sustituir PATH,
# para simular JSON inválido o la ausencia de jq.
run_raw_case() {
  local desc="$1" input="$2" path="$3" expected="$4"
  local dir actual
  dir=$(setup_repo feat/x)

  printf '%s' "$input" \
    | PATH="$path" CLAUDE_PROJECT_DIR="$dir" bash "$HOOK" >/tmp/guardia_test_out.$$ 2>&1
  actual=$?

  rm -rf "$dir"
  check_result "$desc" "$expected" "$actual" "entrada: $input"
}

# Directorio con enlaces a todos los ejecutables del sistema excepto jq, para
# simular un entorno donde jq no está instalado.
NO_JQ_BIN=$(mktemp -d)
for f in /usr/local/bin/* /usr/bin/* /bin/*; do
  name=$(basename "$f")
  [ "$name" = "jq" ] && continue
  [ -e "$NO_JQ_BIN/$name" ] || ln -s "$f" "$NO_JQ_BIN/$name" 2>/dev/null
done
# Igual, pero sin realpath (el hook lo necesita para resolver cd y cwd).
NO_REALPATH_BIN=$(mktemp -d)
for f in /usr/local/bin/* /usr/bin/* /bin/*; do
  name=$(basename "$f")
  [ "$name" = "realpath" ] && continue
  [ -e "$NO_REALPATH_BIN/$name" ] || ln -s "$f" "$NO_REALPATH_BIN/$name" 2>/dev/null
done
trap 'rm -rf "$NO_JQ_BIN" "$NO_REALPATH_BIN"' EXIT

echo "== Casos que deben bloquear (exit 2) =="

# Bypass 1: -n corto en git commit equivale a --no-verify.
run_case "commit -n -m x (flag corto -n)"            'git commit -n -m x'                          feat/x 2
run_case "commit -nm x (flag combinado -nm)"          'git commit -nm x'                            feat/x 2
run_case "commit -an -m x (flag combinado -an)"       'git commit -an -m x'                         feat/x 2

# Bypass 2: cambiar a main y hacer commit/merge en el mismo comando compuesto.
run_case "switch main && commit -am"                  'git switch main && git commit -am x'         feat/x 2
run_case "checkout main; commit -m x"                 'git checkout main; git commit -m x'          feat/x 2
run_case "switch main && merge feat/x"                'git switch main && git merge feat/x'         feat/x 2

# Regresiones existentes.
run_case "--no-verify explícito"                      'git commit --no-verify -m x'                 feat/x 2
run_case "commit -m x estando en main"                'git commit -m x'                              main   2
run_case "push a main"                                'git push origin main'                        feat/x 2
run_case "push --force"                               'git push --force origin feat/x'              feat/x 2

# Segunda revisión — bypass A: git acepta abreviaturas únicas de opciones
# largas, así que "--no-verif"/"--no-veri" también desactivan los hooks
# aunque no coincidan con la cadena exacta "--no-verify".
run_case "commit --no-verif (abreviatura de --no-verify)"   'git commit -m x --no-verif'                  feat/x 2
run_case "commit --no-veri (abreviatura de --no-verify)"    'git commit -m x --no-veri'                   feat/x 2
run_case "push --no-verif (abreviatura en push)"            'git push --no-verif origin feat/x'          feat/x 2

# Segunda revisión — bypass B: crear o pasar a main con flags intermedios
# (-c, -B, --create) entre "switch"/"checkout" y "main" evadía la regla
# original, que solo buscaba el literal "git switch main"/"git checkout main".
run_case "switch -c main && commit (crea rama 'main' local)"      'git switch -c main && git commit -m x'        feat/x 2
run_case "checkout -B main && commit (crea/resetea rama 'main')"  'git checkout -B main && git commit -m x'      feat/x 2
run_case "switch --create main; merge (forma larga de -c)"        'git switch --create main; git merge feat/x'   feat/x 2

# Segunda revisión — bypass C: espacios repetidos o tabuladores entre
# tokens rompían la coincidencia literal de un solo espacio.
run_case "switch  main con doble espacio && commit -am"           'git  switch  main && git commit -am x'        feat/x 2
TAB_SWITCH_MAIN_COMMIT=$'git\tswitch\tmain && git commit -m x'
run_case "switch/main separados por tabuladores && commit"        "$TAB_SWITCH_MAIN_COMMIT"                       feat/x 2

# Issue #1, PR A — fallar cerrado: si la entrada no se puede analizar, el
# hook debe bloquear en vez de dejar CMD vacío y salir con 0.
run_raw_case "entrada que no es JSON"                     'esto no es json'                                        "$PATH"      2
run_raw_case "jq no instalado"                            '{"tool_input":{"command":"git commit -m x"}}'           "$NO_JQ_BIN" 2

# Issue #1, PR A — opciones globales y envoltorios delante de git.
run_case "-C . commit estando en main"                    'git -C . commit -m x'                           main     2
run_case "-C <ruta> commit (rama destino desconocida)"    'git -C /tmp/otro commit -m x'                   feat/x   2
run_case "--git-dir=... commit (rama destino desconocida)" 'git --git-dir=/tmp/otro/.git commit -m x'      feat/x   2
run_case "-c user.name=x commit estando en main"          'git -c user.name=x commit -m x'                 main     2
run_case "--no-pager commit estando en main"              'git --no-pager commit -m x'                     main     2
run_case "env git commit estando en main"                 'env git commit -m x'                            main     2
run_case "env VAR=1 git merge estando en main"            'env GIT_TRACE=1 git merge feat/x'               main     2
run_case "command git commit estando en main"             'command git commit -m x'                        main     2
run_case "/usr/bin/git commit estando en main"            '/usr/bin/git commit -m x'                       main     2
run_case "commit con HEAD separado (rama vacía)"          'git commit -m x'                                DETACHED 2

# Issue #1, PR A — redirigir los hooks de git a otro directorio.
run_case "-c core.hooksPath=/dev/null commit"             'git -c core.hooksPath=/dev/null commit -m x'    feat/x   2
run_case "git config core.hooksPath"                      'git config core.hooksPath /tmp/hooks'           feat/x   2

# Issue #1, PR A — regla de push precisa: forzado y destino main.
run_case "push -uf (flags cortos combinados con -f)"      'git push -uf origin feat/x'                     feat/x   2
run_case "push +refspec (force push sin flag)"            'git push origin +feat/x'                        feat/x   2
run_case "push --force-with-lease"                        'git push --force-with-lease origin feat/x'      feat/x   2
run_case "push --mirror"                                  'git push --mirror origin'                       feat/x   2
run_case "push HEAD:main"                                 'git push origin HEAD:main'                      feat/x   2
run_case "push feat/x:refs/heads/main"                    'git push origin feat/x:refs/heads/main'         feat/x   2
run_case "push --delete main"                             'git push origin --delete main'                  feat/x   2
run_case "push sin refspec estando en main"               'git push'                                       main     2
run_case "-C <ruta> push origin main"                     'git -C /tmp/otro push origin main'              feat/x   2
run_case "/usr/bin/git push origin main"                  '/usr/bin/git push origin main'                  feat/x   2

# Issue #1, PR A (segunda ronda) — git invocado de formas que el shell
# ejecuta igual: subshell, grupo, comillas, escapes, bash -c, time, $(...).
run_case "(git commit) en subshell estando en main"       '(git commit -m x)'                              main     2
run_case "{ git commit; } en grupo estando en main"       '{ git commit -m x; }'                           main     2
run_case "\"git\" entre comillas estando en main"         '"git" commit -m x'                              main     2
run_case "g\\it con escape estando en main"               'g\it commit -m x'                               main     2
run_case "bash -c \"git commit\" estando en main"         'bash -c "git commit -m x"'                      main     2
run_case "time git commit estando en main"                'time git commit -m x'                           main     2
run_case "\$(git commit) estando en main"                 'echo $(git commit -m x)'                        main     2
run_case "bash -c \"git push origin main\""               'bash -c "git push origin main"'                 feat/x   2

# Issue #1, PR A (segunda ronda) — repositorio destino distinto del proyecto.
run_case "GIT_DIR=... git commit (rama destino desconocida)" 'GIT_DIR=/tmp/otro/.git git commit -m x'      feat/x   2
run_case "cd fuera del proyecto && git commit"            'cd /tmp && git commit -m x'                     feat/x   2
run_case "cd \$VAR && git commit (destino no resoluble)"  'cd "$OTRO" && git commit -m x'                  feat/x   2

# Issue #1, PR A (segunda ronda) — otros subcomandos que crean commits en main.
run_case "cherry-pick estando en main"                    'git cherry-pick abc123'                         main     2
run_case "revert estando en main"                         'git revert HEAD'                                main     2

# Issue #1, PR A (segunda ronda) — push que afecta a main sin nombrarla, y
# abreviaturas de opciones largas (git acepta prefijos únicos).
run_case "push --all"                                     'git push --all origin'                          feat/x   2
run_case "push --prune"                                   'git push --prune origin'                        feat/x   2
run_case "push --forc (abreviatura de --force)"           'git push --forc origin feat/x'                  feat/x   2
run_case "push --mirr (abreviatura de --mirror)"          'git push --mirr origin'                         feat/x   2

# Issue #1, PR A (tercera ronda) — un salto de línea separa comandos en el
# shell; no puede fundir dos invocaciones de git en un solo segmento.
NL_STATUS_COMMIT=$'git status\ngit commit -m x'
NL_LOG_PUSH_MAIN=$'git log -1\ngit push origin main'
NL_STATUS_PUSH_FORCE=$'git status\ngit push --force origin feat/x'
run_case "status⏎commit estando en main (salto de línea)"   "$NL_STATUS_COMMIT"                           main     2
run_case "log⏎push origin main (salto de línea)"            "$NL_LOG_PUSH_MAIN"                           feat/x   2
run_case "status⏎push --force (salto de línea)"             "$NL_STATUS_PUSH_FORCE"                       feat/x   2

# Issue #1, PR A (cuarta ronda, revisión de seguridad) — familia estructural:
# el parser debe entender git bien escrito.
run_case "--namespace <x> commit (opción global con valor separado)" 'git --namespace x commit -m y'      main     2
run_case "--config-env <a=B> commit (opción global con valor)"       'git --config-env a=B commit -m y'   main     2
run_case "sudo -u git git commit (el primer 'git' no es el comando)" 'sudo -u git git commit -m x'        main     2
run_case "switch main && cherry-pick"                     'git switch main && git cherry-pick abc'         feat/x   2
run_case "switch main && revert"                          'git switch main && git revert HEAD'             feat/x   2
run_case "symbolic-ref HEAD refs/heads/main && commit"    'git symbolic-ref HEAD refs/heads/main && git commit -m x' feat/x 2
run_case "push HEAD:heads/main (git completa refs/)"      'git push origin HEAD:heads/main'                feat/x   2
run_case "push con refspec comodín"                       'git push origin refs/heads/*:refs/heads/*'      feat/x   2
run_case "push origin : (todas las ramas coincidentes)"   'git push origin :'                              feat/x   2
run_case "push -o <valor> origin estando en main"         'git push -o x origin'                           main     2
run_case "-C <ruta> push origin sin refspec"              'git -C /tmp/otro push origin'                   feat/x   2
run_case "SKIP=<hook> git commit (salta hooks de pre-commit)" 'SKIP=gitleaks git commit -m x'              feat/x   2

# Issue #1, PR A (cuarta ronda) — familia de configuración persistente.
run_case "git config remote.origin.push"                  'git config remote.origin.push HEAD:main'        feat/x   2
run_case "git config alias con !"                         'git config alias.x "!git commit"'               feat/x   2
run_case "git config include.path"                        'git config include.path /tmp/otro.cfg'          feat/x   2
run_case "-c remote.origin.push=... push"                 'git -c remote.origin.push=HEAD:main push origin' feat/x  2
run_case "GIT_CONFIG_COUNT/KEY/VALUE en el entorno"       'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.$P GIT_CONFIG_VALUE_0=/x git commit -m y' feat/x 2
run_case "GIT_CONFIG_GLOBAL apuntando a otro archivo"     'GIT_CONFIG_GLOBAL=/tmp/otro.cfg git commit -m y' feat/x  2

# Issue #1, PR A (cuarta ronda) — fallar cerrado ante un entorno degradado y
# ante un directorio de trabajo persistente fuera del proyecto (campo cwd).
run_raw_case "realpath no instalado"                      '{"tool_input":{"command":"cd /tmp && git commit -m x"}}' "$NO_REALPATH_BIN" 2
run_cwd_case "cwd fuera del proyecto + commit"            'git commit -m x'                                '/tmp'   2
run_cwd_case "cwd fuera del proyecto + push sin refspec"  'git push'                                       '/tmp'   2
run_cwd_case "cwd dentro del proyecto + commit"           'git commit -m x'                                '.'      0

# Issue #1, PR A (quinta ronda, pasada final de seguridad).
run_raw_case "entrada vacía"                              ''                                                       "$PATH"      2
run_raw_case "JSON sin tool_input.command"                '{"tool_input":{}}'                                      "$PATH"      2
run_case "--attr-source <valor> commit (opción global con valor)" 'git --attr-source HEAD commit -m x'     main     2
run_case "push --m (abreviatura única de --mirror)"       'git push --m origin'                            feat/x   2
run_case "switch - && commit (vuelta a la rama anterior)" 'git switch - && git commit -m x'                feat/x   2
run_case "checkout @{-1} && commit"                       'git checkout @{-1} && git commit -m x'          feat/x   2
run_case "git config remote.origin.mirror"                'git config remote.origin.mirror true'           feat/x   2
run_case "git config core.worktree"                       'git config core.worktree /tmp/otro'             feat/x   2
# Solo una persona fusiona (AGENTS.md §5): el agente no puede ejecutar la fusión.
run_case "gh pr merge"                                    'gh pr merge 12 --squash'                        feat/x   2
run_case "gh pr merge encadenado tras push"               'git push -u origin feat/x && gh pr merge --auto --squash' feat/x 2

# Issue #1, PR B — git diff/log/show están permitidos sin confirmación en
# .claude/settings.json, así que no pueden servir para leer secretos ni
# escribir archivos. git diff compara rutas fuera del índice (modo
# --no-index) también de forma implícita si una ruta queda fuera del árbol.
run_case "diff --no-index /dev/null .env"                 'git diff --no-index /dev/null .env'             feat/x   2
run_case "diff /dev/null .env (no-index implícito)"       'git diff /dev/null .env'                        feat/x   2
run_case "diff ../otro archivo (ruta fuera del árbol)"    'git diff ../otro/archivo archivo'               feat/x   2
run_case "diff con ruta absoluta"                         'git diff /etc/hostname README.md'               feat/x   2
run_case "log -p -- .env.local"                           'git log -p -- .env.local'                       feat/x   2
run_case "show HEAD:secrets/clave.pem"                    'git show HEAD:secrets/clave.pem'                feat/x   2
run_case "log --output=<archivo> (escribe archivos)"      'git log --output=/tmp/x -1'                     feat/x   2
run_case "diff --output <archivo>"                        'git diff --output /tmp/x'                       feat/x   2
run_case "diff --ext-diff (ejecuta un programa externo)"  'git diff --ext-diff'                            feat/x   2

# Issue #1, PR B (segunda ronda, revisión de seguridad) — vías que leen
# archivos fuera de lo que git registra (saltan .gitignore) o ejecutan
# programas. Los pathspecs sobre contenido registrado (git log -p, globs)
# no alcanzan un .env ignorado y quedan como límite documentado.
run_case "diff ~/ruta (no-index implícito vía ~)"         'git diff ~/.ssh/a README.md'                    feat/x   2
run_case "diff \$HOME/ruta (no-index implícito vía \$)"   'git diff $HOME/.ssh/a README.md'                feat/x   2
run_case "show :0:.env (entrada del índice por etapa)"    'git show :0:.env'                               feat/x   2
run_case "log -L1,9:.env (ruta pegada a la opción)"       'git log -L1,9:.env'                             feat/x   2
run_case "blame --contents=.env (lee el archivo del disco)" 'git blame --contents=.env README.md'          feat/x   2
run_case "grep -f.env (patrones leídos de un archivo)"    'git grep -f.env .'                              feat/x   2
run_case "grep --untracked --no-exclude-standard"         'git grep --untracked --no-exclude-standard -e x' feat/x  2
run_case "grep -O<programa> (ejecuta un programa)"        'git grep -Ocat -e x'                            feat/x   2
run_case "cat-file --batch (rutas por stdin)"             'echo HEAD:x | git cat-file --batch'             feat/x   2
run_case "GIT_EXTERNAL_DIFF=<programa> git diff"          'GIT_EXTERNAL_DIFF=/tmp/x git diff'              feat/x   2
run_case "GIT_PAGER=<programa> git log"                   'GIT_PAGER=/tmp/x git log -1'                    feat/x   2
run_case "git config core.pager"                          'git config core.pager /tmp/x'                   feat/x   2
run_case "-c diff.external=<programa> diff"               'git -c diff.external=/tmp/x diff'               feat/x   2
# git grep y git blame aceptan prefijos únicos de opciones largas (comprobado
# con git 2.55: --op, --u, --no-exc y --cont se aceptan).
run_case "grep --op=<programa> (abreviatura de --open-files-in-pager)" 'git grep --op=cat -e x'             feat/x   2
run_case "grep --u (abreviatura de --untracked)"          'git grep --u -e x'                              feat/x   2
run_case "grep --no-exc (abreviatura de --no-exclude-standard)" 'git grep --untracked --no-exc -e x'       feat/x   2
run_case "blame --cont=.env (abreviatura de --contents)"  'git blame --cont=.env README.md'               feat/x   2

echo
echo "== Casos que deben permitirse (exit 0) =="

run_case "commit -m x en rama de trabajo"             'git commit -m x'                              feat/x 0
run_case "push -n (dry-run, no es --no-verify)"       'git push -n origin feat/x'                   feat/x 0
run_case "switch a rama de trabajo"                   'git switch feat/y'                            feat/x 0
run_case "git status"                                 'git status'                                   feat/x 0
run_case "switch a main solo (sin commit/merge)"      'git switch main'                              feat/x 0

# Segunda revisión — deben seguir permitidos tras endurecer las reglas.
run_case "commit --verbose (no es --no-verify)"                    'git commit -m x --verbose'                    feat/x 0
run_case "commit --no-verbose (opción distinta, no abreviatura)"   'git commit --no-verbose -m x'                 feat/x 0
run_case "switch -c feat/main-page (rama con 'main' en el nombre)" 'git switch -c feat/main-page'                 feat/x 0
run_case "checkout feat/x"                                          'git checkout feat/x'                          feat/x 0

# Issue #1, PR A — la regla de push ya no debe bloquear nombres de rama que
# contienen "main" ni un "gh pr create --base main" encadenado.
run_case "push -u de rama con '-main' en el nombre"                 'git push -u origin ci/4-proteccion-main'      feat/x 0
run_case "push -u de feat/5-main-page"                              'git push -u origin feat/5-main-page'          feat/x 0
run_case "push && gh pr create --base main"                         'git push -u origin feat/x && gh pr create --base main' feat/x 0
run_case "push sin refspec en rama de trabajo"                      'git push'                                     feat/x 0
run_case "push --delete de rama de trabajo"                         'git push origin --delete feat/old'            feat/x 0
run_case "-C . status (opción global sin commit/merge)"             'git -C . status'                              feat/x 0
run_case "--no-pager log -1"                                        'git --no-pager log -1'                        feat/x 0
run_case "env VAR=1 git commit en rama de trabajo"                  'env GIT_TRACE=1 git commit -m x'              feat/x 0
run_case "git config user.name (no es hooksPath)"                   'git config user.name x'                       feat/x 0

# Issue #1, PR A (segunda ronda) — no romper el uso normal.
run_case "cd . && git commit (cd dentro del proyecto)"              'cd . && git commit -m x'                      feat/x 0
run_case "push --follow-tags (no es --force)"                       'git push --follow-tags origin feat/x'         feat/x 0
run_case "pull --ff-only estando en main"                           'git pull --ff-only'                           main   0
run_case "revert en rama de trabajo"                                'git revert HEAD'                              feat/x 0

# Issue #1, PR A (cuarta ronda) — no romper el uso normal.
run_case "push -o ci.skip origin feat/x"                            'git push -o ci.skip origin feat/x'            feat/x 0
run_case "git config user.email (clave inocua)"                     'git config user.email x@example.invalid'      feat/x 0
run_case "git config --get remote.origin.url (solo lectura)"        'git config --get remote.origin.url'           feat/x 0
run_case "switch -c feat/y (sin main)"                              'git switch -c feat/y && git commit -m x'      feat/x 0

# Issue #1, PR A (quinta ronda) — no romper el uso normal.
run_case "gh pr view / checks (solo lectura)"                       'gh pr view 12 && gh pr checks 12'             feat/x 0
run_case "gh pr create --body-file"                                 'gh pr create --base main --body-file b.md'    feat/x 0
run_case "push --mo? no: push --porcelain (no es --mirror)"         'git push --porcelain origin feat/x'           feat/x 0

# Issue #1, PR B — uso normal de git diff/log/show.
run_case "git diff"                                                 'git diff'                                     feat/x 0
run_case "git diff --stat main...HEAD"                              'git diff --stat main...HEAD'                  feat/x 0
run_case "git log --oneline -5"                                     'git log --oneline -5'                         feat/x 0
run_case "git show --stat HEAD"                                     'git show --stat HEAD'                         feat/x 0
run_case "git diff -- .env.example (plantilla con valores ficticios)" 'git diff -- .env.example'                   feat/x 0
run_case "git show HEAD:docs/BITACORA.md"                           'git show HEAD:docs/BITACORA.md'               feat/x 0
run_case "git diff --no-ext-diff (desactiva, no activa)"            'git diff --no-ext-diff'                       feat/x 0
run_case "git log -L1,9:README.md"                                  'git log -L1,9:README.md'                      feat/x 0
run_case "git grep -e x (solo contenido registrado)"                'git grep -e x'                                feat/x 0
run_case "git blame README.md"                                      'git blame README.md'                          feat/x 0
run_case "git show :README.md (índice)"                             'git show :README.md'                          feat/x 0
run_case "git grep --only-matching -e x"                            'git grep --only-matching -e x'                feat/x 0
run_case "git blame --color-lines README.md"                        'git blame --color-lines README.md'            feat/x 0

echo
echo "== Falso positivo documentado y aceptado (fail-closed) =="
# La regex de -n corto no distingue el contenido de un mensaje de commit
# entre comillas de un flag real: "-n" dentro de "fix -n flag" también
# coincide con el patrón de flag corto. Se acepta este falso positivo
# porque el hook debe fallar cerrado (bloquear) ante la duda, en vez de
# arriesgarse a dejar pasar un --no-verify real. Documentado en el plan
# aprobado (issue #2) y en docs/BITACORA.md.
run_case "commit -am con '-n' dentro del mensaje (FP aceptado)" \
  'git commit -am "fix -n flag"' feat/x 2

# Segunda revisión — falso positivo D (aceptado, fail-closed): la regla de
# flag corto -n busca el patrón en todo el comando, no solo en la porción
# de "git commit". Por eso "git log -n 5" encadenado tras un commit también
# bloquea, aunque el -n pertenezca a "git log" y no sea un intento real de
# saltarse los hooks. Se acepta porque, ante la duda, el hook debe bloquear
# en vez de arriesgarse a dejar pasar un --no-verify real.
run_case "commit && log -n 5 (FP aceptado: -n es de 'git log', no de commit)" \
  'git commit -m y && git log -n 5' feat/x 2

echo
echo "Total: $COUNT casos, $FAILED fallidos."
if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
exit 0
