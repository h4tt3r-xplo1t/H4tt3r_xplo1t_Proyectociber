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
trap 'rm -rf "$NO_JQ_BIN"' EXIT

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
