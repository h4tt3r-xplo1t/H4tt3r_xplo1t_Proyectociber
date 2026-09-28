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

# run_case <descripción> <comando> <rama> <exit code esperado>
run_case() {
  local desc="$1" cmd="$2" branch="$3" expected="$4"
  local dir actual
  dir=$(setup_repo "$branch")

  jq -n --arg c "$cmd" '{tool_input:{command:$c}}' \
    | CLAUDE_PROJECT_DIR="$dir" bash "$HOOK" >/tmp/guardia_test_out.$$ 2>&1
  actual=$?

  rm -rf "$dir"
  COUNT=$((COUNT + 1))

  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (esperado exit=$expected, obtenido exit=$actual) -- cmd: $cmd"
    echo "  salida del hook: $(cat /tmp/guardia_test_out.$$)"
    FAILED=$((FAILED + 1))
  fi
  rm -f /tmp/guardia_test_out.$$
}

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
