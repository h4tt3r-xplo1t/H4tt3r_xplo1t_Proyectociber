#!/bin/bash
# Guardia DevSecOps: bloquea (exit 2) acciones que rompen el flujo acordado.
# Falla cerrado: si no puede analizar la entrada o el entorno está degradado, bloquea.
#
# Límite aceptado y documentado: no se resuelve la expansión del shell
# (${IFS}, {git,commit}, $'\x67it', variables que contienen "git", alias,
# funciones, eval). Cubrirla exigiría un intérprete de shell completo.

bloquear() { echo "Bloqueado: $1" >&2; exit 2; }

# Entorno degradado: sin bash >= 4 o sin las herramientas que usan las reglas,
# la guardia no puede evaluar nada con garantías.
[ "${BASH_VERSINFO[0]:-0}" -ge 4 ] || bloquear "se requiere bash >= 4; la guardia no puede analizar el comando."
for herramienta in jq realpath sed grep tr; do
  command -v "$herramienta" >/dev/null 2>&1 || bloquear "$herramienta no está instalado; la guardia no puede analizar el comando."
done
[ -n "${CLAUDE_PROJECT_DIR:-}" ] || bloquear "CLAUDE_PROJECT_DIR está vacío; no se conoce el proyecto."
PROYECTO=$(realpath -m "$CLAUDE_PROJECT_DIR")
[ -n "$PROYECTO" ] || bloquear "no se pudo resolver CLAUDE_PROJECT_DIR."

# Fallar cerrado: con JSON inválido no hay forma de inspeccionar el comando.
ENTRADA=$(cat)
CMD=$(printf '%s' "$ENTRADA" | jq -r '.tool_input.command // ""') || bloquear "la entrada no es JSON válido; la guardia no puede analizar el comando."
CWD=$(printf '%s' "$ENTRADA" | jq -r '.cwd // ""') || bloquear "la entrada no es JSON válido; la guardia no puede analizar el comando."

# Normaliza espacios repetidos y tabuladores a un solo espacio para que las
# reglas basadas en coincidencia literal no se evadan con "git  switch  main"
# o separadores con tabulador. Antes, cada salto de línea pasa a ser ";":
# en el shell separa comandos, y fundirlo en un espacio escondería el
# segundo git dentro del segmento del primero.
CMD=$(printf '%s' "$CMD" | tr '\n' ';' | tr -s '[:space:]' ' ')
# Copia "limpia" para las reglas: sin barras invertidas ni comillas ("git",
# g\it, g''it pasan a ser git) y con ( ) { } $ ` ! convertidos en espacios
# para que subshells, grupos y sustituciones no escondan git.
LIMPIO=$(printf '%s' "$CMD" | tr -d '\\"'"'"'' | tr '(){}$`!' '       ')
RAMA=$(git -C "$CLAUDE_PROJECT_DIR" branch --show-current 2>/dev/null)

dentro_del_proyecto() { case "$1" in "$PROYECTO"|"$PROYECTO"/*) return 0 ;; *) return 1 ;; esac; }

# Estado inicial del directorio de trabajo. Claude Code envía "cwd"; si está
# fuera del proyecto, la rama destino es desconocida (igual que un cd fuera).
# Sin cwd (entrada antigua) se usa el comportamiento anterior: $PWD si está
# dentro del proyecto, y si no el propio proyecto.
CD_FUERA=0
if [ -n "$CWD" ]; then
  BASE=$(realpath -m "$CWD")
  dentro_del_proyecto "$BASE" || CD_FUERA=1
else
  BASE="$PWD"
  dentro_del_proyecto "$BASE" || BASE="$PROYECTO"
fi

# Clave de configuración de git que puede cambiar hooks, destinos de push,
# alias o comandos externos (comparación sin distinguir mayúsculas).
clave_peligrosa() {
  case "${1,,}" in
    remote.*.push|remote.*.pushurl|alias.*|include.*|includeif.*|push.*|branch.*.merge|branch.*.pushremote|core.hookspath|core.sshcommand|core.fsmonitor) return 0 ;;
  esac
  return 1
}

# Interpreta la invocación de git que empieza en TOK[$1]: deja en SUB el
# subcomando, en ARGS sus argumentos y en TARGET=1 si la rama destino es
# desconocida (-C, --git-dir, --work-tree, GIT_DIR=, cd o cwd fuera del
# proyecto, opción global desconocida). TOK es la lista global de tokens
# del segmento.
parsear_git() {
  local i=$(($1 + 1)) tok
  SUB=""; ARGS=(); TARGET=$((CD_FUERA | VAR_GIT))
  while [ "$i" -lt "${#TOK[@]}" ]; do
    tok="${TOK[i]}"
    case "$tok" in
      -C|--git-dir|--work-tree) TARGET=1; i=$((i + 2)) ;;  # opción con valor separado
      -c) clave_peligrosa "${TOK[i+1]%%=*}" && bloquear "configuración peligrosa por -c (${TOK[i+1]%%=*})."
          i=$((i + 2)) ;;
      --config-env) clave_peligrosa "${TOK[i+1]%%=*}" && bloquear "configuración peligrosa por --config-env (${TOK[i+1]%%=*})."
          i=$((i + 2)) ;;
      --namespace|--super-prefix) i=$((i + 2)) ;;          # opciones con valor separado
      --git-dir=*|--work-tree=*) TARGET=1; i=$((i + 1)) ;;
      --config-env=*) tok="${tok#--config-env=}"
          clave_peligrosa "${tok%%=*}" && bloquear "configuración peligrosa por --config-env (${tok%%=*})."
          i=$((i + 1)) ;;
      --namespace=*|--super-prefix=*) i=$((i + 1)) ;;
      # Opciones globales conocidas sin valor.
      --no-pager|-p|--paginate|-P|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-advice|--exec-path|--html-path|--man-path|--info-path|--version|--help|--list-cmds=*|--exec-path=*) i=$((i + 1)) ;;
      -*) TARGET=1; i=$((i + 1)) ;;                        # desconocida: fail-closed
      *) break ;;                                          # primer token sin guion: subcomando
    esac
  done
  SUB="${TOK[i]:-}"
  ARGS=("${TOK[@]:i+1}")
}

# Si el segmento hace cd/pushd, actualiza CD_FUERA: 1 cuando el destino cae
# fuera del proyecto o no se puede resolver ($, `, "-", sin argumento).
# Se evalúa sobre el comando crudo para ver "$VAR" antes de limpiarlo.
actualizar_cd() {
  local -a t
  local i arg
  read -ra t <<< "$1"
  for i in "${!t[@]}"; do
    case "${t[i]}" in cd|pushd) break ;; esac
  done
  [[ "${t[i]:-}" == cd || "${t[i]:-}" == pushd ]] || return 0
  arg="${t[i+1]:-}"
  while [[ "$arg" == -[PLe@] ]]; do i=$((i + 1)); arg="${t[i+1]:-}"; done
  arg="${arg//[\"\']/}"
  case "$arg" in
    ""|-*|*[\$\`]*) CD_FUERA=1; BASE=""; return 0 ;;
    "~"|"~/"*) arg="$HOME${arg#\~}" ;;
    "~"*) CD_FUERA=1; BASE=""; return 0 ;;
  esac
  if [[ "$arg" != /* ]]; then
    [ -n "$BASE" ] || { CD_FUERA=1; return 0; }   # base desconocida
    arg="$BASE/$arg"
  fi
  BASE=$(realpath -m "$arg")
  if dentro_del_proyecto "$BASE"; then CD_FUERA=0; else CD_FUERA=1; fi
}

# Git acepta prefijos únicos de opciones largas: se bloquea todo prefijo de
# 4+ caracteres de una opción de push peligrosa (--forc, --mirr, --al...).
opcion_push_prohibida() {
  local nombre="$1" larga
  [ "${#nombre}" -ge 4 ] || return 0
  for larga in --force --force-with-lease --force-if-includes --mirror --all --prune; do
    [[ "$larga" == "$nombre"* ]] && bloquear "opción de push peligrosa ($nombre): forzado, --mirror, --all o --prune no permitidos. Usa PR."
  done
}

# Reglas de push, evaluadas solo sobre los tokens del segmento "git push".
# Recibe: TARGET y ARGS.
revisar_push() {
  local tok destino posicionales=0 salta=0
  for tok in "${ARGS[@]}"; do
    # Valor separado de una opción de push (-o x, --repo x...): no es refspec.
    if [ "$salta" -eq 1 ]; then salta=0; continue; fi
    case "$tok" in
      -o|--push-option|--repo|--receive-pack|--exec) salta=1; continue ;;
      --*) opcion_push_prohibida "${tok%%=*}"; continue ;;
      +*) bloquear "push con refspec '+' (forzado) no permitido. Usa PR." ;;
    esac
    # Flag corto que incluye f (-f, -uf...); -n solo es un dry-run y se permite.
    if [[ "$tok" =~ ^-[a-zA-Z]+$ ]]; then
      [[ "$tok" == *f* ]] && bloquear "push forzado (-f) no permitido. Usa PR."
      continue
    fi
    posicionales=$((posicionales + 1))
    [[ "$tok" == *"*"* ]] && bloquear "push con refspec comodín (*) no permitido. Usa PR."
    [ "$tok" = ":" ] && bloquear "push con refspec ':' (todas las ramas coincidentes) no permitido. Usa PR."
    # Destino = parte tras el último ':' (main, heads/main, refs/heads/main...).
    destino="${tok##*:}"
    case "$destino" in main|*/main) bloquear "push a main no permitido. Usa PR." ;; esac
  done
  # Sin refspec (solo remoto): empuja la rama actual, que no puede ser main ni desconocida.
  if [ "$posicionales" -le 1 ] && { [ "$RAMA" = "main" ] || [ -z "$RAMA" ] || [ "$TARGET" -eq 1 ]; }; then
    bloquear "push sin refspec desde main o con rama desconocida no permitido. Usa PR."
  fi
}

# "git config" en forma de escritura con una clave peligrosa. Las formas de
# solo lectura (--get, --list, -l, --get-regexp, --show-origin) se permiten.
revisar_config() {
  local tok
  for tok in "${ARGS[@]}"; do
    case "$tok" in
      --get|--get-all|--get-regexp|--get-urlmatch|--list|-l|--show-origin|--show-scope) return 0 ;;
    esac
  done
  for tok in "${ARGS[@]}"; do
    [[ "$tok" == -* ]] || { clave_peligrosa "$tok" && bloquear "git config con clave peligrosa ($tok)."; }
  done
}

# Aplica las reglas a una invocación de git ya interpretada (SUB, ARGS, TARGET).
revisar_invocacion() {
  case "$SUB" in
    commit|merge|cherry-pick|revert|am)
      if [ "$RAMA" = "main" ]; then
        bloquear "estás en main. Crea una rama tipo/ID-descripcion."
      elif [ -z "$RAMA" ]; then
        bloquear "no hay rama actual (HEAD separado o fuera de un repositorio)."
      elif [ "$TARGET" -eq 1 ]; then
        bloquear "commit/merge con destino desconocido (-C, --git-dir, --work-tree, cd/cwd fuera del proyecto...)."
      fi ;;
    push) revisar_push ;;
    config) revisar_config ;;
  esac
}

# core.hooksPath (con -c o git config) redirige los hooks a otro directorio.
if echo "$LIMPIO" | grep -qi 'core\.hookspath'; then
  bloquear "no se permite modificar core.hooksPath (evita los hooks de git)."
fi
# Variables de entorno que cambian la configuración de git o desactivan hooks de pre-commit.
if echo "$LIMPIO" | grep -qE 'GIT_CONFIG_(COUNT|KEY_|VALUE_|PARAMETERS|GLOBAL=|SYSTEM=)'; then
  bloquear "no se permite alterar la configuración de git por variables de entorno (GIT_CONFIG_*)."
fi
if echo "$LIMPIO" | grep -qE '(^|[^A-Za-z0-9_])(SKIP|PRE_COMMIT_ALLOW_NO_CONFIG)='; then
  bloquear "no se permite saltarse hooks de pre-commit con SKIP= o PRE_COMMIT_ALLOW_NO_CONFIG=."
fi

# Revisa cada segmento (separados por ; && || | &) por separado.
NORM=""; VAR_GIT=0
# GIT_DIR=/GIT_WORK_TREE= en cualquier parte: rama destino desconocida.
echo "$LIMPIO" | grep -qE '(^|[^A-Za-z0-9_])GIT_(DIR|WORK_TREE)=' && VAR_GIT=1
# Ambas listas se dividen igual: quitar comillas o paréntesis no crea ni borra separadores.
mapfile -t SEGS_CRUDOS < <(printf '%s\n' "$CMD" | sed 's/[;&|]/\n/g')
mapfile -t SEGS_LIMPIOS < <(printf '%s\n' "$LIMPIO" | sed 's/[;&|]/\n/g')
for idx in "${!SEGS_LIMPIOS[@]}"; do
  actualizar_cd "${SEGS_CRUDOS[idx]}"
  read -ra TOK <<< "${SEGS_LIMPIOS[idx]}"
  # Cada token git (o */git) del segmento es una invocación candidata, no solo
  # el primero ("sudo -u git git commit"). Acepta a propósito falsos positivos
  # como "echo git commit" en main (fail-closed).
  for j in "${!TOK[@]}"; do
    case "${TOK[j]}" in git|*/git) ;; *) continue ;; esac
    parsear_git "$j"
    NORM="$NORM git $SUB ${ARGS[*]} ;"
    revisar_invocacion
  done
done

# Reglas sobre el comando completo (NORM ya no lleva envoltorios ni opciones globales).
if echo "$LIMPIO" | grep -qE -- '--no-ve?r?i?f?y?([^a-z-]|$)'; then
  bloquear "no se permite saltarse los hooks de git (--no-verify), incluidas sus abreviaturas (--no-verif, --no-veri, --no-ver, --no-ve, --no-v)."
fi
if echo "$NORM" | grep -qE '(^|[ ;])git commit' && echo "$LIMPIO" | grep -qE '(^|[[:space:]])-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
  bloquear "-n equivale a --no-verify; no se permite saltarse los hooks."
fi
# Cambiar a main (switch/checkout, o symbolic-ref de HEAD) y crear commits en el mismo comando.
if echo "$NORM" | grep -qE 'git (switch|checkout)[^;]* main( |;|$)|git symbolic-ref[^;]* (refs/)?heads/main( |;|$)' \
  && echo "$NORM" | grep -qE 'git (commit|merge|cherry-pick|revert|am) '; then
  bloquear "no combines el cambio/creación de main (switch, checkout, symbolic-ref) con commit, merge, cherry-pick, revert o am."
fi
exit 0
