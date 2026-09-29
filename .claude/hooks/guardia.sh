#!/bin/bash
# Guardia DevSecOps: bloquea (exit 2) acciones que rompen el flujo acordado.
# Falla cerrado: si no puede analizar la entrada, bloquea.

bloquear() { echo "Bloqueado: $1" >&2; exit 2; }

# Fallar cerrado: sin jq o con JSON inválido no hay forma de inspeccionar el comando.
command -v jq >/dev/null 2>&1 || bloquear "jq no está instalado; la guardia no puede analizar el comando."
CMD=$(jq -r '.tool_input.command // ""') || bloquear "la entrada no es JSON válido; la guardia no puede analizar el comando."

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
PROYECTO=$(realpath -m "$CLAUDE_PROJECT_DIR")
RAMA=$(git -C "$CLAUDE_PROJECT_DIR" branch --show-current 2>/dev/null)

# Interpreta un segmento de comando. Localiza el PRIMER token git (o */git)
# en cualquier posición del segmento; así los envoltorios (env, command, exec,
# time, bash -c, VAR=valor...) no lo esconden. A propósito acepta falsos
# positivos como "echo git commit" en main (fail-closed). Deja en SUB el
# subcomando, en ARGS sus argumentos y en TARGET=1 si la rama destino es
# desconocida (-C, --git-dir, --work-tree, GIT_DIR=, cd fuera del proyecto).
# Devuelve 1 si el segmento no contiene git.
parsear_segmento() {
  local -a t
  local i=0 tok
  read -ra t <<< "$1"
  SUB=""; ARGS=(); TARGET=$((CD_FUERA | VAR_GIT))
  while [ "$i" -lt "${#t[@]}" ]; do
    case "${t[i]}" in git|*/git) break ;; esac
    i=$((i + 1))
  done
  [ "$i" -lt "${#t[@]}" ] || return 1
  i=$((i + 1))
  while [ "$i" -lt "${#t[@]}" ]; do
    tok="${t[i]}"
    case "$tok" in
      -C|--git-dir|--work-tree) TARGET=1; i=$((i + 2)) ;;  # opción con valor separado
      -c) i=$((i + 2)) ;;                                  # -c clave=valor
      --git-dir=*|--work-tree=*) TARGET=1; i=$((i + 1)) ;;
      -*) i=$((i + 1)) ;;                                  # --no-pager, -p, --bare...
      *) break ;;                                          # primer token sin guion: subcomando
    esac
  done
  SUB="${t[i]:-}"
  ARGS=("${t[@]:i+1}")
  return 0
}

# Si el segmento hace cd/pushd, actualiza CD_FUERA: 1 cuando el destino cae
# fuera del proyecto o no se puede resolver ($, `, "-", sin argumento).
# Se evalúa sobre el comando crudo para ver "$VAR" antes de limpiarlo.
actualizar_cd() {
  local -a t
  local i arg base
  read -ra t <<< "$1"
  for i in "${!t[@]}"; do
    case "${t[i]}" in cd|pushd) break ;; esac
  done
  [[ "${t[i]:-}" == cd || "${t[i]:-}" == pushd ]] || return 0
  arg="${t[i+1]:-}"
  while [[ "$arg" == -[PLe@] ]]; do i=$((i + 1)); arg="${t[i+1]:-}"; done
  arg="${arg//[\"\']/}"
  case "$arg" in
    ""|-*|*[\$\`]*) CD_FUERA=1; return 0 ;;
    "~"|"~/"*) arg="$HOME${arg#\~}" ;;
    "~"*) CD_FUERA=1; return 0 ;;
  esac
  base="$PWD"
  case "$base" in "$PROYECTO"|"$PROYECTO"/*) ;; *) base="$PROYECTO" ;; esac
  [[ "$arg" == /* ]] || arg="$base/$arg"
  arg=$(realpath -m "$arg")
  case "$arg" in "$PROYECTO"|"$PROYECTO"/*) CD_FUERA=0 ;; *) CD_FUERA=1 ;; esac
}

# Reglas de push, evaluadas solo sobre los tokens del segmento "git push".
# Git acepta prefijos únicos de opciones largas: se bloquea todo prefijo de
# 4+ caracteres de una opción peligrosa (--forc, --mirr, --al...).
opcion_push_prohibida() {
  local nombre="$1" larga
  [ "${#nombre}" -ge 4 ] || return 0
  for larga in --force --force-with-lease --force-if-includes --mirror --all --prune; do
    [[ "$larga" == "$nombre"* ]] && bloquear "opción de push peligrosa ($nombre): forzado, --mirror, --all o --prune no permitidos. Usa PR."
  done
}

# Recibe: TARGET (uso de -C/--git-dir/--work-tree) y ARGS.
revisar_push() {
  local tok posicionales=0
  for tok in "${ARGS[@]}"; do
    case "$tok" in
      --*) opcion_push_prohibida "${tok%%=*}" ;;
      +*) bloquear "push con refspec '+' (forzado) no permitido. Usa PR." ;;
      main|*:main|refs/heads/main|*:refs/heads/main|*/refs/heads/main) bloquear "push a main no permitido. Usa PR." ;;
    esac
    # Flag corto que incluye f (-f, -uf...); -n solo es un dry-run y se permite.
    if [[ "$tok" =~ ^-[a-zA-Z]+$ && "$tok" == *f* ]]; then
      bloquear "push forzado (-f) no permitido. Usa PR."
    fi
    [[ "$tok" != -* ]] && posicionales=$((posicionales + 1))
  done
  # Sin refspec (solo remoto): empuja la rama actual, que no puede ser main ni desconocida.
  if [ "$posicionales" -le 1 ] && { [ "$RAMA" = "main" ] || [ -z "$RAMA" ] || [ "$TARGET" -eq 1 ]; }; then
    bloquear "push sin refspec desde main o con rama desconocida no permitido. Usa PR."
  fi
}

# core.hooksPath (con -c o git config) redirige los hooks a otro directorio.
if echo "$LIMPIO" | grep -qi 'core\.hookspath'; then
  bloquear "no se permite modificar core.hooksPath (evita los hooks de git)."
fi

# Revisa cada segmento (separados por ; && || | &) por separado.
NORM=""; CD_FUERA=0; VAR_GIT=0
# GIT_DIR=/GIT_WORK_TREE= en cualquier parte: rama destino desconocida.
echo "$CMD" | grep -qE '(^|[^A-Za-z0-9_])GIT_(DIR|WORK_TREE)=' && VAR_GIT=1
# Ambas listas se dividen igual: quitar comillas o paréntesis no crea ni borra separadores.
mapfile -t SEGS_CRUDOS < <(printf '%s\n' "$CMD" | sed 's/[;&|]/\n/g')
mapfile -t SEGS_LIMPIOS < <(printf '%s\n' "$LIMPIO" | sed 's/[;&|]/\n/g')
for idx in "${!SEGS_LIMPIOS[@]}"; do
  actualizar_cd "${SEGS_CRUDOS[idx]}"
  parsear_segmento "${SEGS_LIMPIOS[idx]}" || continue
  NORM="$NORM git $SUB ${ARGS[*]} ;"
  case "$SUB" in
    commit|merge|cherry-pick|revert|am)
      if [ "$RAMA" = "main" ]; then
        bloquear "estás en main. Crea una rama tipo/ID-descripcion."
      elif [ -z "$RAMA" ]; then
        bloquear "no hay rama actual (HEAD separado o fuera de un repositorio)."
      elif [ "$TARGET" -eq 1 ]; then
        bloquear "commit/merge con -C, --git-dir o --work-tree: la rama destino es desconocida."
      fi ;;
    push) revisar_push ;;
  esac
done

# Reglas sobre el comando completo (NORM ya no lleva envoltorios ni opciones globales).
if echo "$LIMPIO" | grep -qE -- '--no-ve?r?i?f?y?([^a-z-]|$)'; then
  bloquear "no se permite saltarse los hooks de git (--no-verify), incluidas sus abreviaturas (--no-verif, --no-veri, --no-ver, --no-ve, --no-v)."
fi
if echo "$NORM" | grep -qE '(^|[ ;])git commit' && echo "$LIMPIO" | grep -qE '(^|[[:space:]])-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
  bloquear "-n equivale a --no-verify; no se permite saltarse los hooks."
fi
if echo "$NORM" | grep -qE 'git (switch|checkout)[^;]* main( |;|$)' && echo "$NORM" | grep -qE 'git (commit|merge) '; then
  bloquear "no combines el cambio/creación de main (switch, checkout, -c, -B, --create) con commit o merge."
fi
exit 0
