#!/bin/bash
# Guardia DevSecOps: bloquea (exit 2) acciones que rompen el flujo acordado.
CMD=$(jq -r '.tool_input.command // ""')
# Normaliza espacios repetidos y tabuladores a un solo espacio para que las
# reglas basadas en coincidencia literal no se evadan con "git  switch  main"
# o separadores con tabulador.
CMD=$(printf '%s' "$CMD" | tr -s '[:space:]' ' ')
RAMA=$(git -C "$CLAUDE_PROJECT_DIR" branch --show-current 2>/dev/null)

if echo "$CMD" | grep -qE -- '--no-ve?r?i?f?y?([^a-z-]|$)'; then
  echo "Bloqueado: no se permite saltarse los hooks de git (--no-verify), incluidas sus abreviaturas (--no-verif, --no-veri, --no-ver, --no-ve, --no-v)." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git commit' && echo "$CMD" | grep -qE '(^|[[:space:]])-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
  echo "Bloqueado: -n equivale a --no-verify; no se permite saltarse los hooks." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git (commit|merge)( |$)' && [ "$RAMA" = "main" ]; then
  echo "Bloqueado: estás en main. Crea una rama tipo/ID-descripcion." >&2; exit 2
fi
if echo "$CMD" | grep -qE 'git (switch|checkout)[^;&|]* main([ ;&|]|$)' && echo "$CMD" | grep -qE '(^|[;&| ])git (commit|merge)( |$)'; then
  echo "Bloqueado: no combines el cambio/creación de main (switch, checkout, -c, -B, --create) con commit o merge." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git push' && echo "$CMD" | grep -qE '(\bmain\b|--force|-f\b)'; then
  echo "Bloqueado: push a main o forzado no permitido. Usa PR." >&2; exit 2
fi
exit 0
