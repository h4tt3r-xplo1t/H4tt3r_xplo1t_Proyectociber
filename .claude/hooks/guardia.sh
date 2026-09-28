#!/bin/bash
# Guardia DevSecOps: bloquea (exit 2) acciones que rompen el flujo acordado.
CMD=$(jq -r '.tool_input.command // ""')
RAMA=$(git -C "$CLAUDE_PROJECT_DIR" branch --show-current 2>/dev/null)

if echo "$CMD" | grep -qE -- '--no-verify'; then
  echo "Bloqueado: no se permite saltarse los hooks de git (--no-verify)." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git commit' && echo "$CMD" | grep -qE '(^|[[:space:]])-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
  echo "Bloqueado: -n equivale a --no-verify; no se permite saltarse los hooks." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git (commit|merge)( |$)' && [ "$RAMA" = "main" ]; then
  echo "Bloqueado: estás en main. Crea una rama tipo/ID-descripcion." >&2; exit 2
fi
if echo "$CMD" | grep -qE 'git (switch|checkout) main([[:space:];&|]|$)' && echo "$CMD" | grep -qE '(^|[;&| ])git (commit|merge)( |$)'; then
  echo "Bloqueado: no combines el cambio a main con commit o merge." >&2; exit 2
fi
if echo "$CMD" | grep -qE '(^|[;&| ])git push' && echo "$CMD" | grep -qE '(\bmain\b|--force|-f\b)'; then
  echo "Bloqueado: push a main o forzado no permitido. Usa PR." >&2; exit 2
fi
exit 0
