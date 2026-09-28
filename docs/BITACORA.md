# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## 2026-09-27 · Arranque
- Prompt maestro v4 adoptado (AGENTS.md): trabajo en capas, modos por permisos, fases E0–E9, flujo GitHub.
- Configuración de Claude Code: modo plan por defecto, permisos allow/ask/deny, hook de guardia, subagente revisor-seguridad, comando /tarea.
- Referencias vigentes (verificar en cada uso): OWASP ASVS 5.0, OWASP Top 10:2025, NIST SSDF 1.1 (1.2 en borrador), SLSA v1.2, CycloneDX 1.7.x.

## Pendientes
- [ ] Probar el kit dentro de Claude Code (/memory, /permissions, /hooks, /agents; commit en main debe bloquearse).
- [ ] Fase E0: completar docs/PROJECT_CONTEXT.md.
- [x] Contacto en SECURITY.md.
- [ ] Confirmar política institucional sobre dónde alojar el repositorio.
- [ ] Elegir lenguaje y stack; añadir sus comandos de prueba/lint a .claude/settings.json.
