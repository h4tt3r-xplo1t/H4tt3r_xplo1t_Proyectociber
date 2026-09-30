# Instrucciones del proyecto
@AGENTS.md
@docs/PROJECT_CONTEXT.md
@docs/BITACORA.md

## Pipeline DevSecOps de Ciclo Completo para una Aplicación Contenerizada de Libre Uso (específico para Claude)

## Reglas operativas para Claude Code
- Empieza cada sesión en modo plan y declara modo, issue y rama.
- Nunca trabajes en main: crea la rama `tipo/ID-descripcion` desde main actualizada.
- Commits con Conventional Commits que referencien el issue.
- No hagas push ni abras PR sin que yo lo pida explícitamente en ese mensaje.
- Si una tarea sale del alcance del issue, detente y pregunta.
- Antes de proponer un PR, invoca al subagente revisor-seguridad.
- Al cerrar cada tarea, actualiza docs/BITACORA.md con decisiones y pendientes.
- Límite de instrucciones (150k caracteres entre todos los archivos cargados): si docs/BITACORA.md supera ~20k bytes (`wc -c`), mueve sin cambios las entradas de issues cerrados a `docs/bitacora/` y enlázalas en su sección Historial. La sección Pendientes nunca se mueve. El enunciado del curso está en docs/enunciado.md y no se importa.
