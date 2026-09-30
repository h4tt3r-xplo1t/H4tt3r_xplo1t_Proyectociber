# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## Historial

Las entradas de issues cerrados se mueven a `docs/bitacora/` para no superar el límite de instrucciones de Claude Code (issue #23). No se cargan en cada sesión; léelas cuando haga falta el detalle.

- [2026-09-27 a 2026-09-28](bitacora/2026-09-27_28.md): arranque, `guardia.sh` (issue #1, PR #3), protección de `main` (issue #4) y pruebas reales en CI (issue #9).
- [2026-09-29](bitacora/2026-09-29.md): E0 y elección de la aplicación (issue #15), modelo de amenazas (issue #18) y ADR 0004 (issue #20).
- Decisiones deliberadas que solo están en ese historial, y que no deben «arreglarse» sin revisarlo: `.env.example` no se puede leer con la herramienta Read (una regla `allow` no puede exceptuar una `deny`; issue #1, PR #12) y el detalle de cobertura y rondas TDD de `guardia.sh` (los límites y falsos positivos aceptados también están en el ADR 0002).

## 2026-09-30 · Issue #23: contexto de instrucciones por debajo de 150k

Rama `docs/23-contexto-instrucciones`.

- **Problema.** Claude Code avisó al iniciar: los 5 archivos de instrucciones sumaban 170 380 bytes según `wc -c` (el aviso hablaba de 166,3k caracteres: las tildes ocupan 2 bytes), por encima del límite de 150 000. Los más grandes: `~/.claude/CLAUDE.md` (69 479), `docs/PROJECT_CONTEXT.md` (43 576) y esta bitácora (43 556).
- **Decisión: mover, no borrar.** El enunciado del curso (unos 28 800 bytes dentro de `PROJECT_CONTEXT.md`) pasa a `docs/enunciado.md`, y las entradas del 27 y 28 de septiembre, a `docs/bitacora/2026-09-27_28.md`. Ninguno de los dos se importa, así que se leen bajo demanda. `PROJECT_CONTEXT.md` conserva la ficha con un enlace al enunciado; esta bitácora conserva las entradas recientes, los pendientes y un índice de historial.
- **Sin cambios en `~/.claude/CLAUDE.md`.** Es global y lo gestiona gentle-ai: una sincronización sobrescribiría cualquier recorte.
- **Regla de rotación** añadida a `CLAUDE.md`: si la bitácora supera unos 20 000 bytes (`wc -c`), las entradas de issues cerrados se mueven a `docs/bitacora/`; los pendientes nunca se mueven.
- **Revisión de seguridad (revisor-seguridad):** listo para PR, sin críticos, altos ni medios. Se corrigieron sus 3 observaciones bajas: las cifras eran bytes de `wc -c` y no caracteres, el tamaño del enunciado estaba mal redondeado, y la decisión de `.env.example` solo quedaba en el historial (ahora el índice de Historial la señala).
- **Verificación.** Tras el cambio, los archivos cargados suman 115 109 bytes (`wc -c`), algo menos en caracteres. Al reconstruir cada archivo original con el texto movido, `diff` contra `main` no muestra diferencias. Las referencias a los dos archivos siguen siendo válidas: no cambian de nombre y ningún enlace con ancla apuntaba a las secciones movidas.

## 2026-09-30 · Issue #25: E2, esqueleto del gateway

Rama `feat/25-esqueleto-gateway`. Primer código de la aplicación: `services/gateway/` con `GET /healthz`.

- **Gestor de dependencias: `uv`** con `uv.lock`, que guarda el hash de cada paquete; `uv sync --locked` falla si el lockfile no coincide con `pyproject.toml`. El proyecto no se construye como paquete (`package = false`): no necesita un backend de construcción, una dependencia menos.
- **Versiones verificadas (2026-09-30)** con `gh api` sobre las publicaciones de GitHub; los datos de PyPI vienen de un resumen automático (segunda mano): CPython 3.14.7, uv 0.12.21, fastapi 0.142.2, pytest 9.1.1, ruff 0.16.9 (MIT) y httpx 0.28.1 (BSD-3, sin publicaciones desde 2024-12: solo se usa en pruebas).
- **CI sin acción de terceros para `uv`:** se descarga el binario oficial y se verifica su sha256 (el digest de GitHub coincide con el `.sha256` publicado), igual que gitleaks y actionlint. Se descartó `astral-sh/setup-uv`.
- **Ruff con las reglas `S` (flake8-bandit).** La única excepción es S101 en `tests/**`: pytest comprueba con `assert`, y la regla va dirigida al código de producción, donde `python -O` elimina los `assert`.
- **TDD:** RED observado (`ModuleNotFoundError: gateway.main`) y luego GREEN (1 prueba pasa).
- **Vulnerabilidades:** `uv audit --locked` no encontró vulnerabilidades conocidas en 22 paquetes. El comando es experimental: evidencia PARCIAL hasta que E4 añada SCA en CI.
- **NO VERIFICADO:** el soporte de Dependabot para `uv` solo consta en la referencia de opciones de GitHub, no en la página de ecosistemas; se confirmará cuando Dependabot se ejecute en el repositorio.
- **`httpx2`:** Starlette 1.7 recomienda `httpx2` para `TestClient`. Es de la organización `pydantic` (BSD-3, v2.13.1). El cambio quedó sin hacer porque el permiso automático bloqueó añadir el paquete: lo decide la persona.
- **Revisiones:** `revisor-seguridad`, listo para PR sin críticos, altos ni medios; la revisión de Gentle AI (4 lentes), aprobada sin bloqueantes. Se corrigieron los hallazgos bajos: `uv` va a un directorio propio del PATH (no a todo `RUNNER_TEMP`), `curl` reintenta, las reglas `allow` son exactas y sin comodín (con comodín, `pytest` aceptaba argumentos como `-p`), y el intérprete queda fijado en `.python-version` (3.14.7; en CI lo descarga `uv`).

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25).
- [ ] Verificar las versiones del resto del stack (React, workers, PostgreSQL, RabbitMQ, Vault) antes de fijarlas; las del `gateway` se verificaron en el issue #25.
- [ ] Decidir si se cambia `httpx` por `httpx2` en las pruebas del `gateway` (Starlette 1.7 marca `httpx` como obsoleto en `TestClient`; issue #25).
- [ ] Marcar el job `gateway` como check obligatorio en el ruleset de `main` (operación remota; issue #25).
- [ ] **E3/E6:** desactivar `/docs`, `/redoc` y `/openapi.json` del `gateway` fuera de desarrollo antes de añadir rutas de autenticación (hallazgo de la revisión del #25).
- [ ] Revisar periódicamente las versiones de `uv`, gitleaks y actionlint fijadas por sha256 en CI: Dependabot no las actualiza (hallazgo del #25).
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [ ] **E3:** implementar el MFA con TOTP, la recuperación asistida y el arranque del primer administrador (ADR 0004, decisiones 8, 10 y 11), con sus pruebas. Las amenazas 43 a 47 ya están en el modelo.
- [ ] **E3:** implementar la renovación de sesión de un solo vuelo en el frontend.
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).

### E5: plataforma, red y cifrado
- [ ] ADR de cifrado dentro del clúster (TLS/mTLS para Vault, PostgreSQL y RabbitMQ), antes de E5.
- [ ] Decidir el mecanismo de cifrado del secreto TOTP (transit de Vault o cifrado de aplicación), junto con el ADR de red y criptografía (antes de E5).

### E4/E7: CI/CD y cadena de suministro
- [ ] Modelar la cadena de suministro de CI/CD (E4/E7).
- [ ] **E7:** referenciar las imágenes por digest, no solo por `vX.Y.Z` y `latest` (hallazgo B4 del #15).

### E8: operación
- [ ] **E8:** respaldo y restauración probados de PostgreSQL y Vault (declarado en `docs/threat-model.md`).

### Gobierno del repositorio
- [ ] CODEOWNERS para rutas sensibles (`.github/**`, `.claude/**`, `tests/**`, `docs/adr/**`), útil cuando haya un segundo revisor (mitigación de M1, ADR 0001).

### Opciones futuras
- [ ] Recuperación de cuenta por correo: opción futura con ADR propio (requeriría egress).

### Cierre del proyecto
- [ ] Traslado a una rama del repositorio del curso: última tarea del proyecto (decidido el 2026-09-29).

### Hechos
- [x] **E0 (issue #15, PR #16 y #17):** ficha, ADR 0003 y propuesta.
- [x] Revisión manual de los términos de uso de RCN, Semana, Caracol, Blu Radio y Citytv (persona, 2026-09-29): ninguno prohíbe el uso informativo con enlace. Repetir antes de la entrega final.
- [x] **E1:** contenido de las fuentes externas como entrada no confiable (XSS, XXE, SSRF) y concentración de funciones en el gateway, modelados en el issue #18 (amenazas 2, 5, 20 y 21). Los controles siguen sin verificar hasta que haya código y pruebas (E3).
- [x] Nivel objetivo de OWASP ASVS: 5.0.0, L1 general y L2 en V3.3/V3.5, V6, V7, V8, V9 y V16 (16.2.1, 16.2.2, 16.2.5, 16.3.1, 16.3.2) (ADR 0004, issue #20).
- [x] Imágenes rotas referenciadas en `docs/PROJECT_CONTEXT.md` (`Logo.png`, `Arquitectura_IDENTIX.png`), restauradas en `f834b9d`.
- [x] Contacto en SECURITY.md.
- [x] Prueba del kit dentro de Claude Code: hook, subagente, permisos y archivos de memoria verificados (`/hooks`, `/agents`, `/context`).
- [x] Issue #1: `guardia.sh` falla cerrado, lectura de secretos con git, permisos y pre-commit por SHA (PR #11 y #12).
- [x] Issue #4: ruleset como código, `PUT` sobre `protege`, merge commit y rebase desactivados, bloqueo verificado (PR #5, #6 y #8).
- [x] Issue #9 (M2): el job `pruebas` ejecuta las pruebas reales (PR #10).
- [x] `delete_branch_on_merge` activado.
- [x] Quitar el scope `workflow` del token de `gh` (hallazgo B1 del PR #5).
- [x] Contrastar los sha256 de gitleaks y actionlint con los `checksums.txt` oficiales (hallazgo I1 del PR #5).
- [x] **E1 (issue #18, PR #19):** DFD de nivel 0 y 1 en Threat Dragon, 42 amenazas iniciales, PNG exportados y revisión de seguridad.
- [x] **ADR 0004 (issue #20, PR #21):** autenticación y autorización; modelo ampliado a 47 amenazas.
