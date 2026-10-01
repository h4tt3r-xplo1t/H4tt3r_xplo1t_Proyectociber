# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## Historial

Las entradas de issues cerrados se mueven a `docs/bitacora/` para no superar el límite de instrucciones de Claude Code (issue #23). No se cargan en cada sesión; léelas cuando haga falta el detalle.

- [2026-09-27 a 2026-09-28](bitacora/2026-09-27_28.md): arranque, `guardia.sh` (issue #1, PR #3), protección de `main` (issue #4) y pruebas reales en CI (issue #9).
- Decisiones deliberadas que solo están en ese historial, y que no deben «arreglarse» sin revisarlo: `.env.example` no se puede leer con la herramienta Read (una regla `allow` no puede exceptuar una `deny`; issue #1, PR #12) y el detalle de cobertura y rondas TDD de `guardia.sh` (los límites y falsos positivos aceptados también están en el ADR 0002).
- [2026-09-29](bitacora/2026-09-29.md): E0 y elección de la aplicación (issue #15), modelo de amenazas (issue #18) y ADR 0004 (issue #20).

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

- **Cierre:** PR #26 fusionado con squash como `da5a9e7`; issue #25 cerrado. El push lo hizo la persona por SSH, porque el token de `gh` no tiene el scope `workflow` (quitado a propósito, B1 del PR #5); así no hubo que ampliarlo.

## 2026-09-30 · Issue #27: mantenimiento del gateway

Rama `chore/27-mantenimiento-gateway`. Cierra los pendientes del #25.

- **Check obligatorio:** `.github/rulesets/main.json` exige `gateway` además de `secretos`, `workflows` y `pruebas`; la prueba del ruleset falló primero y luego pasó. Aplicarlo en GitHub es una operación remota tras la fusión. El ADR 0001 enumera los tres checks originales: no se edita (fuera de alcance); el JSON del ruleset es la fuente de verdad.
- **Documentación de la API desactivada por defecto:** `/docs`, `/redoc` y `/openapi.json` responden 404 salvo que `GATEWAY_DOCS_ENABLED` valga exactamente `true` (solo desarrollo). `create_app()` construye la aplicación; pruebas de ambos casos (22 en total tras la revisión).
- **`httpx2` en lugar de `httpx`:** verificado en PyPI (2.13.1, BSD-3-Clause, mantenedor Pydantic Services Inc., enlaza a `pydantic/httpx2`, sin vulnerabilidades registradas). Trae `httpcore2` (mismo repositorio) y `truststore` 0.10.4 (MIT, `sethmlarson/truststore`, activo). El aviso de obsoleto desaparece; `uv audit`: 23 paquetes sin vulnerabilidades conocidas.
- **Dependencia condicional `httpx2-jsfetch` 1.0** (en `uv.lock`, solo con `sys_platform == 'emscripten'`): transporte de `httpx2` para Pyodide; BSD-3-Clause, autor Hood Chatham, sin vulnerabilidades en PyPI. PyPI no publica su repositorio: verificación PARCIAL. No se instala en Linux ni en CI.
- **Revisiones:** `revisor-seguridad`, listo para PR sin críticos, altos ni medios; revisión de Gentle AI (4 lentes) aprobada. Corregidos: la prueba de valores no exactos cubre las tres rutas (22 pruebas) y un comentario aclara que la variable se lee al importar (cambiarla exige reiniciar).

- **Cierre:** PR #28 fusionado con squash como `8ea3b1b`; issue #27 cerrado. Con autorización de la persona, el ruleset se aplicó con `gh api -X PUT` sobre `protege` (id 24097824): exige `secretos`, `workflows`, `pruebas` y `gateway` (app 15368). La única diferencia entre la regla anterior y la nueva es `gateway`; los campos `require_extra_approval_for_unattributed_changes` y `required_reviewers` los añade GitHub por defecto y ya estaban.

## 2026-09-30 · Issue #29: E3, registro de usuarios (autenticación A1)

Rama `feat/29-registro-usuarios`. Primera parte de la autenticación del ADR 0004; el inicio de sesión y las sesiones van en A2.

- **Decisiones de la persona:** SQLAlchemy 2 con Alembic (síncrono, psycopg 3); PostgreSQL con Docker Compose en local y un contenedor de servicio en CI, ambos con `postgres:18.6-alpine` fijado por digest (`sha256:77f5851…a1873`, igual en la API de Docker Hub y en el registro).
- **Dependencias verificadas (2026-09-30):** SQLAlchemy 2.1.1 y Alembic 1.20.0 (MIT), psycopg 3.3.6 con `binary` (LGPL-3.0-only: se usa como biblioteca importada, compatible con distribuir bajo Apache-2.0), argon2-cffi 25.1.0 (MIT). `uv audit`: 34 paquetes sin vulnerabilidades conocidas.
- **Registro:** `POST /api/auth/register` con nombre de usuario (3 a 32, `[a-z0-9_.-]`) y sin correo (minimización de datos; recuperación asistida, decisión 10). Contraseña de 15 a 128 caracteres, cualquier carácter, sin reglas de composición; Argon2id con m=19456, t=2, p=1. Responde 201 con `id`, `username` y `role`; 409 genérico si el nombre existe (se apoya en la restricción `UNIQUE`, sin carrera).
- **Fuga evitada:** el manejador 422 por defecto de FastAPI devuelve el valor rechazado, incluida la contraseña; se comprobó con las pruebas y se sustituyó por uno que solo dice qué campo falló y por qué.
- **Enumeración de usuarios:** el 409 revela si un nombre existe; es inherente a un alta abierta. Se mitiga con el límite por IP del Ingress (E5).
- **Sin valores por defecto:** la URL de la base de datos sale solo de `GATEWAY_DATABASE_URL`; sin ella, las rutas de datos fallan de forma explícita. En CI se usan credenciales desechables y marcadas como tales (base efímera del runner).
- **TDD:** RED de migraciones (`CommandError` de Alembic) y de registro (`ModuleNotFoundError: gateway.passwords`), luego GREEN: 53 pruebas contra PostgreSQL real; sin la variable, las pruebas de datos fallan con un mensaje claro (no se omiten).
- **Revisiones:** `revisor-seguridad` y Gentle AI (4 lentes) aprobaron sin críticos ni altos. Corregido antes del PR: `hide_parameters=True` y además ningún error de inserción distinto del duplicado lleva el `DETAIL` de PostgreSQL (la fila con el hash), solo el SQLSTATE; `connect_timeout` de 5 s; como mucho 4 hashes Argon2id a la vez por proceso (19 MiB cada uno en una ruta sin autenticar); las pruebas se niegan a correr contra una base cuyo nombre no termine en `_test` o `_ci` (vacían tablas); la restricción de roles sale de `ROLES`; Alembic funciona desde la terminal. Resultado: 67 pruebas.

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25).
- [ ] Verificar las versiones del resto del stack (React, workers, PostgreSQL, RabbitMQ, Vault) antes de fijarlas; las del `gateway` se verificaron en el issue #25.
- [ ] Revisar periódicamente las versiones de `uv`, gitleaks y actionlint fijadas por sha256 en CI: Dependabot no las actualiza (hallazgo del #25).
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [ ] **E3:** implementar el MFA con TOTP, la recuperación asistida y el arranque del primer administrador (ADR 0004, decisiones 8, 10 y 11), con sus pruebas. Las amenazas 43 a 47 ya están en el modelo.
- [ ] **E3:** implementar la renovación de sesión de un solo vuelo en el frontend.
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).

### E3: pendientes del registro (issue #29)
- [ ] Decidir la normalización Unicode de las contraseñas (NFKC u otra) antes del inicio de sesión (A2); sin ella, la misma contraseña escrita desde otro teclado puede no coincidir.
- [ ] Límite de tasa en `POST /api/auth/register` y tope de tamaño del cuerpo (Ingress, E5); hoy solo hay el límite de 4 hashes simultáneos.
- [ ] `readyz` que compruebe la base de datos (E5): sin `GATEWAY_DATABASE_URL`, `/healthz` responde pero la API falla.
- [ ] **A2:** tiempo máximo de espera en el semáforo de Argon2id (hoy espera sin límite) y respuesta 503 al agotarlo, antes de que el login comparta el semáforo con el registro (aviso de la revisión del #29).

### E5: plataforma, red y cifrado
- [ ] ADR de cifrado dentro del clúster (TLS/mTLS para Vault, PostgreSQL y RabbitMQ), antes de E5.
- [ ] Decidir el mecanismo de cifrado del secreto TOTP (transit de Vault o cifrado de aplicación), junto con el ADR de red y criptografía (antes de E5).

### E4/E7: CI/CD y cadena de suministro
- [ ] Modelar la cadena de suministro de CI/CD (E4/E7).
- [ ] **E7:** referenciar las imágenes por digest, no solo por `vX.Y.Z` y `latest` (hallazgo B4 del #15).
- [ ] **E7:** la imagen del `gateway` redistribuye `psycopg-binary` (LGPL-3.0 con libpq y OpenSSL empaquetados): incluir el aviso de licencia y declararlo en el SBOM (issue #29).

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
- [x] **E2 (issue #25, PR #26):** esqueleto del `gateway` con `uv.lock`, lint y pruebas en CI.
- [x] **Issue #27 (PR #28):** `gateway` obligatorio en el ruleset (aplicado en GitHub el 2026-09-30 y verificado desde la API), documentación de la API desactivada por defecto y `httpx2`. ADR 0001 actualizado en el issue #29.
