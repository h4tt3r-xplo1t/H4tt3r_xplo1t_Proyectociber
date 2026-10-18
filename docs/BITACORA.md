# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## Historial

Las entradas de issues cerrados se mueven a `docs/bitacora/` para no superar el límite de instrucciones de Claude Code (issue #23). No se cargan en cada sesión; léelas cuando haga falta el detalle.

- [2026-09-27 a 2026-09-28](bitacora/2026-09-27_28.md): arranque, `guardia.sh` (issue #1, PR #3), protección de `main` (issue #4) y pruebas reales en CI (issue #9).
- Decisiones deliberadas que solo están en ese historial, y que no deben «arreglarse» sin revisarlo: `.env.example` no se puede leer con la herramienta Read (una regla `allow` no puede exceptuar una `deny`; issue #1, PR #12) y el detalle de cobertura y rondas TDD de `guardia.sh` (los límites y falsos positivos aceptados también están en el ADR 0002).
- [2026-09-29](bitacora/2026-09-29.md): E0 y elección de la aplicación (issue #15), modelo de amenazas (issue #18) y ADR 0004 (issue #20).
- [2026-09-30](bitacora/2026-09-30.md): límite de instrucciones (issue #23), esqueleto del gateway (issue #25), mantenimiento (issue #27), registro de usuarios (issue #29) y OpenBao (issue #31, ADR 0005). Decisiones que conviene conocer: `uv` sin acción de terceros en CI, el manejador 422 propio (el de FastAPI devuelve la contraseña), `hide_parameters` y SQLSTATE sin `DETAIL`, y el cliente de OpenBao que ignora `VAULT_TOKEN`.
- [2026-10-03 a 2026-10-05](bitacora/2026-10-03_05.md): inicio de sesión (issue #33), sesión con refresh, logout y denylist (issue #35) y mantenimiento de la sesión (issue #37). Decisiones que conviene conocer:
  - NFC (no NFKC) para las contraseñas.
  - `sid` igual al `id` de la familia de refresh; la reutilización de un refresh revoca la familia sin periodo de gracia (riesgo aceptado).
  - Los 403 por origen o CSRF del logout no borran cookies.
  - `tokens_valid_since` sale del reloj de la aplicación (requisito de NTP).
- [2026-10-05 a 2026-10-11](bitacora/2026-10-05_11.md): MFA con TOTP (issue #39) y cierre de A3a (issue #43). Decisiones que conviene conocer: el secreto TOTP se cifra con transit de OpenBao (ADR 0006), un rol con privilegios sin MFA solo recibe un JWT de alcance `enroll-mfa`, `current_user` y `refresh` rechazan la sesión con privilegios sin MFA, y el trabajo lento (transit, Argon2) se hace fuera del bloqueo de filas con una comprobación final.
- [2026-10-12](bitacora/2026-10-12.md): administración del gateway (issue #45, A3b1) y seguimiento de su revisión (issue #47), endurecimiento del gateway (issue #49) y gestión del MFA (issue #51). Decisiones que conviene conocer: contador de generación `gen` en cada JWT (los tokens sin `gen` se rechazan una vez), el hash del login se verifica sin bloqueo de fila, el MFA solo lo desactivan los lectores, la cuota de altas (5 por hora) se consume aunque transit falle, y el arranque del primer administrador lee su contraseña solo de OpenBao con un AppRole aparte y se niega si ya hay un administrador, `busy_guard` traduce los bloqueos a 503, y `bootstrap-seed` solo se crea con `CI=true` o `OPENBAO_DEV_BOOTSTRAP_SEED=1`.
- [2026-10-15](bitacora/2026-10-15.md): recuperación asistida y restablecimiento del MFA (issue #56). Decisiones que conviene conocer: opción B con la marca `privileged_at` y dos administradores distintos para las cuentas que tienen o tuvieron privilegios, segundo factor del código solo con el MFA activo y vencimiento de 1 h de las solicitudes.
- [2026-10-16](bitacora/2026-10-16.md): procedimiento de emergencia (break-glass, issue #58). Decisiones que conviene conocer: el break-glass cubre toda cuenta que tiene o tuvo privilegios, tiene AppRole propio, destruye el secreto antes de confirmar la transacción y no reinicia el contador de bloqueo del login.

## 2026-10-17 · Issue #60: worker-noticias (ingesta de RSS y sitemaps)

Rama `feat/60-worker-noticias`. El worker lee los RSS de RCN y Semana y los sitemaps de noticias de RCN, Caracol, Blu Radio y Citytv (seis fuentes de cinco medios) y guarda titular, enlace, fecha, resumen, medio y autor (amenazas 15, 17, 20, 21 y 22). Detalle por tarea, evidencias RED y mutaciones: `odd/tasks/worker-noticias.md`.

- **T1 (`80e280e`):** esqueleto con `uv.lock`, ruff `S` y pytest; trabajo `worker-noticias` obligatorio en CI y en el ruleset local; Dependabot; ADR 0007.
- **T2 (`255dd24`, corrección `6176730`):** `fetch.py`: lista fija de hosts, solo https, toda IP resuelta pública y conexión fijada a la IP validada con SNI, redirecciones al mismo host, plazo comprobado tras cada lectura y tope de 5 MiB descomprimido.
- **T3 (`9c5ba16`, `d4240cb`):** seguimientos de T2 y `feeds.py` con `defusedxml` (sin DTD ni entidades), texto plano acotado, enlace del propio medio y fecha UTC; un `sitemapindex` no se sigue.
- **T4 (`7c0f21e`):** `robots.py` (RFC 9309) con un `User-Agent` propio.
- **T5 (`5037336`):** esquema `noticias`, tabla `news_items` con enlace único, migraciones propias, rol `worker_noticias` con `SELECT`, `INSERT` y `DELETE` solo en su tabla y purga por retención.
- **T6 (`5d30e04`, `993905d`):** `cycle.py` y `__main__.py` (`run`, `once`, `check-live`) con aislamiento por fuente; `5d30e04` incluye los seguimientos de T5 y `993905d` los de la revisión de T6.
- **Decisiones:** (persona, 2026-10-16) bucle propio sin Celery (ADR 0007) y un solo PR; (persona) se autoriza editar `tests/rulesets/main_ruleset_test.sh`; `urllib3` y `defusedxml` verificados en PyPI (riesgo aceptado: poca actividad de `defusedxml`; prueba de Expat >= 2.7.2); `robots.txt`: 4xx permite, 5xx, 429 y fallos prohíben durante el ciclo; el `<author>` con `@` se descarta (dato personal).
- **Incidente (2026-10-17):** una prueba del redactor llamó a `once` con el cliente real y envió un ciclo de peticiones a los medios sin autorización (unos 4,6 s; no se leyó la salida). Se corrigió y se añadió la guarda `no_network` en `tests/conftest.py`, con sus pruebas.
- **Residuales:** NO VERIFICADO: formatos reales, `robots.txt` reales y el `Allow` de Semana (pendiente de `check-live`), el trabajo de CI, migraciones junto a las tablas reales del gateway y SIGTERM real. Una sola réplica (ADR 0007). El plazo puede excederse en una lectura (10 s). Con un operador solo CREATEROLE, `create_role.sql` depende de su idempotencia y de un servidor sin registro de sentencias.
- **Gentle AI:** T1 `review-a940d05cfd519d3d`; T2 `review-587bdbdb2bce1b06` (una corrección: un servidor que enviaba un byte cada 9 s eludía el plazo, CRÍTICO); T3 `review-25174e7c8efc294d`; T4 `review-eba8829d59158a74` (dos falsos positivos sustentados por mutación); T5 `review-c2f0de0a079a4e73`; T6 `review-860038808ca0fae8`.
- **TDD:** RED por comportamiento desde T3; en T2 solo a nivel de archivo (desviación declarada, sustituida por mutaciones). De 0 a 324 pruebas.

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25; falta `worker-noticias`, issue #60).
- [ ] Verificar las versiones del resto del stack (React, workers, PostgreSQL, RabbitMQ, Vault) antes de fijarlas; las del `gateway` se verificaron en el issue #25.
- [ ] Revisar periódicamente las versiones de `uv`, gitleaks y actionlint fijadas por sha256 en CI: Dependabot no las actualiza (hallazgo del #25).
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [x] **A3b2b:** procedimiento de emergencia (break-glass) para administradores (ADR 0004, decisión 11). Resuelto en el #58. La recuperación asistida y el restablecimiento del MFA con dos administradores se resolvieron en el #56 (A3b2a, amenaza 46).
- [x] **ADR 0004:** (resuelto en el #58) incorporar a la decisión 10 las decisiones de la persona del #56: un lector nunca privilegiado se restablece con un administrador; la marca de privilegio y los dos administradores para el MFA y el código de las cuentas que tienen o tuvieron privilegios; el segundo factor del código solo con el MFA activo; el vencimiento de 1 h de las solicitudes. Quedó fuera del alcance del #56 porque `docs/adr/**` no estaba autorizado.
- [ ] **E5:** formulario de ayuda anónimo, con límite por IP; hasta entonces la ayuda se pide por un canal externo documentado (#56).
- [x] Límite de frecuencia propio en `/mfa/enroll`, y desactivar el MFA o regenerar los códigos de recuperación (#39). Resuelto en el #51.
- [x] **A3b:** un usuario con privilegios que ya existía sin MFA y sin fecha límite de alta no podía iniciar sesión ni darse de alta; resuelto con la asignación pendiente de roles (issue #45).
- [x] **A3b2:** (resuelto en el #58 con `gateway.breakglass`) el administrador de arranque queda bloqueado si caduca su ventana de alta de 24 h; reabrirla exige otro administrador, así que depende del procedimiento de emergencia (L1 de la revisión del #45).
- [x] `tokens_valid_since` tiene granularidad de un segundo: un token con alcance emitido en el mismo segundo que el cambio no queda anulado por él (L2 de la revisión del #45). Resuelto en el #49: contador de generación `gen`.
- [x] El arranque del primer administrador usa un bloqueo asesor y no una restricción única en la base de datos (I2 de la revisión del #45). Resuelto en el #49: se mantiene el bloqueo asesor (decisión).
- [ ] **E5:** mantener los AppRoles `bootstrap-seed` y `breakglass-seed` (solo desarrollo y CI) fuera de los manifiestos.
- [ ] **E5:** empaquetar `gateway.bootstrap` y `gateway.breakglass` como Jobs de Kubernetes ejecutados a mano con `backoffLimit: 0` (#58). En producción el `secret_id` de `bootstrap` y de `breakglass` debe ser de un solo uso (`secret_id_num_uses=1`) y de TTL corto, generado justo antes de la ejecución; los AppRoles de desarrollo usan `secret_id_ttl=0` y `secret_id_num_uses=0` (hallazgo bajo de `revisor-seguridad` del #58).
- [x] El bloqueo del contador de intentos del login (`auth.py`) solo traduce `LOCK_NOT_AVAILABLE` a 503; valorar usar `busy_guard` también ahí (#47). Resuelto en el #49: `_lock_attempt` usa `busy_guard`.
- [ ] Varias peticiones `/login/mfa` en paralelo con un token `mfa-pending` válido hacen su llamada a transit y su Argon2 a la vez, ya sin serializar; depende del límite de tasa por IP (E5) (L1 de la revisión del #43).
- [ ] Rotación de la clave transit `totp` con `rewrap` de los textos cifrados (ADR 0006).
- [ ] **E3:** implementar la renovación de sesión de un solo vuelo en el frontend.
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).
- [ ] **E3:** aplicar en GitHub el ruleset con la comprobación obligatoria `worker-noticias` después de la fusión del #60 (operación remota, a petición de la persona).
- [ ] **E3:** `check-live` contra los medios (decisión de la persona) para verificar los formatos de los sitemaps y del RSS de RCN, los `robots.txt` reales y la cobertura del `Allow` de Semana (NO VERIFICADO, #60).
- [ ] **E3:** publicación en RabbitMQ y `worker-analisis` (siguiente issue).

### E3: pendientes del registro (issue #29)
- [ ] Límite de tasa en `POST /api/auth/register` y tope de tamaño del cuerpo (Ingress, E5); hoy solo hay el límite de 4 hashes simultáneos.
- [x] `readyz` que compruebe la base de datos (E5): sin `GATEWAY_DATABASE_URL`, `/healthz` responde pero la API falla. Resuelto en el #49: `GET /readyz`.

### Inicio de sesión (issue #33)
- [ ] Bloqueo dirigido: cualquiera puede mantener bloqueada una cuenta ajena (4 fallos y luego uno cada 30 min). Lo acepta el ADR 0004 hasta que existan el límite por IP (E5) y la recuperación asistida (revisión de Gentle AI del #33).
- [x] El login mantiene la conexión a la base de datos y el bloqueo de fila durante la espera del hash (hasta 5 s más el hash). Valorar leer y bloquear el contador en una transacción corta separada del hash (revisión de Gentle AI del #33). Resuelto en el #49: el hash se verifica sin bloqueo ni transacción.
- [ ] Saturación del threadpool: hasta 5 s de espera por el semáforo bloquean hilos de las rutas síncronas; depende del límite de tasa (E5) (L6 de la revisión del #33).
- [ ] Programar la purga (`python -m gateway.maintenance purge`) como CronJob en E5 (#37); desde el #51 también purga `mfa_enrollment_attempts` y desde el #56 `password_reset_codes` y `mfa_reset_requests`.
- [x] Exigir el CSRF ligado al `sid` en las rutas que cambien estado después del login; `refresh` y `logout` ya lo exigen (#35). Resuelto en el #49: ya estaba completo; una prueba de guarda lo comprueba.

### OpenBao (issue #31)
- [ ] Llevar a OpenBao las credenciales de PostgreSQL (hoy en variables de entorno).
- [ ] Rotación de la clave JWT con `kid` y custodia de las claves de desbloqueo fuera de desarrollo.
- [ ] TLS del listener de OpenBao junto con el ADR de cifrado interno.
- [ ] Dispositivo de auditoría de OpenBao (E5/E8) y reintentos con espera del gateway al arrancar si OpenBao no responde (amenaza 14).
- [ ] Las claves quedan en caché hasta reiniciar el proceso: la rotación con `kid` (A2 o posterior) debe definir cómo se recargan.

### E5: plataforma, red y cifrado
- [ ] ADR de cifrado dentro del clúster (TLS/mTLS para Vault, PostgreSQL y RabbitMQ), antes de E5.
- [ ] **E5:** `/readyz` no debe exponerse fuera del clúster y debe quedar cubierto por el límite de tasa: es anónimo y, con la base caída, cada sonda tarda hasta unos 5 s y puede agotar el threadpool (L2 de la revisión del #49).
- [ ] **E5:** los 10 hashes de `/mfa/recovery-codes` toman el semáforo de Argon2id uno a uno (hasta unos 10 × 5 s de hilo); misma clase que L6 del #33, depende del límite de tasa (L3 de la revisión del #51).
- [ ] Prueba de concurrencia del límite de altas del MFA: lo cierra el bloqueo de la fila del usuario, sin prueba que lo demuestre (#51).
- [ ] **E5:** proxy de salida o política por nombre de dominio para el worker de noticias (amenaza 21): hoy solo hay controles en código (#60).
- [ ] **E5:** CronJob o Deployment de Kubernetes con una sola réplica para `worker-noticias` (ADR 0007), con las credenciales de base de datos del worker en OpenBao y la contraseña del rol `worker_noticias` desde el gestor de secretos (#60).

### E4/E7: CI/CD y cadena de suministro
- [ ] Modelar la cadena de suministro de CI/CD (E4/E7).
- [ ] **E7:** referenciar las imágenes por digest, no solo por `vX.Y.Z` y `latest` (hallazgo B4 del #15).
- [ ] **E7:** la imagen del `gateway` redistribuye `psycopg-binary` (LGPL-3.0 con libpq y OpenSSL empaquetados): incluir el aviso de licencia y declararlo en el SBOM (issue #29); la imagen de `worker-noticias` también lo redistribuye (issue #60).

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
- [x] **Issue #29 (PR #30)** y **#31 (PR #32):** registro de usuarios y OpenBao.
- [x] **A2b (issue #35):** refresh con rotación y detección de reutilización, logout, denylist y `tokens_valid_since`; reinicio del contador tras emitir los tokens y longitud después de NFC.
- [x] Mecanismo de cifrado del secreto TOTP: transit de OpenBao (ADR 0006, issue #39).
- [x] **Issue #47:** hallazgos no bloqueantes de la revisión de Gentle AI del #45.
- [x] **Issue #39 (PR #42, `28f63e8`):** MFA con TOTP y secreto cifrado con transit de OpenBao (ADR 0006).
- [x] **Issue #45 (PR #46, `8ab9ce6`):** administración del gateway: primer administrador (`gateway.bootstrap`), endpoints `/api/admin/...` con rol pendiente y cambio de contraseña.
- [x] **Issue #37:** purga de las tablas de sesión, reloj único para `tokens_valid_since` y logout que borra las cookies.
- [x] Normalización Unicode de contraseñas (NFC) y tiempo máximo del semáforo de Argon2id (pendientes del #29, cerrados en el #33).
- [x] **Issue #27 (PR #28):** `gateway` obligatorio en el ruleset (aplicado en GitHub el 2026-09-30 y verificado desde la API), documentación de la API desactivada por defecto y `httpx2`. ADR 0001 actualizado en el issue #29.
- [x] **Issue #49:** endurecimiento del gateway: login sin bloqueo durante el hash, contador de generación de tokens, `/readyz` con comprobación de la base de datos, prueba de guarda del CSRF y hallazgos del #47.
- [x] **Issue #56:** código de restablecimiento emitido por un administrador, ruta anónima de restablecimiento, aviso en el siguiente inicio de sesión y restablecimiento del MFA (dos administradores para cuentas con privilegios).
- [x] **Issue #51:** límite de altas del MFA, desactivación del MFA para lectores, regeneración de los códigos de recuperación y amenaza 48 del modelo.
