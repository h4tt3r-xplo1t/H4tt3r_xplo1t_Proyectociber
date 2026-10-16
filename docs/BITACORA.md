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

## 2026-10-16 · Issue #58: procedimiento de emergencia (break-glass)

Rama `feat/58-procedimiento-emergencia`. Cierra A3b2b (ADR 0004, decisión 11; amenazas 46 y 47).

- **Revisión del #56 (T0, `08fd6c7`):** registro de la revisión y recuento de pruebas de 978 a 988.
- **Sugerencias del #56 (T1, `473718e`):** de la revisión de Gentle AI.
  - Renombres `ApprovalRequest`, `ApprovalPendingOut` y `APPROVAL_REQUEST_TTL` (el nombre de la tabla se conserva).
  - `_claim_request` compartido por las dos rutas de aprobación; el vencimiento se calcula una sola vez; `issue_reset_code` no calcula el hash antes de la comprobación de los dos administradores; pruebas movidas y añadidas.
  - Desviación de TDD declarada en el documento de la tarea: un elemento se implementó antes de su prueba, sin RED previo; se sustituye por evidencia de mutación (forzar el hash hizo fallar la prueba).
- **Comando de emergencia (T2, `9bf60e6`):** `python -m gateway.breakglass --username <nombre> --break-glass`.
  - AppRole propio `breakglass`, con una política que solo permite leer `secret/data/breakglass/account` y borrar sus metadatos; el AppRole `breakglass-seed` solo se crea con `CI=true` o `OPENBAO_DEV_BOOTSTRAP_SEED=1`. Políticas en `deploy/openbao/` y script de inicialización.
  - Guarda contra el objetivo equivocado: se rechaza un secreto cuyo `username` no coincide con `--username`.
  - Efectos en una sola transacción bajo el bloqueo de la fila: contraseña sembrada con `must_change_password`, MFA y códigos de recuperación borrados, ventana de alta de 24 h, solicitudes y código de restablecimiento pendientes borrados, sesiones revocadas y aviso en el siguiente inicio de sesión.
  - El secreto se destruye antes de confirmar la transacción; códigos de salida 0/1/2/3/4/5; evento `break_glass_reset`.
  - `gateway/oneshot.py` con `destroy_secret` compartido, que usa también `bootstrap`.
  - R3-001 de la revisión de T1: comentario reformulado y prueba añadida.
  - Cierra L1 del #45 (ventana de alta del primer administrador caducada).
- **ADR (T3, `afbba7d`):** decisiones 10 y 11 del ADR 0004 con lo decidido en el #56 y el #58. Se aclara la discrepancia del arranque: el código se niega ante cualquier `administrador`, y el ADR decía activo.
- **Decisiones:** (persona, 2026-10-16) el break-glass cubre toda cuenta que tiene o tuvo privilegios, no solo los administradores.
- **Residuales:**
  - El contador de bloqueo del login no se reinicia: la cuenta espera como máximo 30 min o la desbloquea un administrador.
  - Resultado desconocido de la confirmación tras destruir el secreto: la cuenta puede estar o no restablecida; hay que volver a sembrar y repetir.
  - Dos ejecuciones simultáneas sobre la misma cuenta se serializan en el bloqueo de la fila (sin prueba).
  - El empaquetado como Job de Kubernetes queda para E5.
- **Gentle AI:** T0 aprobada (`review-cff36e38c7d7e756`); T1 aprobada (`review-e56d424c59d58206`); T2 de riesgo alto, cuatro lentes, aprobada (`review-21632641453f603c`) con 5 sugerencias no bloqueantes que se incorporan en T5:
  - R4: el docstring y el texto de `RESET_FAILED` deben decir que la cuenta puede o no haberse restablecido.
  - R2: `except` sin paréntesis en `breakglass.py:251`; `mark_privileged` falta en la lista del docstring; parámetro `shared` sin uso en el `FakeBao` de `test_breakglass.py`; `OPENBAO_DEV_BOOTSTRAP_SEED` también crea el rol escritor del break-glass.
  - T3 pasiva.
- **TDD:** RED observado en T1 (salvo la desviación declarada) y en T2; T0, T3 y T4 son solo documentación. De 988 a 1065 pruebas (1065 passed localmente, 491 s).

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25).
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
- [ ] **E5:** empaquetar `gateway.bootstrap` y `gateway.breakglass` como Jobs de Kubernetes ejecutados a mano con `backoffLimit: 0` (#58).
- [x] El bloqueo del contador de intentos del login (`auth.py`) solo traduce `LOCK_NOT_AVAILABLE` a 503; valorar usar `busy_guard` también ahí (#47). Resuelto en el #49: `_lock_attempt` usa `busy_guard`.
- [ ] Varias peticiones `/login/mfa` en paralelo con un token `mfa-pending` válido hacen su llamada a transit y su Argon2 a la vez, ya sin serializar; depende del límite de tasa por IP (E5) (L1 de la revisión del #43).
- [ ] Rotación de la clave transit `totp` con `rewrap` de los textos cifrados (ADR 0006).
- [ ] **E3:** implementar la renovación de sesión de un solo vuelo en el frontend.
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).

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
