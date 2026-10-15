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

## 2026-10-15 · Issue #56: recuperación asistida y restablecimiento del MFA

Rama `feat/56-recuperacion-asistida`. Cierra A3b2a: recuperación de cuenta con un código emitido por un administrador y restablecimiento del MFA (ADR 0004, decisión 10; amenaza 46).

- **Revisión del #51 (T0, `17a3195`):** el registro de la revisión de Gentle AI se guardó como primera tarea.
- **Sugerencias del #51 (T1, `bf73401`):** `disable_mfa_actor` pasa a `mfa_manager_actor`; el bloque de bloqueo, comprobación y consumo del segundo factor de `mfa_disable` y `mfa_recovery_codes` se comparte; ayudantes de prueba duplicados movidos a `tests/helpers.py`; prueba del 503 del bloqueo de la reserva de altas.
- **Código de restablecimiento (T2, `59f2fbb`):** `POST /api/admin/users/{id}/reset-code` (migración 0008).
  - Código de base32 de Crockford, 20 símbolos (100 bits, CSPRNG), guardado con Argon2id, de 15 min y uno vivo por usuario; uno nuevo anula el anterior.
  - Se muestra una sola vez con `NO_STORE`; un administrador no puede emitirse uno a sí mismo (403).
- **Ruta anónima (T3, `25f7600`):** `POST /api/auth/password-reset`, con origen y CSRF previo a la sesión como el login.
  - 401 genérico para cualquier fallo, contado en el bloqueo progresivo; una cuenta bloqueada se rechaza sin contar.
  - Segundo factor: se exige solo si el MFA está activo (ver la decisión de la opción B).
  - Cierra todas las sesiones y no abre ninguna.
- **Aviso al usuario (T4, `896315b`):** el siguiente inicio de sesión completo informa del restablecimiento (`password_reset_at` en `LoginOut`, migración 0009) y lo borra con compare-and-set en la misma transacción; `/me` no cambia.
- **Restablecimiento del MFA (T5, `9bcb3e4`):** `POST /api/admin/users/{id}/mfa-reset` y `.../mfa-reset/approve` (migración 0010).
  - Lector: un solo administrador, al instante.
  - Cuenta con privilegios: solicitud de un administrador y aprobación de otro distinto, ninguno el afectado; la solicitud vence en 1 h; se rechaza (409) si no hay dos administradores además del afectado.
  - Borra el secreto y los códigos, abre una ventana de alta de 24 h, cierra las sesiones y deja eventos fijos.
- **Decisiones:**
  - (a) (persona, 2026-10-15) Un solo administrador puede quitar el MFA de un lector que nunca tuvo privilegios: mismo riesgo residual aceptado que el código para cuentas sin MFA.
  - (b) (persona, 2026-10-15, tras el hallazgo M1 de `revisor-seguridad`) Opción B, que sustituye la regla estricta y la recuperación por degradación:
    - Marca `users.privileged_at`: se fija la primera vez que la cuenta recibe un rol con privilegios o pendiente y nunca se borra (migración 0011, con relleno).
    - Una cuenta que tiene o tuvo privilegios necesita dos administradores distintos, ninguno el afectado, tanto para quitar el MFA como para recibir un código (`.../reset-code/approve`); el código se lo lleva quien aprueba, y la fila guarda `issued_by` y `approved_by`.
    - El código exige segundo factor solo si el MFA está activo; una cuenta con privilegios sin MFA se recupera con un código aprobado por dos administradores.
    - La recuperación por degradación desaparece.
  - (supuesto reversible) La solicitud de restablecimiento del MFA vence en 1 h.
  - El formulario de ayuda anónimo queda fuera hasta el límite por IP (E5): la ayuda se pide por un canal externo documentado.
- **Residuales:**
  - Dos aprobaciones cruzadas (A pidió por B y B por A) pueden bloquearse entre sí; Postgres aborta una con 40P01 y `busy_guard` responde 503 (falla seguro).
  - La caducidad entre la lectura y los bloqueos no tiene prueba: `now` es fijo por petición.
  - El administrador que emite el código lo conoce: lo acepta el ADR 0004 y lo mitiga el aviso en el siguiente inicio de sesión. B1: puede consumir el aviso iniciando sesión antes que el usuario.
  - I2: el recuento de administradores restantes se lee sin el bloqueo de roles.
  - Fallo intermitente observado una vez bajo carga (`test_mfa_recovery_codes.py::test_a_password_changed_meanwhile_counts_as_a_failure`); no se reprodujo en 6 repeticiones. Vigilar en CI.
- **Corrección de la revisión (`3d74003`):** M1 con la opción B (migración 0011: `privileged_at`, `mfa_reset_requests.kind`, `password_reset_codes.approved_by`); B2: `issue_reset_code` llama a `_refuse_if_demoted`; B3: la ventana de alta de un lector con rol pendiente se conserva al restablecer el MFA.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos ni altos.
  - M1 (un solo administrador tomaba una cuenta con privilegios degradándola a lector) se corrigió en `3d74003` con la opción B; B2 y B3 también.
  - B1 (el administrador que emite el código puede consumir el aviso iniciando sesión primero) se acepta dentro del riesgo del ADR 0004.
  - Informativos: I1 (aprobaciones cruzadas, 503), I2 (recuento de administradores sin el bloqueo de roles) e I3 (la solicitud sobrevive si quien la pidió pierde el MFA; inofensivo).
- **Gentle AI:** la revisión de la rama completa superó el presupuesto de contexto del revisor (`lens_context_budget_exceeded`); se hace por partes y sus resultados se añaden después.
- **Modelo de amenazas:** amenaza 46 actualizada con los controles implementados.
- **TDD:** RED observado en cada tarea; de 763 a 978 pruebas.

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25).
- [ ] Verificar las versiones del resto del stack (React, workers, PostgreSQL, RabbitMQ, Vault) antes de fijarlas; las del `gateway` se verificaron en el issue #25.
- [ ] Revisar periódicamente las versiones de `uv`, gitleaks y actionlint fijadas por sha256 en CI: Dependabot no las actualiza (hallazgo del #25).
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [ ] **A3b2b:** procedimiento de emergencia (break-glass) para administradores (ADR 0004, decisión 11). La recuperación asistida y el restablecimiento del MFA con dos administradores se resolvieron en el #56 (A3b2a, amenaza 46).
- [ ] **ADR 0004:** incorporar a la decisión 10 las decisiones de la persona del #56: un lector nunca privilegiado se restablece con un administrador; la marca de privilegio y los dos administradores para el MFA y el código de las cuentas que tienen o tuvieron privilegios; el segundo factor del código solo con el MFA activo; el vencimiento de 1 h de las solicitudes. Quedó fuera del alcance del #56 porque `docs/adr/**` no estaba autorizado.
- [ ] **E5:** formulario de ayuda anónimo, con límite por IP; hasta entonces la ayuda se pide por un canal externo documentado (#56).
- [x] Límite de frecuencia propio en `/mfa/enroll`, y desactivar el MFA o regenerar los códigos de recuperación (#39). Resuelto en el #51.
- [x] **A3b:** un usuario con privilegios que ya existía sin MFA y sin fecha límite de alta no podía iniciar sesión ni darse de alta; resuelto con la asignación pendiente de roles (issue #45).
- [ ] **A3b2:** el administrador de arranque queda bloqueado si caduca su ventana de alta de 24 h; reabrirla exige otro administrador, así que depende del procedimiento de emergencia (L1 de la revisión del #45).
- [x] `tokens_valid_since` tiene granularidad de un segundo: un token con alcance emitido en el mismo segundo que el cambio no queda anulado por él (L2 de la revisión del #45). Resuelto en el #49: contador de generación `gen`.
- [x] El arranque del primer administrador usa un bloqueo asesor y no una restricción única en la base de datos (I2 de la revisión del #45). Resuelto en el #49: se mantiene el bloqueo asesor (decisión).
- [ ] **E5:** mantener el AppRole `bootstrap-seed` (solo desarrollo y CI) fuera de los manifiestos.
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
