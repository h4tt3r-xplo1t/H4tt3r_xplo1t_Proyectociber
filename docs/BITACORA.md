# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## Historial

Las entradas de issues cerrados se mueven a `docs/bitacora/` para no superar el límite de instrucciones de Claude Code (issue #23). No se cargan en cada sesión; léelas cuando haga falta el detalle.

- [2026-09-27 a 2026-09-28](bitacora/2026-09-27_28.md): arranque, `guardia.sh` (issue #1, PR #3), protección de `main` (issue #4) y pruebas reales en CI (issue #9).
- Decisiones deliberadas que solo están en ese historial, y que no deben «arreglarse» sin revisarlo: `.env.example` no se puede leer con la herramienta Read (una regla `allow` no puede exceptuar una `deny`; issue #1, PR #12) y el detalle de cobertura y rondas TDD de `guardia.sh` (los límites y falsos positivos aceptados también están en el ADR 0002).
- [2026-09-29](bitacora/2026-09-29.md): E0 y elección de la aplicación (issue #15), modelo de amenazas (issue #18) y ADR 0004 (issue #20).
- [2026-09-30](bitacora/2026-09-30.md): límite de instrucciones (issue #23), esqueleto del gateway (issue #25), mantenimiento (issue #27), registro de usuarios (issue #29) y OpenBao (issue #31, ADR 0005). Decisiones que conviene conocer: `uv` sin acción de terceros en CI, el manejador 422 propio (el de FastAPI devuelve la contraseña), `hide_parameters` y SQLSTATE sin `DETAIL`, y el cliente de OpenBao que ignora `VAULT_TOKEN`.

## 2026-10-03 · Issue #33: inicio de sesión del gateway (A2a)

Rama `feat/33-login-gateway`. A2 se divide en dos partes: **A2a** (este issue: login, JWT de acceso, CSRF y bloqueo) y **A2b** (refresh con rotación, logout, denylist de `jti` y `tokens_valid_since`). Hasta A2b, el login emite solo el JWT de acceso de 15 min.

- **Normalización NFC, no NFKC.** El issue decía NFKC, recordado de la revisión 3 de NIST SP 800-63B. La revisión 4 (2025-08-26), leída en la fuente, recomienda NFC antes del hash; la persona eligió NFC. Se aplica dentro de `hash_password` y `verify_password`, así que la usan el registro, el login y el hash ficticio. No hay datos reales, así que no se migra ningún hash.
- **PyJWT 2.15.1** (MIT, jpadilla, publicada el 2026-09-28, sin dependencias en Python ≥ 3.11), verificada en PyPI. `uv audit`: 40 paquetes sin vulnerabilidades conocidas.
- **Endpoints:**
  - `GET /api/auth/csrf`: emite un CSRF previo a la sesión de 10 min, con `no-store`.
  - `POST /api/auth/login`: exige ese CSRF y el mismo origen.
  - `GET /api/auth/me`: recarga al usuario de la base de datos.
- **JWT y cookies:**
  - JWT HS256 con `kid`, `algorithms=["HS256"]`, `iss` y `aud` fijos y 30 s de margen.
  - Cookie `__Host-access` (`HttpOnly`, `Secure`, `SameSite=Strict`, 15 min).
  - Tras el login, el `__Host-csrf` queda ligado al `sid`.
- **Origen:** `Sec-Fetch-Site: same-origin`, o `Origin` igual a `GATEWAY_ALLOWED_ORIGIN` cuando el navegador no envía `Sec-Fetch-Site`. Sin ninguno, 403. El registro también lo exige.
- **Bloqueo progresivo** en la tabla `login_attempts` (migración `0002`):
  - Los 3 primeros fallos no bloquean; luego 1, 5, 15 y 30 min.
  - Cuenta también los nombres inexistentes, con `SELECT ... FOR UPDATE` para que los intentos en paralelo no escapen al contador.
  - Contraseña errónea, usuario inexistente y cuenta bloqueada dan el mismo 401 y el mismo cuerpo, y gastan el mismo tiempo (hash ficticio).
- **Semáforo de Argon2id:** como mucho 5 s de espera; si se agota, 503 sin calcular el hash. Cierra el pendiente del #29.
- **Settings nuevos sin valores por defecto:** `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE` y `GATEWAY_ALLOWED_ORIGIN`. En CI tienen valores ficticios.
- **TDD:** RED observado en cada tarea (por ejemplo, `ImportError: cannot import name 'HashingBusy'`), luego GREEN. Pruebas: de 105 a 220. Los tiempos del bloqueo se prueban con un reloj inyectado, sin `sleep`.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos ni altos; 1 medio y 5 bajos. Corregidos con TDD (242 pruebas, comprobadas sobre una base de datos nueva):
  - Un login correcto pone el contador a cero en vez de borrar la fila. Antes, un intento simultáneo daba 500.
  - `lock_timeout` de 2 s sobre la fila del contador; si se agota, responde 503 sin contar un fallo.
  - `login_attempts` se indexa con un HMAC del nombre, con una subclave derivada de la clave CSRF: una contraseña escrita en el campo de usuario ya no se guarda ni se registra. Rotar la clave CSRF reinicia los contadores.
  - El CSRF previo a la sesión lleva una fecha de emisión firmada y caduca en el servidor a los 10 min.
  - `Cache-Control: no-store` en `/login`, `/me` y `/csrf`.

  Quedan pendientes la purga de `login_attempts` y la saturación de hilos por el semáforo (depende del límite de tasa del Ingress).
- **Revisión de Gentle AI (4 lentes):** aprobada sin bloqueantes y confirmada. De sus 12 observaciones se corrigieron 7, con un commit cada una (246 pruebas sobre una base de datos nueva):
  - La prueba de concurrencia se sincroniza con eventos, sin `sleep`; pasó 20 de 20 veces seguidas.
  - Si faltan `GATEWAY_JWT_ISSUER` o `GATEWAY_JWT_AUDIENCE`, el gateway da un error de servidor y no un 401.
  - La columna se renombra a `attempt_key`, porque guarda un HMAC.
  - La espera del bloqueo de fila lanza `LoginBusy`, distinta de `HashingBusy`; las dos dan el mismo 503 y cada 503 registra su causa.
  - La prueba NFC usa escapes `\u`.
  - El TTL de la cookie sale del TTL del JWT.
  - Se corrigió un comentario desactualizado.

  Las otras observaciones están en Pendientes.
- **Bitácora rotada:** las entradas del 30-09 se movieron a `docs/bitacora/2026-09-30.md` (este archivo pasaba de 20 000 bytes). Se comprobó que no se perdió ninguna línea.

- **Cierre:** PR #34 fusionado con squash como `51aa0e4`; issue #33 cerrado. Push por SSH (la rama cambiaba el workflow); en CI corrieron las 246 pruebas.

## 2026-10-03 · Issue #35: sesión del gateway (A2b)

Rama `feat/35-sesion-gateway`. Completa la gestión de sesión del ADR 0004.

- **`sid` igual al `id` de la familia de refresh:** el login crea la familia, y el `sid` del JWT y el CSRF de sesión usan su `id`; no hace falta una columna nueva.
- **Migración `0003`:**
  - `refresh_tokens`: solo el SHA-256 del token. Argon2 no hace falta: el token es aleatorio de 256 bits.
  - `revoked_jtis`: denylist con `expires_at`.
- **Login:** emite además `__Secure-refresh` (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/auth/refresh`), con vida igual al límite absoluto del rol. El CSRF de sesión vive lo mismo, porque el refresh lo necesita cuando el JWT ya venció.
- **`POST /api/auth/refresh`:**
  - Bloqueo de fila del token y de su familia, con `lock_timeout`.
  - El CSRF se comprueba contra el `sid` de la familia, antes de cambiar nada: un CSRF inválido no consume el token ni dispara la revocación.
  - Rotación en cada uso. La reutilización revoca la familia sin periodo de gracia.
  - Límites por rol leídos de la base de datos: lector 24 h de inactividad y 7 d absoluto; el resto, 30 min y 8 h.
- **`POST /api/auth/logout`:**
  - Acepta un JWT vencido si la firma, `iss`, `aud` y `kid` son válidos.
  - Revoca la familia y añade el `jti` a la denylist hasta su `exp`.
  - Borra las tres cookies. Es idempotente.
- **`current_user`:** en una sola consulta rechaza un `jti` revocado, un `iat` anterior a `tokens_valid_since` y una familia revocada o inexistente.
  - `tokens_valid_since` se trunca al segundo, porque el `iat` es entero; un token del mismo segundo que el registro sigue valiendo.
  - Revisar la familia cierra la ventana de 15 min en que el JWT de una sesión robada seguía valiendo tras detectarse la reutilización.
- **Pendientes del #33 cerrados:**
  - El contador de fallos se reinicia en el mismo commit que emite los tokens; si la emisión falla, no cambia.
  - La longitud mínima de la contraseña se comprueba después de NFC.
- **TDD:** RED observado en cada tarea y luego GREEN, sobre una base de datos nueva; detalle en `odd/tasks/sesion-gateway.md`.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos ni altos; 2 medios y 6 bajos. Corregidos:
  - Prueba de concurrencia real con el mismo refresh.
  - Orden fijo de bloqueos (familia y luego token); un deadlock o un error de serialización da 503.
  - Causa correcta del 503 en los logs.
  - `lock_timeout` también en el logout.
  - El refresh respeta `tokens_valid_since`.
  - Un claim de tipo inesperado da 401, nunca 500.
- **Riesgo aceptado (M1):** si se pierde la respuesta de un refresh y el cliente reintenta con el token ya usado, se revoca la familia y la persona debe volver a iniciar sesión. Lo decide el ADR 0004 («sin periodo de gracia»). Una ventana de gracia requeriría un ADR nuevo.
- **Revisión de Gentle AI (4 lentes):** `review-3a4bb0b52adcc031`, aprobada y confirmada sin bloqueantes. Una lente falló al primer intento por el límite de sesión de la cuenta del revisor; se relanzó cuando el estado volvió a ofrecerla.
  - Lo más relevante: el logout no funcionaba pasados 15 min, porque el navegador deja de enviar `__Host-access`. Ahora la cookie vive lo mismo que la sesión y el `exp` del JWT sigue limitando su validez.
  - Corregido también: un `exp` de tipo inválido en el logout daba 500; una prueba de rotación no comprobaba lo que decía su nombre; `LoginBusy` pasa a un nombre genérico; la longitud mínima queda en una sola constante.
- **Riesgo anotado (L5):** `__Secure-refresh` no puede ser `__Host-` porque lleva `Path`; un subdominio hermano podría sobrescribirlo con `Domain=`. Queda mitigado por `SameSite=Strict` y porque el valor no se puede adivinar. Anotado en la amenaza 35.

- **Cierre:** PR #36 fusionado con squash como `afc1372`; issue #35 cerrado. Push por HTTPS (la rama no cambiaba `.github/`); en CI corrieron las 336 pruebas.

## 2026-10-04 · Issue #37: mantenimiento de la sesión

Rama `chore/37-mantenimiento-sesion`. Cierra la deuda de sesión del #33 y del #35 antes de A3.

- **Purga** con `python -m gateway.maintenance purge` (idempotente; solo imprime el nombre de cada tabla y cuántas filas borró). Borra:
  - contadores de `login_attempts` sin bloqueo vigente y sin actividad en 24 h;
  - `jti` vencidos de `revoked_jtis`;
  - familias de refresh revocadas o que superan el límite absoluto del rol actual, con sus tokens en cascada.

  Una familia purgada sigue dando 401, porque `current_user` exige que exista. Lanzarla de forma periódica (CronJob) queda para E5.
- **Reloj único:** `tokens_valid_since` se fija con el reloj de la aplicación en el registro, igual que el `iat` y `family.created_at`; cualquier cambio futuro debe usar ese mismo reloj.
- **Logout:** sin una cookie de acceso válida sigue respondiendo 401, pero borra las tres cookies. Los 403 por origen o CSRF no las borran, a propósito: una petición falsificada desde otro sitio no debe poder vaciar las cookies de la víctima.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos, altos ni medios. Se corrigieron sus 4 bajos en una sola ronda:
  - Un `jti` solo se purga cuando además pasa el margen de 30 s del decodificador.
  - El número de `refresh_tokens` borrados sale de `DELETE ... RETURNING`.
  - Si la purga borra el contador a mitad de un login, el login reintenta una vez y, si vuelve a fallar, responde 503, nunca 500.
  - El comando falla con un mensaje fijo (sin URL, usuario ni traceback) y código de salida 1.
- **Requisito de operación:** los relojes de las réplicas del gateway deben estar sincronizados (NTP). Con desfase, un token emitido en una réplica atrasada justo después de registrarse en otra adelantada se rechaza hasta que pase el desfase.
- **Pruebas:** fixtures `clock` y `client` compartidos en `conftest.py`. TDD con RED observado en cada cambio de comportamiento; de 336 a 354 pruebas.

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
- [ ] Límite de tasa en `POST /api/auth/register` y tope de tamaño del cuerpo (Ingress, E5); hoy solo hay el límite de 4 hashes simultáneos.
- [ ] `readyz` que compruebe la base de datos (E5): sin `GATEWAY_DATABASE_URL`, `/healthz` responde pero la API falla.

### Inicio de sesión (issue #33)
- [ ] Bloqueo dirigido: cualquiera puede mantener bloqueada una cuenta ajena (4 fallos y luego uno cada 30 min). Lo acepta el ADR 0004 hasta que existan el límite por IP (E5) y la recuperación asistida (revisión de Gentle AI del #33).
- [ ] El login mantiene la conexión a la base de datos y el bloqueo de fila durante la espera del hash (hasta 5 s más el hash). Valorar leer y bloquear el contador en una transacción corta separada del hash (revisión de Gentle AI del #33).
- [ ] Saturación del threadpool: hasta 5 s de espera por el semáforo bloquean hilos de las rutas síncronas; depende del límite de tasa (E5) (L6 de la revisión del #33).
- [ ] Programar la purga (`python -m gateway.maintenance purge`) como CronJob en E5 (#37).
- [ ] Exigir el CSRF ligado al `sid` en las rutas que cambien estado después del login; `refresh` y `logout` ya lo exigen (#35).

### OpenBao (issue #31)
- [ ] Llevar a OpenBao las credenciales de PostgreSQL (hoy en variables de entorno).
- [ ] Rotación de la clave JWT con `kid` y custodia de las claves de desbloqueo fuera de desarrollo.
- [ ] TLS del listener de OpenBao junto con el ADR de cifrado interno.
- [ ] Dispositivo de auditoría de OpenBao (E5/E8) y reintentos con espera del gateway al arrancar si OpenBao no responde (amenaza 14).
- [ ] Las claves quedan en caché hasta reiniciar el proceso: la rotación con `kid` (A2 o posterior) debe definir cómo se recargan.

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
- [x] **Issue #29 (PR #30)** y **#31 (PR #32):** registro de usuarios y OpenBao.
- [x] **A2b (issue #35):** refresh con rotación y detección de reutilización, logout, denylist y `tokens_valid_since`; reinicio del contador tras emitir los tokens y longitud después de NFC.
- [x] **Issue #37:** purga de las tablas de sesión, reloj único para `tokens_valid_since` y logout que borra las cookies.
- [x] Normalización Unicode de contraseñas (NFC) y tiempo máximo del semáforo de Argon2id (pendientes del #29, cerrados en el #33).
- [x] **Issue #27 (PR #28):** `gateway` obligatorio en el ruleset (aplicado en GitHub el 2026-09-30 y verificado desde la API), documentación de la API desactivada por defecto y `httpx2`. ADR 0001 actualizado en el issue #29.
