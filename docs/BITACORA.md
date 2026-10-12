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
- **Pruebas:** fixtures `clock` y `client` compartidos en `conftest.py`. TDD con RED observado en cada cambio de comportamiento; de 336 a 360 pruebas (354 antes de las correcciones de la revisión).

## 2026-10-05 · Issue #39: MFA con TOTP (A3a)

Rama `feat/39-mfa-gateway`. Primera parte de A3 (ADR 0004, decisiones 4, 8 y 11); la recuperación asistida, el primer administrador y el procedimiento de emergencia van en A3b.

- **Cifrado del secreto TOTP con transit de OpenBao** (decisión de la persona, [ADR 0006](adr/0006-cifrado-secreto-totp.md)):
  - Clave `totp`; la política del gateway solo permite cifrar y descifrar con ella.
  - En la base de datos solo se guarda el texto cifrado.
  - Si OpenBao cae, el login con MFA falla cerrado (503).
- **`pyotp` 2.10.0**, verificada en PyPI (MIT, Andrey Kislyuk, sin dependencias); `uv audit`: 41 paquetes sin vulnerabilidades conocidas.
- **Alta:** un rol con privilegios sin MFA solo recibe un JWT de 10 min con alcance `enroll-mfa`, y solo antes de su fecha límite de alta.
  - `/mfa/enroll` muestra el secreto una vez.
  - `/mfa/confirm` lo activa y muestra una vez 10 códigos de recuperación (Argon2id).
  - El lector puede activarlo desde su sesión.
- **Segundo factor:** con MFA, la contraseña solo da un JWT `mfa-pending` de 5 min; `/login/mfa` con un TOTP o un código de recuperación da la sesión completa por el mismo camino que el login.
  - Ventana de ±1 paso; un paso ya usado se rechaza; los códigos de recuperación son de un solo uso.
  - Los fallos de MFA cuentan en el bloqueo.
- **Denegación por defecto de los alcances:** `current_user` rechaza cualquier token con `scope`.
- **Desarrollo:** transit solo se configura en el primer arranque de OpenBao (después se revoca el token root), así que la pila local se recreó; en CI siempre arranca de cero.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos ni altos; 2 medios y 5 bajos. Corregidos en una sola ronda:
  - El token `mfa-pending` es de un solo uso aunque lleguen dos peticiones a la vez.
  - El alta desde una sesión de lector exige la contraseña actual, y toda confirmación cierra las demás sesiones del usuario.
  - La fecha límite del alta se comprueba también en el alta y en la confirmación.
  - Las llamadas a transit tienen tiempo máximo.
  - El texto cifrado queda ligado al usuario (`context` de transit con su id).
- **Riesgo aceptado:** durante la ventana de alta (24 h), quien conozca la contraseña de un usuario con privilegios puede dar de alta su propio dispositivo (ADR 0004, decisión 11; anotado en la amenaza 43).
- **Entornos de desarrollo existentes:** el script solo configura transit en el primer arranque. Hay que recrear el volumen de OpenBao y los archivos de `.local/openbao/`; sin eso, el MFA responde 503.
- **TDD:** RED observado en cada tarea y en cada corrección; de 360 a 462 pruebas (448 antes de las correcciones de la revisión).
- **Bitácora rotada:** las entradas del #33, el #35 y el #37 pasan a `docs/bitacora/2026-10-03_05.md`, con el cierre del #37 y el número de pruebas corregido (360).

## 2026-10-11 · Issue #43: cierre de A3a

Rama `fix/43-mfa-sesion-privilegiada`. Corrige lo que señaló la revisión de Gentle AI del #39 (PR #42, `28f63e8`), que no se pudo arreglar en ese PR para no hacer commits después de la aprobación.

- **Cierre del #39:** la persona fusionó el PR #42 como `28f63e8`. Antes, al fusionar los PR #41 (SQLAlchemy 2.1.2) y #40 (ruff 0.16.10) de Dependabot, hubo que integrar `main` dos veces en la rama (`55dabed` y `a64f917`, con `uv lock` regenerado) y repetir dos veces la revisión de riesgo alto. **Decisión:** los PR de dependencias se fusionan antes de abrir el PR de una funcionalidad, o esperan a que esta se fusione. Además, la carpeta `.codex/` que apareció sin seguimiento (una copia del kit para Codex) se excluye en local con `.git/info/exclude`.
- **Sesión con privilegios sin MFA:** `current_user` y `refresh` responden el 401 genérico cuando el usuario tiene un rol con privilegios y no tiene MFA, y el refresh revoca la familia. Cubre la sesión abierta antes del despliegue y la de un lector ascendido. Siete pruebas existentes que ascendían a un usuario ahora también le asignan MFA, sin aserciones debilitadas.
- **Trabajo lento fuera del bloqueo:** en `login_mfa`, `mfa_confirm` y `mfa_enroll`, la llamada a transit y el Argon2 de los códigos de recuperación se hacen sin filas bloqueadas. Después, bajo el bloqueo, una comprobación final (compare-and-set) mantiene el uso único del paso TOTP y de cada código, y repite la elegibilidad del alta (ventana, rol y MFA ya activo).
  - Pruebas sin tiempos: una sonda intenta `FOR UPDATE NOWAIT` desde otra conexión durante el trabajo lento.
  - Cada comprobación final tiene una prueba que falla si se quita (comprobación por mutación).
- **Transit:** los errores se registran con la causa fija `transit_failed`. La prueba de OpenBao lento pasaba sin probar nada si faltaban las variables de entorno; ahora falla sin el tiempo máximo. `transit.py` usa `secrets.login_from_env` y `secrets.revoke`, que ahora son públicas.
- **Documentación:** el ADR 0006 pasa a Aceptado y describe la clave derivada con el id del usuario como `context`; las amenazas 1 y 43 recogen los controles nuevos.
- **Revisión de seguridad (`revisor-seguridad`):** lista para PR, sin críticos, altos ni medios; 3 bajos y 4 informativos. Se corrigieron L2, L3 y la falta de pruebas de las comprobaciones finales (I1) en una sola ronda. L1 queda aceptado (ver Pendientes).
- **Entorno de pruebas local:** `DOCKER_CONTEXT=default`; OpenBao con `docker compose` y PostgreSQL en un contenedor desechable con credenciales de prueba, igual que la CI, sin leer el `.env`.
- **TDD:** RED observado en cada cambio de comportamiento; de 462 a 488 pruebas (480 antes de las correcciones de la revisión).

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir a `.claude/settings.json` los comandos de prueba y lint de cada servicio nuevo (los del `gateway` ya están, issue #25).
- [ ] Verificar las versiones del resto del stack (React, workers, PostgreSQL, RabbitMQ, Vault) antes de fijarlas; las del `gateway` se verificaron en el issue #25.
- [ ] Revisar periódicamente las versiones de `uv`, gitleaks y actionlint fijadas por sha256 en CI: Dependabot no las actualiza (hallazgo del #25).
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [ ] **A3b:** recuperación asistida, arranque del primer administrador, procedimiento de emergencia, asignación pendiente de roles con privilegios y cambio de contraseña (ADR 0004, decisiones 10 y 11). Amenazas 45 a 47.
- [ ] Límite de frecuencia propio en `/mfa/enroll`, y desactivar el MFA o regenerar los códigos de recuperación (#39).
- [ ] **A3b:** un usuario con privilegios que ya existía sin MFA y sin fecha límite de alta no puede iniciar sesión ni darse de alta; se resuelve con la asignación pendiente de roles (revisión de Gentle AI del #39).
- [ ] Varias peticiones `/login/mfa` en paralelo con un token `mfa-pending` válido hacen su llamada a transit y su Argon2 a la vez, ya sin serializar; depende del límite de tasa por IP (E5) (L1 de la revisión del #43).
- [ ] Rotación de la clave transit `totp` con `rewrap` de los textos cifrados (ADR 0006).
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
- [x] **Issue #39 (PR #42, `28f63e8`):** MFA con TOTP y secreto cifrado con transit de OpenBao (ADR 0006).
- [x] **Issue #37:** purga de las tablas de sesión, reloj único para `tokens_valid_since` y logout que borra las cookies.
- [x] Normalización Unicode de contraseñas (NFC) y tiempo máximo del semáforo de Argon2id (pendientes del #29, cerrados en el #33).
- [x] **Issue #27 (PR #28):** `gateway` obligatorio en el ruleset (aplicado en GitHub el 2026-09-30 y verificado desde la API), documentación de la API desactivada por defecto y `httpx2`. ADR 0001 actualizado en el issue #29.
