# ADR 0004: Autenticación y autorización del gateway

## Estado

Propuesto, 2026-09-29. Pasa a Aceptado cuando la persona responsable fusione el PR.

## Contexto

El `gateway` es la única API pública del sistema y concentra la autenticación,
los usuarios, la búsqueda y la auditoría ([ADR 0003](0003-agrupacion-microservicios.md)).
Un fallo aquí afecta a todo el sistema, y el enunciado exige JWT u OAuth2 con
control básico de roles (sección 3.1).

El [modelo de amenazas](../threat-model.md) deja abiertas las amenazas
directamente ligadas a este ADR:

| # | Amenaza | Tema |
|---|---|---|
| 1 | Suplantación con un JWT robado o falsificado | Firma y validación del token |
| 2 | Elevación de privilegios por concentración de funciones en el gateway | Roles, denegación por defecto |
| 4 | El lector niega haber realizado una acción | Auditoría |
| 8 | Fuerza bruta o relleno de credenciales en el login | Contraseñas y bloqueo |
| 35 | Tokens sin revocación ni rotación | Sesión y refresco |
| 36 | CSRF y CORS mal configurado | Transporte del token |
| 37 | Acceso a datos de otro usuario (IDOR) | Autorización por objeto |
| 38 | Falseo de X-Forwarded-For para esquivar límites por IP | Límite por IP |
| 39 | Datos sensibles o inyección en los logs | Auditoría y logs |
| 43 | Robo del secreto TOTP | MFA |
| 44 | Fuerza bruta del TOTP o abuso de los códigos de recuperación | MFA |
| 45 | Lista de tokens anulados no disponible | Revocación |
| 46 | Abuso de la recuperación asistida o toma de control mediante el restablecimiento del MFA | Recuperación de cuenta |
| 47 | Credencial de arranque convertida en puerta trasera | Primer administrador |

Además, el modelo dejó dos decisiones pendientes que este ADR cierra: el
algoritmo y la audiencia de los JWT, y si el texto de búsqueda se guarda en la
auditoría.

El nivel objetivo de OWASP ASVS no estaba acordado. Se fija ASVS 5.0.0
(mayo de 2025, <https://github.com/OWASP/ASVS>, etiqueta v5.0.0): **L1 en todo
el sistema; L2 en V3.3 y V3.5 (cookies y CSRF), V6 (Autenticación), V7
(Gestión de sesiones), V8 (Autorización) y V9 (Tokens autocontenidos) para el
JWT; y L2 en los requisitos de eventos de seguridad de V16 (16.2.1, 16.2.2,
16.2.5, 16.3.1 y 16.3.2).** V3.3 y V3.5 forman parte de «sesiones», que la
persona ya había ubicado en L2; los requisitos de V16 se derivan de la
decisión 6. Los marcos son referencias, no prueba de conformidad (AGENTS.md
§8). Ningún requisito está implementado todavía.

Las fuentes se consultaron el 2026-09-29. Los resúmenes de las herramientas
de investigación son de segunda mano: las citas se presentan como paráfrasis
salvo que se marquen como literales.

## Opciones consideradas

### Transporte del token de sesión

1. **Cookie `__Host-` con HttpOnly, Secure y SameSite=Strict.** Elegida. Un
   script inyectado (XSS) no puede leer el token. La guía de gestión de
   sesiones de OWASP recomienda esos atributos y el prefijo `__Host-`, y
   desaconseja guardar tokens en `localStorage`
   (<https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>).
2. **Cabecera `Authorization` con el token en JavaScript.** Descartada: el
   token quedaría al alcance de cualquier XSS, y las fuentes externas son
   entrada no confiable en este proyecto. Evita el CSRF, pero cambia un riesgo
   por otro peor.

Con cookie reaparece el CSRF. SameSite no lo sustituye: según la guía de
prevención de CSRF de OWASP (literal), «SameSite is useful as a defense-in-depth
control but it does not replace a proper CSRF defense in most deployments»
(<https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>).
Por eso se añade un token anti-CSRF (ver la decisión 1).

### Firma del JWT

1. **HS256 con clave aleatoria en Vault.** Elegida: solo el `gateway` firma y
   verifica, así que no hace falta compartir una clave pública. Es más simple
   y no hay confusión entre algoritmos si se fija uno.
2. **ES256 o EdDSA (asimétrico).** Descartada por ahora: solo aporta valor si
   otro servicio debe verificar tokens sin poder firmarlos. Si eso ocurre, se
   cambia mediante un ADR nuevo.

### Reglas de composición de la contraseña

La persona pidió inicialmente reglas de composición (mayúsculas, números y
símbolos) y cambió de decisión al ver la evidencia: ASVS 5.0.0, requisito
6.2.5 (literal): «There must be no requirement for a minimum number of upper or
lower case characters, numbers, or special characters.» NIST SP 800-63B-4
(final, 2025-08-26,
<https://pages.nist.gov/800-63-4/sp800-63b.html>) dice, literal: «Verifiers and
CSPs SHALL NOT impose other composition rules (e.g., requiring mixtures of
different character types) for passwords.»

1. **Reglas de composición.** Descartada: los estándares vigentes las
   desaconsejan y empujan a contraseñas previsibles.
2. **Política de longitud, sin composición, con lista de contraseñas
   comunes.** Elegida.

### Bloqueo por intentos fallidos

La persona eligió primero un bloqueo fijo (3 intentos, 30 minutos) y cambió
tras ver la advertencia de la guía de autenticación de OWASP: un bloqueo por
cuenta permite a un atacante dejar fuera a otros usuarios (denegación de
servicio) (<https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>).

1. **Bloqueo fijo 3/30.** Descartada: bloquear a un usuario legítimo durante
   30 minutos con solo fallar tres veces es demasiado fácil de provocar.
2. **Bloqueo progresivo con recuperación disponible.** Elegida.

### Longitud mínima y segundo factor

1. **Mínimo de 12 caracteres, sin segundo factor.** Descartada. NIST
   SP 800-63B-4 pide (paráfrasis) mínimo 15 con un solo factor y 8 con MFA;
   ASVS 6.2.1 pide al menos 8 y recomienda 15.
2. **Mínimo de 15 más MFA.** Elegida (la persona cambió de 12 a 15 más MFA
   tras ver esa evidencia).

### Alcance del MFA

1. **MFA para todos los usuarios.** Descartada: añade fricción en una demo
   pública, donde el lector solo consulta noticias.
2. **MFA obligatorio para los roles con privilegios y opcional para el
   lector.** Elegida.

### Recuperación de cuenta

Sin recuperación, el bloqueo progresivo y el MFA dejarían a los usuarios sin
acceso. La persona eligió el 2026-09-29 la opción 2 para mantener el gateway
sin salida a internet (ADR 0003).

| Opción | Ventajas | Inconvenientes |
|---|---|---|
| 1. Enlace por correo | Autoservicio, sin intervención humana | El gateway necesitaría salida a un servidor de correo (un componente de egress nuevo); el correo pasa a ser un factor que hay que proteger |
| 2. Asistida por un administrador (elegida) | Sin egress; identidad verificada por una persona | Más lenta; depende de que haya un administrador disponible |

### Tiempos de sesión

1. **Un valor global de 4 a 8 horas.** Descartada: castiga al lector (poco
   riesgo) sin proteger más a los roles con privilegios (más riesgo).
2. **Tiempos por rol.** Elegida.

## Decisión

### 1. Token de sesión en cookie `__Host-`

- Cookie de acceso `__Host-access` con `HttpOnly`, `Secure`, `SameSite=Strict`
  y `Path=/` (el prefijo exige además que no lleve `Domain`). Ver decisión 3
  para la cookie de refresco (ASVS 3.3.1, 3.3.2, 3.3.3, 3.3.4).
- Mismo origen entre la SPA y el gateway: no se configura CORS.
- **Token anti-CSRF de doble envío firmado y ligado a la sesión** (patrón de
  OWASP): el gateway genera un token aleatorio y lo combina mediante HMAC con
  el identificador de sesión (`sid`, el de la familia de refresco). Se envía
  en una cookie legible `__Host-csrf` y debe repetirse en la cabecera
  `X-CSRF-Token` en todo `POST`, `PUT`, `PATCH` y `DELETE`; el gateway
  verifica el HMAC y la coincidencia (3.5.1).
- Ningún cambio de estado usa `GET` (3.5.3).
- Se exige `Sec-Fetch-Site: same-origin` o, si falta, que `Origin` coincida
  con el origen de la aplicación. Si faltan ambas cabeceras en una petición
  que cambia estado, se rechaza (falla cerrado).
- No se guarda ningún token en `localStorage`.

### 2. JWT firmado con HS256

- HS256 con una clave aleatoria de al menos 256 bits guardada en Vault
  (OWASP, guía de JWT: la clave HMAC debe tener al menos el tamaño del hash).
- Algoritmo fijado en código: `algorithms=["HS256"]`; se rechaza `none`
  (RFC 8725 §3.1, <https://www.rfc-editor.org/rfc/rfc8725>).
- Se validan `exp`, `iss` y `aud` (contra una lista de audiencias permitidas)
  en cada petición. El identificador `kid` permite rotar la clave.
- Reglas de uso de PyJWT: el diccionario `options` se construye en cada
  llamada y no se reutiliza (GHSA-gvp8-978c-rx2q); nunca se usa
  `verify_signature=False`.
- Holgura (`leeway`) de 30 s para `exp` y `nbf`; los nodos se sincronizan por
  NTP y usan UTC.
- Rotación de la clave: cada 90 días y de inmediato ante sospecha de
  compromiso. Tras rotar el `kid`, la clave anterior se conserva al menos
  15 minutos más la holgura, para que los accesos vigentes sigan siendo
  válidos.
- Si otro servicio debe verificar tokens, se pasa a firma asimétrica
  mediante un ADR nuevo.

### 3. Vida del token, refresco y revocación

| Elemento | Decisión |
|---|---|
| Token de acceso (JWT) | Dura 15 minutos; va en `__Host-access` (`Path=/`) y lleva `sid` |
| Token de refresco | Opaco y aleatorio (CSPRNG, al menos 128 bits, ASVS 7.2.3); solo se guarda su hash. Va en la cookie `__Secure-refresh` con `Path=/api/auth/refresh` (un `__Host-` exige `Path=/`, así que el refresco usa `__Secure-`, permitido por 3.3.1) |
| Familia de refresco | Guarda `created_at` (límite absoluto por rol) y `last_used_at` (límite de inactividad por rol). El refresco se rechaza si se supera cualquiera de los dos, así el límite de inactividad se aplica aunque el acceso dure 15 minutos |
| Rotación | Se rota en cada uso |
| Reutilización de un refresco viejo | Revoca toda la familia, salvo la gracia de 10 s |
| Gracia de 10 s | Si el refresco inmediatamente anterior se reutiliza en menos de 10 s (dos pestañas o un reintento de red), se devuelve el sucesor ya emitido en vez de revocar. Fuera de esa ventana, la reutilización revoca la familia |
| Nueva sesión al autenticar | Cada login emite tokens y `sid` nuevos (7.2.4) |
| Cierre de sesión | Borra el refresco y añade el `jti` del acceso a una lista de denegación hasta su expiración |
| Lista de denegación | Clave por `jti`, no por hash del token crudo (maleabilidad; guía de JWT de OWASP) |
| Vinculación a dispositivo | **No implementada**; la protección es la cookie `HttpOnly` |

La rotación con revocación de la familia sigue por analogía a RFC 9700
(BCP 240, enero de 2025, §2.2.2 y §4.14.2,
<https://www.rfc-editor.org/rfc/rfc9700>); no hay servidor OAuth externo, por
eso se aplica como criterio de diseño y no como cumplimiento del RFC.
La lista de denegación planea cumplir ASVS 7.4.1 para tokens autocontenidos.
El gateway verifica cada token en el backend (7.2.1).

### 4. Contraseñas, bloqueo y errores

- **Hash:** Argon2id con `m=19456` (19 MiB), `t=2`, `p=1` como mínimo, fijados
  de forma explícita (guía de almacenamiento de contraseñas de OWASP,
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>).
- **Longitud:** mínimo 15 caracteres; se permiten 64 o más; cualquier carácter
  y **ninguna regla de composición**.
- **Lista de contraseñas comunes y filtradas:** local, sin enviar la
  contraseña a terceros. Su origen y licencia se verifican en E3.
- **Bloqueo progresivo por cuenta:** tras 3 fallos, espera de 1, 5, 15 y
  30 minutos en fallos sucesivos. La recuperación asistida (decisión 10)
  sigue disponible durante el bloqueo. NIST admite como máximo 100 intentos
  fallidos consecutivos; este esquema queda muy por debajo.
- **Contadores:** también existen para usuarios inexistentes (tabla aparte
  con TTL), de modo que el comportamiento no revele qué cuentas existen. Se
  reinician tras un login correcto. Los fallos de MFA cuentan para el
  bloqueo progresivo.
- **Límite por IP:** lo aplica el Ingress, y el gateway solo confía en la
  cabecera `X-Forwarded-For` que añade el proxy de confianza (amenaza 38).
- **Errores genéricos y tiempo constante:** el login devuelve siempre el
  mismo mensaje («Login failed; Invalid user ID or password», según la guía de
  autenticación de OWASP) y tarda lo mismo exista o no el usuario. La
  respuesta es idéntica (mismo cuerpo, estado 401 y tiempo similar) para una
  cuenta bloqueada, un usuario inexistente y unas credenciales erróneas. El
  429 se usa solo para el límite por IP. El requisito 6.3.8 es de nivel L3,
  así que esto es un refuerzo voluntario.
- **Reglas del TOTP:** ventana de ±1 paso; el mismo código no se acepta dos
  veces (6.5.1); vida de 30 s (6.5.5); la hora del servidor viene de NTP
  (6.5.8, refuerzo L3).

### 5. Roles y autorización

Cuatro roles, con denegación por defecto (ASVS 8.1.1: las reglas quedan
documentadas aquí), comprobación de propiedad por objeto y UUID como
identificadores. La autorización se aplica en el servicio del gateway, nunca
solo en el frontend (ASVS 8.3.1).

| Permiso | lector | editor | auditor | administrador |
|---|---|---|---|---|
| Buscar y leer resultados | Sí | Sí | Sí | Sí |
| Gestionar sus propios temas favoritos | Sí | Sí | Sí | Sí |
| Activar o desactivar fuentes ya existentes y ajustar su frecuencia de consulta | No | Sí | No | No |
| Añadir dominios nuevos a la lista de salida | No | No | No | No (solo mediante un PR revisado en el repositorio) |
| Leer y exportar el registro de auditoría | No | No | Sí | No |
| Borrar o purgar el registro de auditoría | No | No | No | No (solo el CronJob de purga, que no es un rol humano; ver decisión 6) |
| Gestionar usuarios y roles | No | No | No | Sí |
| Desbloquear cuentas y terminar sesiones de otros usuarios | No | No | No | Sí |

Reglas de separación de funciones (decisión propia: no se encontró un
requisito explícito de separación de funciones en el capítulo V8 de ASVS):

- Nadie añade dominios desde la aplicación, tampoco el administrador: la lista
  de salida es el control contra SSRF (amenaza 21) y solo cambia con un PR
  revisado. El editor solo gestiona las fuentes que ya están en la lista.
- El administrador no edita fuentes: gestiona personas, no contenido.
- Un administrador no puede ser también auditor ni asignarse ese rol, y no
  puede leer ni borrar el registro de auditoría.
- El primer administrador se crea con el procedimiento de arranque de la
  decisión 11; no hay registro público de administradores.

Verificación y revocación por usuario:

- El rol viaja en el JWT, pero se **vuelve a comprobar en la base de datos**,
  junto con el estado de la cuenta, en cada endpoint de editor, auditor y
  administrador.
- Cada usuario tiene una marca `tokens_valid_since`. Se rechazan los tokens
  cuyo `iat` sea anterior, y se comprueba en la misma consulta que la lista
  de denegación por `jti`. Se actualiza al cambiar el rol, deshabilitar la
  cuenta (7.4.2), restablecer la contraseña, restablecer el MFA, cuando un
  administrador termina las sesiones del usuario (7.4.5) y cuando el propio
  usuario elige «cerrar las demás sesiones» tras cambiar su contraseña
  (7.4.3).
- Ventana aceptada: ninguna para estos eventos, porque la consulta se hace en
  cada petición.

### 6. Registro de eventos de seguridad

- **Búsquedas:** cada registro guarda UUID del usuario, fecha y hora, acción,
  resultado, número de resultados e IP truncada. **No guarda el texto de la
  búsqueda**, que puede revelar intereses o datos personales (amenaza 39). La
  retención es de 180 días.
- **Eventos de seguridad:** login correcto y fallido (16.3.1); alta, éxito y
  fallo del MFA; bloqueos; códigos de recuperación emitidos y usados;
  restablecimientos de contraseña y de MFA; cambios de rol; desbloqueos de
  cuenta; terminaciones de sesión; activación o desactivación de fuentes; e
  intentos de autorización fallidos (16.3.2).
- Cada registro lleva hora en UTC, quién, qué, el valor anterior y el nuevo
  cuando aplique, e IP truncada (16.2.1, 16.2.2).
- Nunca se registran contraseñas, tokens, códigos TOTP, códigos de
  recuperación ni texto de búsqueda (16.2.5).
- **Principal de purga:** no es un rol de usuario. Es un CronJob de
  Kubernetes con su propio rol de base de datos (solo `DELETE` sobre
  registros de auditoría de más de 180 días) y credenciales de Vault; ninguna
  persona inicia sesión con él. Queda fuera de los cuatro roles humanos.

### 7. Nivel objetivo de ASVS

ASVS 5.0.0: L1 en todo el sistema; L2 en V3.3 y V3.5, V6, V7 y V8; V9 para el
JWT; y L2 en 16.2.1, 16.2.2, 16.2.5, 16.3.1 y 16.3.2. Esto cierra el
pendiente «elegir el nivel objetivo de OWASP ASVS». Es un objetivo de
trabajo, no una declaración de conformidad.

### 8. MFA con TOTP

- TOTP obligatorio para editor, auditor y administrador; opcional para el
  lector. Un rol con privilegios no puede operar sin MFA activo (el alta y el
  arranque están en la decisión 11).
- El secreto TOTP y los códigos de recuperación salen de un CSPRNG (6.5.3).
  Los códigos de recuperación se guardan con hash (6.5.2) y son de un solo
  uso (6.5.1).
- El secreto TOTP se guarda cifrado. El mecanismo (transit de Vault o cifrado
  de aplicación) se decide junto con el ADR de red y criptografía.
- Reglas de verificación: decisión 4.
- Biblioteca: `pyotp` 2.10.0 (2026-06-14, licencia MIT, `pyauth/pyotp`).

### 9. Tiempos de sesión por rol

| Rol | Inactividad | Duración absoluta | Al expirar |
|---|---|---|---|
| lector | 24 horas | 7 días | Nuevo login |
| editor, auditor, administrador | 30 minutos | 8 horas | Nuevo login más MFA |

Los tiempos de los roles con privilegios están dentro del rango de la guía
de sesiones de OWASP (inactividad de 2 a 30 minutos según el riesgo;
duración absoluta típica de 4 a 8 horas). El del lector queda **fuera** de ese
rango típico: es una decisión de riesgo documentada (ver Consecuencias).

### 10. Recuperación de cuenta asistida

- El usuario pide ayuda con un formulario que responde igual exista o no la
  cuenta, o por un canal externo documentado.
- Un administrador verifica la identidad fuera de banda y genera un **código
  de restablecimiento de un solo uso**: CSPRNG, al menos 16 caracteres
  alfanuméricos aleatorios, guardado con hash, vence en 15 minutos y se usa
  una sola vez (6.4.1). El administrador nunca ve ni elige la contraseña nueva
  (6.4.6, refuerzo L3).
- El usuario introduce el código y una contraseña nueva que cumpla la
  política. Si la cuenta tiene un rol con privilegios o el MFA activo, se
  exige además un TOTP o un código de recuperación: el restablecimiento no
  esquiva el MFA (6.4.3).
- Tras el restablecimiento se actualiza `tokens_valid_since` (se revocan todas
  las sesiones), se reinician los contadores de bloqueo y se registra el
  evento.
- **MFA perdido en una cuenta con privilegios (6.4.4):** el restablecimiento
  del MFA exige la aprobación de **dos administradores distintos**, ninguno de
  ellos el usuario afectado, con la identidad verificada fuera de banda. Se
  registra y el auditor puede verlo. Si solo existe un administrador, se usa
  el procedimiento de arranque de la decisión 11.
- Sin preguntas secretas ni pistas de contraseña (6.4.2).
- La recuperación por correo de autoservicio queda como ADR futuro: requeriría
  un componente con salida a internet.

### 11. Alta del MFA y arranque del primer administrador

- **Alta del MFA:** cuando un usuario que debe tener MFA inicia sesión sin él,
  el gateway emite una sesión limitada con alcance `enroll-mfa`, válida
  10 minutos y utilizable solo en los endpoints de alta. El secreto sale de un
  CSPRNG (6.5.3), se muestra **una sola vez** (QR y texto) y se guarda cifrado
  (mecanismo pendiente). Solo queda activo cuando el usuario demuestra un
  código válido. Entonces se muestran una sola vez 10 códigos de
  recuperación de 12 caracteres en base32, agrupados como XXXX-XXXX-XXXX, de un
  solo uso y guardados con hash Argon2id (6.5.1, 6.5.2).
- **Asignar un rol con privilegios a un usuario sin MFA** deja la asignación
  pendiente. Se hace efectiva solo tras el alta del MFA; hasta entonces el
  usuario tiene permisos de lector.
- **Arranque del primer administrador:** un Job de Kubernetes de una sola
  ejecución lee de Vault una contraseña de arranque de un solo uso (aleatoria,
  al menos 20 caracteres, cumple la política, válida 24 horas) y crea el
  administrador marcado `must_change_password` y `must_enroll_mfa`. En el
  primer login, el cambio de contraseña y el alta del MFA son obligatorios
  antes de cualquier otra acción. Después el Job borra el secreto de arranque
  de Vault y se niega a ejecutarse si ya existe un administrador. No hay
  ninguna credencial de administrador estática permanente (6.4.1).

### Bibliotecas verificadas (PyPI, 2026-09-29)

| Biblioteca | Versión | Licencia / mantenedor | Nota |
|---|---|---|---|
| PyJWT | ≥ 2.15.0; se elige 2.15.1 (2026-09-28) | MIT, jpadilla | Verificado en GitHub el 2026-09-29: GHSA-ffc3-869f-jxw9 (crítico), GHSA-9j54-fg26-wv3r, GHSA-p4g4-x82p-q773 y GHSA-9v7f-9g4p-ffgj (altos), GHSA-hxm8-2xgr-2p9m, GHSA-8wjv-2p76-3863, GHSA-w6j9-cwv2-h6wq y GHSA-gvp8-978c-rx2q afectan a ≤ 2.13.0 y se corrigen en 2.14.0; GHSA-42vr-xj54-vc7v y GHSA-x33g-cr3x-6449 afectan a ≤ 2.14.0 y se corrigen en 2.15.0. La versión elegida queda fuera de todos los rangos afectados listados. Reglas de uso en la decisión 2 |
| argon2-cffi | 25.1.0 (2025-06-03) | MIT, Hynek Schlawack | Parámetros explícitos, al menos los valores de OWASP |
| pyotp | 2.10.0 (2026-06-14) | MIT, pyauth/pyotp | Solo TOTP, con las reglas de la decisión 4 |

Descartada: `python-jose` 3.5.0. Las CVE-2024-33663 y CVE-2024-33664 afectan a
versiones hasta 3.3.0; su estado de mantenimiento es **NO VERIFICADO**. Las
versiones se fijan en el lockfile y las vigilan Dependabot y el análisis SCA.

### Trazabilidad

| Decisión | Requisitos ASVS 5.0.0 | Amenazas |
|---|---|---|
| 1. Cookie `__Host-` y anti-CSRF | 3.3.1, 3.3.2, 3.3.3, 3.3.4, 3.5.1, 3.5.3 | 36, 1 |
| 2. JWT HS256 | 9.1.1, 9.1.2, 9.1.3, 9.2.1, 9.2.3 | 1 |
| 3. Vida, refresco y revocación | 7.2.1, 7.2.3 (el refresco es un token de referencia), 7.2.4, 7.4.1, 7.4.3 | 35, 1, 45 |
| 4. Contraseñas y bloqueo | 6.1.1, 6.2.1, 6.2.4, 6.2.5, 6.2.9, 6.2.12, 6.3.1, 6.3.8, 6.5.1, 6.5.5, 6.5.8 | 8, 38, 44 |
| 5. Roles y autorización | 8.1.1, 8.2.1, 8.2.2, 8.3.1, 7.4.2, 7.4.5 | 2, 37, 21 |
| 6. Registro de eventos de seguridad | 16.2.1, 16.2.2, 16.2.5, 16.3.1, 16.3.2 | 4, 39 |
| 7. Nivel objetivo | (marco general) | (todas las anteriores) |
| 8. MFA con TOTP | 6.5.1, 6.5.2, 6.5.3, 6.5.5, 6.5.8 | 8, 1, 43, 44 |
| 9. Tiempos de sesión | 7.3.1, 7.3.2, 7.4.5 | 35, 1 |
| 10. Recuperación asistida | 6.4.1, 6.4.2, 6.4.3, 6.4.4, 6.4.6, 7.4.3 | 46, 8 |
| 11. Alta del MFA y primer administrador | 6.4.1, 6.5.3, 6.5.1, 6.5.2 | 47, 43, 46 |

Estado de los requisitos: ninguno está implementado todavía (no hay código).
6.2.12 queda **pendiente** hasta elegir la lista de contraseñas filtradas.
Todos los demás quedan «planeados»: el diseño da base a los controles de estos
requisitos y su cumplimiento se comprobará con pruebas en E3.

## Consecuencias

**Positivas**

- Las once decisiones dan base a los controles de las amenazas 1, 8, 35, 36 y
  37 a nivel de diseño, y a los de 2, 4, 38, 39 y 43 a 47; cada una queda
  ligada a una prueba en E3.
- Sin reglas de composición ni bloqueo fijo: alineado con NIST y ASVS, y sin
  regalar una denegación de servicio por cuenta.
- El token de sesión no es legible por JavaScript.
- Un solo algoritmo de firma y una sola parte que firma y verifica: menos
  superficie de ataque.
- Los flujos de recuperación, alta del MFA y arranque están definidos, no solo
  sus parámetros, y no hay credencial de administrador permanente.

**Negativas y riesgos aceptados**

- El MFA añade alcance a E3: pantallas de alta y verificación, códigos de
  recuperación, pruebas y amenazas nuevas.
- La lista de denegación por `jti` y la comprobación de `tokens_valid_since`
  y del rol añaden consultas por petición.
- La recuperación asistida es más lenta y depende de que haya un
  administrador disponible.
- El restablecimiento del MFA con cuatro ojos exige al menos dos
  administradores en operación.
- La sesión de 7 días del lector supera el rango típico de OWASP. Se acepta
  porque el lector solo consulta noticias públicas; si el modelo cambia
  (datos personales, acciones sensibles), se revisa.
- El bloqueo progresivo mitiga la denegación de servicio por cuenta, pero no
  la elimina: un atacante puede seguir retrasando a un usuario concreto.
- El tiempo constante del login (6.3.8, L3) es un refuerzo y no se
  garantiza por completo.
- HS256 exige que la clave se proteja en Vault; su filtración permitiría
  falsificar tokens (amenaza 1). La rotación por `kid` limita el daño.
- Sin vinculación a dispositivo: un refresco robado desde el equipo del
  usuario sigue siendo utilizable hasta que se detecte su reutilización.

**Pendientes**

- Decidir el cifrado del secreto TOTP (transit de Vault o cifrado de
  aplicación) en el ADR de red y criptografía, antes de E5.
- Elegir y verificar en E3 una lista de contraseñas filtradas y su licencia;
  hasta entonces, 6.2.12 (L2) sigue pendiente.
- Recuperación por correo como opción futura (requeriría un componente con
  salida a internet y un ADR nuevo).
