# ADR 0004: Autenticación y autorización del gateway

## Estado

Aceptado, 2026-09-29.

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

Además, el modelo dejó dos decisiones pendientes que este ADR cierra: el
algoritmo y la audiencia de los JWT, y si el texto de búsqueda se guarda en la
auditoría.

El nivel objetivo de OWASP ASVS no estaba acordado. Se fija ASVS 5.0.0
(mayo de 2025, <https://github.com/OWASP/ASVS>): **L1 en todo el sistema y L2
en los capítulos V6 (Autenticación), V7 (Gestión de sesiones) y V8
(Autorización), más V9 (Tokens autocontenidos) para el JWT.** Los marcos son
referencias, no prueba de conformidad (AGENTS.md §8).

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

### Tiempos de sesión

1. **Un valor global de 4 a 8 horas.** Descartada: castiga al lector (poco
   riesgo) sin proteger más a los roles con privilegios (más riesgo).
2. **Tiempos por rol.** Elegida.

## Decisión

### 1. Token de sesión en cookie `__Host-`

- Cookie `__Host-` con `HttpOnly`, `Secure`, `SameSite=Strict` y `Path=/`
  (el prefijo exige además que no lleve `Domain`).
- Mismo origen entre la SPA y el gateway: no se configura CORS.
- En toda petición que cambie estado se exige un token anti-CSRF y una
  comprobación de `Origin` / `Sec-Fetch-Site`.
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
- Si otro servicio debe verificar tokens, se pasa a firma asimétrica
  mediante un ADR nuevo.

### 3. Vida del token, refresco y revocación

| Elemento | Decisión |
|---|---|
| Token de acceso (JWT) | Dura 15 minutos |
| Token de refresco | Opaco y aleatorio (CSPRNG, al menos 128 bits); solo se guarda su hash |
| Rotación | Se rota en cada uso |
| Reutilización de un refresco viejo | Revoca toda la familia de refrescos |
| Cierre de sesión | Borra el refresco y añade el `jti` del acceso a una lista de denegación hasta su expiración |
| Lista de denegación | Clave por `jti`, no por hash del token crudo (maleabilidad; guía de JWT de OWASP) |

La rotación con revocación de la familia sigue por analogía a RFC 9700
(BCP 240, enero de 2025, §2.2.2 y §4.14.2,
<https://www.rfc-editor.org/rfc/rfc9700>); no hay servidor OAuth externo, por
eso se aplica como criterio de diseño y no como cumplimiento del RFC.
La lista de denegación cumple ASVS 7.4.1 para tokens autocontenidos.

### 4. Contraseñas, bloqueo y errores

- **Hash:** Argon2id con `m=19456` (19 MiB), `t=2`, `p=1` como mínimo, fijados
  de forma explícita (guía de almacenamiento de contraseñas de OWASP,
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>).
- **Longitud:** mínimo 15 caracteres; se permiten 64 o más; cualquier carácter
  y **ninguna regla de composición**.
- **Lista de contraseñas comunes y filtradas:** local, sin enviar la
  contraseña a terceros. Su origen y licencia se verifican en E3.
- **Bloqueo progresivo por cuenta:** tras 3 fallos, espera de 1, 5, 15 y
  30 minutos en fallos sucesivos. La recuperación de contraseña sigue
  disponible durante el bloqueo. NIST admite como máximo 100 intentos fallidos
  consecutivos; este esquema queda muy por debajo.
- **Límite por IP:** lo aplica el Ingress, y el gateway solo confía en la
  cabecera `X-Forwarded-For` que añade el proxy de confianza (amenaza 38).
- **Errores genéricos y tiempo constante:** el login devuelve siempre el
  mismo mensaje («Login failed; Invalid user ID or password», según la guía de
  autenticación de OWASP) y tarda lo mismo exista o no el usuario. El requisito
  6.3.8 es de nivel L3, así que esto es un refuerzo voluntario.

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
| Borrar o purgar el registro de auditoría | No | No | No | No (solo el rol dedicado de purga) |
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
- El primer administrador se crea al arrancar con credenciales que salen de
  Vault; no hay registro público de administradores.

### 6. Registro de auditoría de búsquedas

Cada registro guarda: UUID del usuario, fecha y hora, acción, resultado,
número de resultados e IP truncada. **No guarda el texto de la búsqueda**, que
puede revelar intereses o datos personales (amenaza 39). La retención es de
180 días y la purga la hace un rol dedicado, no el administrador.

### 7. Nivel objetivo de ASVS

ASVS 5.0.0: L1 en todo el sistema; L2 en V6, V7 y V8; V9 para el JWT. Esto
cierra el pendiente «elegir el nivel objetivo de OWASP ASVS». Es un objetivo
de trabajo, no una declaración de conformidad.

### 8. MFA con TOTP

- TOTP obligatorio para editor, auditor y administrador; opcional para el
  lector. Un rol con privilegios no puede operar sin MFA activo.
- Los códigos de recuperación se guardan con hash.
- El secreto TOTP se guarda cifrado. El mecanismo (transit de Vault o cifrado
  de aplicación) se decide junto con el ADR de red y criptografía.
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

### Bibliotecas verificadas (PyPI, 2026-09-29)

| Biblioteca | Versión | Licencia / mantenedor | Nota |
|---|---|---|---|
| PyJWT | 2.15.1 (2026-09-28) | MIT, jpadilla | El aviso GHSA-ffc3-869f-jxw9 (crítico, corregido en 2.14.0) no afecta a HS256 con secreto aleatorio que no sea PEM y una lista de un solo algoritmo. Ver reglas de uso en la decisión 2 |
| argon2-cffi | 25.1.0 (2025-06-03) | MIT, Hynek Schlawack | Parámetros explícitos, al menos los valores de OWASP |
| pyotp | 2.10.0 (2026-06-14) | MIT, pyauth/pyotp | Solo TOTP |

Descartada: `python-jose` 3.5.0. Las CVE-2024-33663 y CVE-2024-33664 afectan a
versiones hasta 3.3.0; su estado de mantenimiento es **NO VERIFICADO**. Las
versiones se fijan en el lockfile y las vigilan Dependabot y el análisis SCA.

### Trazabilidad

| Decisión | Requisitos ASVS 5.0.0 | Amenazas |
|---|---|---|
| 1. Cookie `__Host-` y anti-CSRF | 7.2.3, 7.2.4 | 36, 1 |
| 2. JWT HS256 | 9.1.1, 9.1.2, 9.1.3, 9.2.1, 9.2.3 | 1 |
| 3. Vida, refresco y revocación | 7.2.3, 7.2.4, 7.4.1 | 35, 1 |
| 4. Contraseñas y bloqueo | 6.1.1, 6.2.1, 6.2.4, 6.2.5, 6.2.9, 6.2.12, 6.3.1, 6.3.8 | 8, 38 |
| 5. Roles y autorización | 8.1.1, 8.2.1, 8.2.2, 8.3.1 | 2, 37, 21 |
| 6. Auditoría de búsquedas | (sin requisito ASVS citado aquí) | 4, 39 |
| 7. Nivel objetivo | (marco general) | (todas las anteriores) |
| 8. MFA con TOTP | (refuerza V6; sin ID citado) | 8, 1, nuevas (ver Consecuencias) |
| 9. Tiempos de sesión | 7.3.1, 7.3.2, 7.4.5 | 35, 1 |

Estado de los requisitos: ninguno está implementado todavía (no hay código).
6.2.12 queda **pendiente** hasta elegir la lista de contraseñas filtradas.
Todos los demás quedan «planeados».

## Consecuencias

**Positivas**

- Las nueve decisiones cierran las amenazas 1, 8, 35, 36 y 37 a nivel de
  diseño y dan base a los controles de 2, 4, 38 y 39; cada una queda ligada a
  una prueba en E3.
- Sin reglas de composición ni bloqueo fijo: alineado con NIST y ASVS, y sin
  regalar una denegación de servicio por cuenta.
- El token de sesión no es legible por JavaScript.
- Un solo algoritmo de firma y una sola parte que firma y verifica: menos
  superficie de ataque.

**Negativas y riesgos aceptados**

- El MFA añade alcance a E3: pantallas de alta y verificación, códigos de
  recuperación, pruebas y amenazas nuevas.
- La lista de denegación por `jti` añade una consulta por petición.
- La sesión de 7 días del lector supera el rango típico de OWASP. Se acepta
  porque el lector solo consulta noticias públicas; si el modelo cambia
  (datos personales, acciones sensibles), se revisa.
- El bloqueo progresivo mitiga la denegación de servicio por cuenta, pero no
  la elimina: un atacante puede seguir retrasando a un usuario concreto.
- El tiempo constante del login (6.3.8, L3) es un refuerzo y no se
  garantiza por completo.
- HS256 exige que la clave se proteja en Vault; su filtración permitiría
  falsificar tokens (amenaza 1). La rotación por `kid` limita el daño.

**Pendientes**

- Elegir y verificar en E3 una lista de contraseñas filtradas y su licencia;
  hasta entonces, 6.2.12 (L2) sigue pendiente.
- Decidir el cifrado del secreto TOTP (transit de Vault o cifrado de
  aplicación) junto con el ADR de red y criptografía.
- Añadir al modelo de amenazas: robo del secreto TOTP, abuso de los códigos
  de recuperación y disponibilidad de la lista de denegación por `jti`.
- Actualizar las mitigaciones de las amenazas 1, 2, 4, 8, 35, 36, 37, 38 y 39
  en el modelo.
