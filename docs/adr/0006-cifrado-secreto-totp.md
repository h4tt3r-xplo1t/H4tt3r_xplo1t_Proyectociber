# ADR 0006: cifrado del secreto TOTP con transit de OpenBao

## Estado

Aceptado, 2026-10-11: la persona responsable fusionó el PR #42 (`28f63e8`). Propuesto el 2026-10-05 (issue #39).

Concreta el punto que el [ADR 0004](0004-autenticacion.md) dejó pendiente en las decisiones 8 y 11 («el secreto TOTP se guarda cifrado; el mecanismo se decide junto con el ADR de red y criptografía»). Se adelanta a ese ADR porque el MFA (A3a) lo necesita ya. El resto del cifrado interno (TLS entre servicios) sigue pendiente.

## Contexto

Con el secreto TOTP de un usuario cualquiera puede generar sus códigos. Si la base de datos se filtra (una copia de seguridad, una inyección SQL o un acceso indebido), los secretos en claro anularían el segundo factor de todas las cuentas. Por eso el ADR 0004 exige guardarlo cifrado (ASVS 6.5.3 y 6.5.5).

El gateway ya usa OpenBao 2.7.0 ([ADR 0005](0005-openbao-gestor-secretos.md)) mediante AppRole, para leer las claves de JWT y CSRF. A diferencia de los códigos de recuperación, que se guardan con hash porque solo hay que compararlos, el secreto TOTP hay que poder recuperarlo para calcular el código esperado: se necesita cifrado reversible.

## Opciones consideradas

1. **Motor transit de OpenBao.** OpenBao cifra y descifra; la clave nunca sale de OpenBao. Trae versiones de clave, rotación y re-cifrado (`rewrap`). Cada alta y cada verificación de TOTP hace una llamada a OpenBao, así que el login con MFA depende de que OpenBao esté disponible. No añade dependencias: el cliente `hvac` ya está.
2. **Cifrado en la aplicación** (AES-256-GCM con una clave leída de OpenBao KV y guardada en memoria). El login no hace llamadas extra a OpenBao, pero añade la dependencia `cryptography`, obliga a escribir y mantener código criptográfico propio (nonces, formato, rotación) y deja la clave en la memoria del proceso del gateway.

## Decisión

La tomó la persona responsable el 2026-10-05: **opción 1, transit de OpenBao.**

- Clave de transit `totp`, de tipo `aes256-gcm96` y derivada (`derived=true`), creada por el script de inicialización de desarrollo junto con el resto de la configuración inicial.
- Cada cifrado y descifrado pasa como `context` el id del usuario, así que OpenBao usa una clave distinta para cada uno: un texto cifrado copiado a la fila de otro usuario no se descifra. Se añadió en la revisión de seguridad del #39.
- La política del gateway solo permite `update` sobre `transit/encrypt/totp` y `transit/decrypt/totp`: no puede leer, exportar ni rotar la clave, ni cifrar con otras claves.
- En la base de datos se guarda solo el texto cifrado de transit (`vault:v1:…`), nunca el secreto en base32.
- Cada operación usa un token de AppRole de vida corta que se revoca al terminar, como la lectura de claves del ADR 0005. Si OpenBao no responde, la operación falla cerrada con un 503 y un mensaje fijo, sin detalles.

## Consecuencias

- **Positivas:** la clave no sale nunca de OpenBao ni pasa por la memoria del gateway. Una filtración de la base de datos no expone secretos TOTP utilizables. La rotación de la clave y el re-cifrado los ofrece OpenBao, sin código propio.
- **Negativas:** OpenBao pasa a ser necesario en cada login con MFA y en cada alta. Si no está disponible, los usuarios con MFA no pueden iniciar sesión (falla cerrado). Cada operación cuesta tres llamadas a OpenBao (login de AppRole, cifrado o descifrado, revocación).
- **Riesgo aceptado en desarrollo:** el listener de OpenBao sigue sin TLS y publicado solo en 127.0.0.1 (ADR 0005). El texto en claro del secreto viaja a OpenBao dentro de la máquina. El TLS interno queda para el ADR de cifrado dentro del clúster.
- **Pendiente:** rotación periódica de la clave `totp` con `rewrap` de los textos cifrados existentes, junto con la rotación de las demás claves.
