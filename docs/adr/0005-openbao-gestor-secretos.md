# ADR 0005: OpenBao como gestor de secretos

## Estado

Propuesto, 2026-09-30 (issue #31). Pasa a Aceptado cuando la persona responsable fusione el PR.

Reemplaza la elección de «Vault» del [ADR 0003](0003-agrupacion-microservicios.md) y del [ADR 0004](0004-autenticacion.md). Las decisiones de esos ADR sobre qué secretos se guardan y cómo se usan siguen vigentes; cambia solo el producto que los guarda.

## Contexto

Los ADR 0003 y 0004 guardan en «Vault» los secretos de servicio: la clave de firma de los JWT (con `kid`), la clave HMAC del CSRF, las credenciales de la base de datos y la clave de la API de YouTube. El enunciado del curso pide «HashiCorp Vault OSS» con licencia MPL 2.0 (`docs/enunciado.md`, tabla de herramientas).

Comprobado el 2026-09-30:

- **HashiCorp Vault** usa la Business Source License 1.1 desde la versión 1.15, con IBM como licenciante. Fuente: el archivo `LICENSE` del repositorio `hashicorp/vault`, leído con `gh api`; versión más reciente v2.1.1. Permite el uso en producción siempre que no compita con la oferta de pago de IBM. No es software libre, y el «Vault OSS MPL 2.0» del enunciado ya no existe.
- **OpenBao** es la continuación con licencia MPL-2.0 del Vault libre, bajo la Linux Foundation, y es compatible con la API de Vault. Versión 2.7.0, publicada el 2026-09-23. La imagen `openbao/openbao:2.7.0` tiene el mismo digest (`sha256:71156a1c…1315`) en ghcr.io, quay.io y Docker Hub.

El inicio de sesión (A2) necesita ya las claves de JWT y CSRF, antes de que existan la plataforma (E5) y la seguridad en ejecución (E6).

## Opciones consideradas

1. **HashiCorp Vault (BSL 1.1).** La más documentada. Nuestro uso está permitido, pero contradice el requisito de licencia libre del enunciado y de la ficha.
2. **OpenBao (MPL-2.0).** Libre y compatible con la API. Tiene menos documentación y comunidad, y el cliente Python `hvac` no lo prueba oficialmente.
3. **Archivos montados o variables de entorno, sin gestor, hasta E5.** Es lo más simple, pero aplaza la gestión real de secretos y obliga a migrar después.
4. **OpenBao en modo dev.** Es lo más rápido, pero corresponde a la amenaza 42: todo en memoria, arranca desbloqueado y entrega un token root fijo.

## Decisión

La tomó la persona responsable el 2026-09-30:

1. **OpenBao 2.7.0** como gestor de secretos, con la imagen fijada por digest.
2. **Desde ya**, en desarrollo y en CI; no se espera a E5.
3. **Modo servidor** con almacenamiento integrado `raft` de un solo nodo en un volumen, nunca modo dev. OpenBao 2.7 ya no ofrece el almacenamiento `file` (el arranque falla con «unknown storage type file»).
4. **Inicialización de desarrollo** con un script local idempotente:
   - una sola parte de la clave de desbloqueo, guardada fuera del repositorio con permisos 0600;
   - KV v2 y AppRole habilitados;
   - claves aleatorias de al menos 256 bits;
   - el token root revocado al terminar, y comprobado: una consulta con él debe fallar después, o el script termina con error.
5. **Acceso del gateway** mediante AppRole, con una política de solo lectura sobre `secret/data/gateway/*`.
6. **Cliente** `hvac` 2.4.0 (Apache-2.0). Su compatibilidad con OpenBao se demuestra con pruebas de integración contra un OpenBao real. Si fallara, se sustituye por llamadas HTTP directas a los dos endpoints necesarios.

## Consecuencias

- **El enunciado y la ficha se cumplen:** el gestor de secretos es libre (MPL-2.0). En el informe hay que explicar por qué no se usa «Vault».
- **Los ADR 0003 y 0004 no se reescriben.** Donde dicen «Vault», se lee OpenBao, y el modelo de amenazas mantiene el nombre del componente con esta aclaración.
- **Riesgos de desarrollo aceptados:**
  - Una sola parte de la clave de desbloqueo, frente a las varias de un despliegue real.
  - El listener sin TLS, que depende del ADR de cifrado interno, pendiente antes de E5; el puerto solo se publica en 127.0.0.1.
  - Ninguno es válido fuera del entorno local ni de CI.
- **Pendientes:**
  - Llevar a OpenBao las credenciales de PostgreSQL.
  - Rotar las claves con el `kid`.
  - Elegir la autenticación en el clúster (método de Kubernetes, E5/E6).
  - Definir la custodia de la clave de desbloqueo en un entorno compartido.
- **Dependencias de terceros:** el cliente depende de `hvac` y de `requests`. La herramienta de análisis de dependencias (SCA, de E4) los vigilará.
