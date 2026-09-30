# Bitácora del proyecto

Registro de decisiones y estado. Claude Code lo lee al iniciar (importado desde CLAUDE.md). Actualízalo por PR.

## Historial

Las entradas de issues cerrados se mueven a `docs/bitacora/` para no superar el límite de instrucciones de Claude Code (issue #23). No se cargan en cada sesión; léelas cuando haga falta el detalle.

- [2026-09-27 a 2026-09-28](bitacora/2026-09-27_28.md): arranque, `guardia.sh` (issue #1, PR #3), protección de `main` (issue #4) y pruebas reales en CI (issue #9).
- Decisiones deliberadas que solo están en ese historial, y que no deben «arreglarse» sin revisarlo: `.env.example` no se puede leer con la herramienta Read (una regla `allow` no puede exceptuar una `deny`; issue #1, PR #12) y el detalle de cobertura y rondas TDD de `guardia.sh` (los límites y falsos positivos aceptados también están en el ADR 0002).

## 2026-09-29 · Issue #15: E0, elección de la aplicación

Rama `docs/15-ficha-agregador`. Cierra la parte documental de E0: aplicación elegida, ficha, ADR y propuesta escrita.

- **Identix elegida y descartada el mismo día.** Su OSINT sobre personas reales exigía verificar la titularidad de cada identificador (OAuth, un código en la biografía), recoger consentimiento y borrar datos: una carga de protección de datos que superaba el alcance. Además, las plataformas sociales principales no ofrecen acceso legítimo y gratuito. Se renuncia a la bonificación de +1 punto, y la aplicación pasa a ser una propuesta propia que el profesor debe validar por escrito (sección 2 del enunciado).
- **Aplicación elegida: H4tt3r_1nf0rm4t1v0**, agregador de noticias y tendencias de medios colombianos y de habla hispana, con búsqueda por tema, agrupación por noticia y sentimiento. Solo se guardan titular, enlace, fecha y resumen corto.
- **Imágenes del enunciado restauradas** en `f834b9d` (`Logo.png`, `Arquitectura_IDENTIX.png`).
- **Verificación de fuentes (2026-09-29, investigación de solo lectura; los resúmenes de las herramientas son de segunda mano).** Incluidas: RCN y Semana (RSS), Caracol, Blu Radio y Citytv (sitemaps), YouTube Data API, Google Trends RSS (no oficial) y tendencias de Mastodon. Excluidas: X (sin nivel gratuito), Reddit (aprobación previa), CNN en Español (HTTP 451 y bloqueo a bots de IA), Facebook, Instagram y TikTok (sin acceso legítimo para este caso). Detalle, URL y elementos NO VERIFICADO en `docs/PROJECT_CONTEXT.md`.
- **Decisiones del usuario (2026-09-29):** (1) alojamiento en este repositorio, con el traslado a una rama del repositorio del curso como última tarea; (2) cuatro servicios desplegables, ADR 0003; (3) fuentes anteriores; (4) historia de usuario de la sustentación: búsqueda por tema; (5) licencia Apache 2.0, con la licencia del modelo de sentimiento declarada aparte; (6) K3s mediante k3d e IaC con Terraform; (7) Docker Hub `h4tt3rxplo1tt`.
- **Aviso de Docker Hub.** Existe una cuenta parecida, `h4tt3rxplo1t` (una sola t), que no está confirmada como del proyecto. Usar siempre el nombre exacto `h4tt3rxplo1tt` (riesgo de typosquatting) y publicar solo desde CI con un token de alcance mínimo.
- **Documentos añadidos:** sección de ficha en `docs/PROJECT_CONTEXT.md`, `docs/adr/0003-agrupacion-microservicios.md` y `docs/propuesta.md`.
- **Revisión de seguridad (revisor-seguridad):** listo para PR, sin hallazgos críticos, altos ni medios. Corregidos en esta rama: B1 (el `User-Agent` es propio y no suplanta a otro; una fuente que lo bloquee en `robots.txt` se desactiva) y B3 (la afirmación «sin datos personales de terceros» era demasiado fuerte: ahora dice «no se recogen como objetivo», y de Mastodon solo se usan etiquetas y enlaces en tendencia, porque `/trends/statuses` devuelve publicaciones y autores). B2, B5 y B6 pasan a pendientes de E1, E3 y E7. B4 (namespace de Docker Hub sin verificar) ya estaba resuelto: `h4tt3rxplo1tt` se comprobó en la API pública de Docker Hub y con la captura de la cuenta de la persona.
- **Decisiones posteriores al PR #16 (2026-09-29, persona):** la propuesta no se enviará al profesor por ahora (decisión propia, con el riesgo de que la aplicación no se acepte al final; sección 2 del enunciado). Los términos de uso de los 5 medios los revisó la persona y ninguno prohíbe el uso informativo con enlace. Se fija como regla la atribución: nombre del medio, autor cuando exista, fecha y enlace al original. En `docs/propuesta.md` el autor figura con el seudónimo público `H4TT3R_XPLO1T` (el mismo de la cuenta de GitHub), no con el nombre real, porque el repositorio es público.
- **Aprendizaje:** verificar el acceso a cada plataforma antes de comprometer el alcance. Identix se apoyaba en redes sociales cuyo acceso legítimo no existe o exige aprobaciones; comprobarlo al inicio habría ahorrado el desvío.

## 2026-09-29 · Issue #18: E1, modelo de amenazas

Rama `docs/18-modelo-amenazas`. Documento: [`docs/threat-model.md`](threat-model.md); guía de la herramienta: [`docs/architecture/guia-threat-dragon.md`](architecture/guia-threat-dragon.md); modelo: `docs/architecture/threat-model.json`.

- **Modelo.** La persona dibujó los dos DFD en OWASP Threat Dragon 2.6.2 (AppImage con SHA-512 verificado); el agente los ordenó y completó editando el JSON. Resultado: 42 amenazas STRIDE (S 7, T 11, R 2, I 10, D 7, E 5; severidad 17 altas, 22 medias, 3 bajas), todas «Abierta». 40 tienen un control y una verificación ligada a una herramienta o prueba (Semgrep, Bandit, ZAP, Trivy, gitleaks, Checkov, pruebas unitarias); las 2 del cifrado interno (28 y 29) quedan como decisión pendiente.
- **Mínimo privilegio.** Se usa la versión de escritorio sin acceso a GitHub: el modelo es un archivo local.
- **Cifrado dentro del clúster: decisión abierta.** Los flujos internos están marcados como no cifrados a propósito, para que la brecha siga visible; amenazas 28 y 29. Se resolverá en un ADR antes de E5.
- **Límite declarado.** El modelo cubre la aplicación; la cadena de suministro de CI/CD queda para E4/E7. Los PNG de los DFD los exporta la persona; hasta entonces las imágenes del documento están pendientes.
- **Lección del PR #16.** Antes de empujar más commits a la rama de un PR, comprobar que el PR sigue abierto (`gh pr view`). El PR #16 se fusionó antes de que llegaran dos commits; el push recreó la rama borrada; se recuperaron en el PR #17 con cherry-pick sobre una rama nueva, y la rama obsoleta se borró tras comprobar que su árbol era idéntico.

- **Revisión de seguridad (revisor-seguridad) del #18:** listo para PR, sin críticos ni altos. Se corrigieron sus 4 hallazgos medios antes del PR: el control de SSRF no era realizable (las NetworkPolicy nativas filtran por IP, no por dominio: pasa a proxy de salida o política por dominio, validación del host y sin descargar artículos); faltaban 12 amenazas (enlaces maliciosos en tendencias, deserialización en RabbitMQ, inyección en la consulta a YouTube, revocación de tokens, CSRF y CORS, IDOR, falseo de X-Forwarded-For, datos sensibles en logs, privilegios de contenedores, envenenamiento de datos y Vault en modo dev); la garantía de la auditoría estaba sobrevendida (protege frente al gateway, no frente al administrador de BD); y los flujos de Vault decían HTTPS sin cifrado (ahora HTTP hasta decidir TLS interno). Los hallazgos bajos quedaron como decisiones pendientes en `docs/threat-model.md` (algoritmo de los JWT, texto de búsqueda en la auditoría) o corregidos (referencias a B2 con contexto). Aprendizaje: pedir al revisor que evalúe la calidad del modelo, no solo secretos e inyección, encontró brechas reales de diseño.
- **Cierre:** PR #19 fusionado con squash como `2897863`; issue #18 cerrado.

## 2026-09-29 · Issue #20: ADR 0004, autenticación y autorización

Rama `docs/20-adr-autenticacion`. Documento: [`docs/adr/0004-autenticacion.md`](adr/0004-autenticacion.md).

- **Las decisiones 1 a 9 en una línea (la 10 y la 11 se añadieron tras la primera revisión):** (1) token en cookie `__Host-` con anti-CSRF; (2) JWT HS256 con clave en Vault y `kid`; (3) acceso de 15 min, refresco opaco rotado, revocación de la familia y lista de denegación por `jti`; (4) Argon2id, contraseña de al menos 15 caracteres sin reglas de composición, bloqueo progresivo y errores genéricos; (5) cuatro roles con denegación por defecto y separación de funciones; (6) auditoría de búsquedas sin el texto buscado, 180 días; (7) ASVS 5.0.0 con L1 general y L2 en V6, V7 y V8 (más V9); (8) MFA con TOTP obligatorio para roles con privilegios; (9) tiempos de sesión por rol.
- **La investigación verificó las fuentes primarias y cambió tres elecciones iniciales de la persona:** reglas de composición → longitud de 15; bloqueo fijo 3/30 → progresivo; mínimo de 12 → 15 más MFA. La persona decidió cada cambio tras ver la evidencia (ASVS 5.0.0, NIST SP 800-63B-4, guía de autenticación de OWASP).
- **Aprendizaje:** contrastar cada decisión con los estándares primarios antes de escribirla. Dos de las tres elecciones iniciales iban contra la recomendación vigente.
- **Bibliotecas verificadas en PyPI (2026-09-29):** PyJWT 2.15.1, argon2-cffi 25.1.0 y pyotp 2.10.0. Descartada: `python-jose` (CVE-2024-33663 y CVE-2024-33664). Los resúmenes de las herramientas son de segunda mano.
- **NO VERIFICADO:** el estado de mantenimiento de `python-jose`.
- **Revisión de seguridad (revisor-seguridad) del #20:** NO listo (3 hallazgos altos), corregidos. La recuperación de cuenta se diseñó asistida por un administrador (elección de la persona; sin correo ni egress, decisión 10). Se añadieron el alta del MFA y el arranque del primer administrador (decisión 11), y el registro pasó a cubrir eventos de seguridad (decisión 6). Los IDs de ASVS se corrigieron contra el texto oficial v5.0.0 (cookies y CSRF están en V3, no en V7) y se verificaron en GitHub los avisos de PyJWT (se exige ≥ 2.15.0). El ADR queda como «Propuesto» hasta que la persona fusione el PR.
- **Aprendizaje:** un ADR debe definir los flujos (recuperación, alta del MFA, arranque), no solo los parámetros.
- **Segunda revisión de seguridad (revisor-seguridad) del #20:** NO listo (1 alto y 3 medios introducidos por la reescritura), corregidos. Cambios: procedimiento de emergencia (break-glass) para el bloqueo con un solo administrador; periodo de gracia de 10 s eliminado en favor de un refresco de un solo vuelo en el frontend (la reutilización de un refresco rotado revoca siempre la familia); alta del MFA con solo contraseña (N3) y código de restablecimiento conocido por el administrador (N4) documentados como riesgos residuales aceptados, con sus mitigaciones; detalles de cookie `__Secure-refresh` y de CSRF (clave HMAC en Vault, token previo a la sesión en el login); destrucción de todas las versiones del secreto de arranque en Vault KV v2; trazabilidad de la decisión 9 corregida (7.3.1 y 7.3.2).
- **Aprendizaje:** cada mecanismo añadido debe contrastarse con los demás; la reescritura introdujo contradicciones.
- **Tercera revisión de seguridad (revisor-seguridad) del #20:** listo para PR; sus 3 observaciones menores se corrigieron (el arranque nunca se ejecuta con un administrador activo, el alcance `enroll-mfa` cubre solo el cambio de contraseña, el cierre de sesión acepta un acceso caducado con firma válida).
- **Cierre:** PR #21 fusionado con squash como `def4428`; issue #20 cerrado. El estado del ADR 0004 se cambió a «Aceptado» en el mantenimiento posterior de la bitácora.

## 2026-09-30 · Issue #23: contexto de instrucciones por debajo de 150k

Rama `docs/23-contexto-instrucciones`.

- **Problema.** Claude Code avisó al iniciar: los 5 archivos de instrucciones sumaban 170 380 bytes según `wc -c` (el aviso hablaba de 166,3k caracteres: las tildes ocupan 2 bytes), por encima del límite de 150 000. Los más grandes: `~/.claude/CLAUDE.md` (69 479), `docs/PROJECT_CONTEXT.md` (43 576) y esta bitácora (43 556).
- **Decisión: mover, no borrar.** El enunciado del curso (unos 28 800 bytes dentro de `PROJECT_CONTEXT.md`) pasa a `docs/enunciado.md`, y las entradas del 27 y 28 de septiembre, a `docs/bitacora/2026-09-27_28.md`. Ninguno de los dos se importa, así que se leen bajo demanda. `PROJECT_CONTEXT.md` conserva la ficha con un enlace al enunciado; esta bitácora conserva las entradas recientes, los pendientes y un índice de historial.
- **Sin cambios en `~/.claude/CLAUDE.md`.** Es global y lo gestiona gentle-ai: una sincronización sobrescribiría cualquier recorte.
- **Regla de rotación** añadida a `CLAUDE.md`: si la bitácora supera unos 20 000 bytes (`wc -c`), las entradas de issues cerrados se mueven a `docs/bitacora/`; los pendientes nunca se mueven.
- **Revisión de seguridad (revisor-seguridad):** listo para PR, sin críticos, altos ni medios. Se corrigieron sus 3 observaciones bajas: las cifras eran bytes de `wc -c` y no caracteres, el tamaño del enunciado estaba mal redondeado, y la decisión de `.env.example` solo quedaba en el historial (ahora el índice de Historial la señala).
- **Verificación.** Tras el cambio, los archivos cargados suman 115 109 bytes (`wc -c`), algo menos en caracteres. Al reconstruir cada archivo original con el texto movido, `diff` contra `main` no muestra diferencias. Las referencias a los dos archivos siguen siendo válidas: no cambian de nombre y ningún enlace con ancla apuntaba a las secciones movidas.

## Pendientes

### E3: primer flujo (búsqueda por tema) y autenticación
- [ ] **E3:** añadir los comandos de prueba y lint del stack a `.claude/settings.json` cuando exista el código.
- [ ] Verificar las versiones del stack (AGENTS.md §3) antes de fijarlas.
- [ ] **E3:** elegir y verificar una lista de contraseñas filtradas y su licencia (ASVS 6.2.12, L2, pendiente hasta entonces).
- [ ] **E3:** implementar el MFA con TOTP, la recuperación asistida y el arranque del primer administrador (ADR 0004, decisiones 8, 10 y 11), con sus pruebas. Las amenazas 43 a 47 ya están en el modelo.
- [ ] **E3:** implementar la renovación de sesión de un solo vuelo en el frontend.
- [ ] **E3:** antes de añadir `pysentimiento`, verificar nombre, mantenedor, licencia y actividad (AGENTS.md §3) y fijar el modelo de Hugging Face por hash de commit (riesgo de deserialización con `torch`) (hallazgo B5 del #15).

### E5: plataforma, red y cifrado
- [ ] ADR de cifrado dentro del clúster (TLS/mTLS para Vault, PostgreSQL y RabbitMQ), antes de E5.
- [ ] Decidir el mecanismo de cifrado del secreto TOTP (transit de Vault o cifrado de aplicación), junto con el ADR de red y criptografía (antes de E5).

### E4/E7: CI/CD y cadena de suministro
- [ ] Modelar la cadena de suministro de CI/CD (E4/E7).
- [ ] **E7:** referenciar las imágenes por digest, no solo por `vX.Y.Z` y `latest` (hallazgo B4 del #15).

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
