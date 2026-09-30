# Ficha del proyecto

> El enunciado completo del curso (requisitos, entregables, informe, evaluación y la aplicación sugerida Identix) está en [`docs/enunciado.md`](enunciado.md). No se carga en cada sesión: léelo ante cualquier duda sobre requisitos o entregables.

# Ficha del proyecto: H4tt3r_1nf0rm4t1v0

Estado: E0 (Descubrimiento), decisiones del 2026-09-29. Las fuentes externas se verificaron el 2026-09-29 mediante investigación de solo lectura; los resúmenes de las herramientas son de segunda mano, así que lo que no se leyó de la fuente primaria se marca **NO VERIFICADO** (AGENTS.md §3).

## 1. Descripción y propósito

**H4tt3r_1nf0rm4t1v0** (slug técnico `h4tt3r-1nf0rm4t1v0`) es un agregador de las noticias más relevantes de medios colombianos y de habla hispana, más tendencias, con búsqueda por tema. Los resultados se agrupan por noticia entre medios y llevan una etiqueta de sentimiento (positivo, negativo o neutral).

Principio de diseño: se guarda solo el titular, el enlace, la fecha y un resumen corto (nunca el artículo completo); se respetan `robots.txt` y los términos de uso; el bot se identifica con un `User-Agent` propio que no suplanta a ningún navegador ni a otro bot; solo se usa acceso gratuito y legítimo; no se recogen datos personales como objetivo (un titular puede nombrar a personas públicas, pero no se perfila a nadie).

Licencia: Apache 2.0 (el `LICENSE` existente). La licencia del modelo de sentimiento se declara aparte (ver §9).

## 2. Por qué esta aplicación y por qué no Identix

Se eligió primero Identix, la aplicación sugerida por el curso (+1 punto de bonificación). Se descartó el mismo día:

- Su OSINT sobre personas reales exigía verificar la titularidad de cada identificador (OAuth, un código en la biografía), recoger consentimiento y borrar datos. Esa carga de protección de datos superaba el alcance del trabajo.
- Las plataformas sociales principales no ofrecen acceso legítimo y gratuito (ver §5).

Se renuncia a la bonificación. Al ser una **propuesta propia**, debe validarla el profesor por escrito (sección 2 del enunciado); el borrador está en [`docs/propuesta.md`](propuesta.md). Encaja con el ejemplo del enunciado «Plataforma de detección de desinformación y verificación de fuentes».

Alojamiento: el trabajo se mantiene en este repositorio; el traslado a una rama del repositorio del curso será la **última** tarea del proyecto.

## 3. Alcance del MVP

| Dentro | Fuera |
|---|---|
| Registro e inicio de sesión (JWT, roles), temas favoritos | Aplicación móvil |
| Lectura periódica de RSS y sitemaps de cinco medios | Almacenar artículos completos |
| Tendencias de YouTube, Google Trends (RSS) y Mastodon | Redes sociales cerradas (Facebook, Instagram, TikTok, X, Reddit) |
| Búsqueda por tema con resultados agrupados por noticia | Recolección de datos personales; publicaciones y cuentas de usuarios de Mastodon |
| Sentimiento en español por noticia | Publicar contenido en redes sociales |
| Registro de auditoría de las búsquedas | Observabilidad (Fase 6, opcional): se decide más adelante |

## 4. Fuentes de noticias y tendencias

Estado al 2026-09-29. Las URL son las verificadas en la investigación.

| Fuente | Método de acceso | Evidencia | Estado |
|---|---|---|---|
| RCN | RSS `https://www.noticiasrcn.com/feed-kiosko-google` y sitemap de noticias `https://www.noticiasrcn.com/sitemapnews` | `robots.txt` permite `/` para `*` (no `/buscar`) | Incluida |
| Semana | RSS `https://www.semana.com/arc/outboundfeeds/rss/?outputType=xml` | `robots.txt` tiene `Allow: /rss/` | Incluida |
| Caracol | Sin RSS encontrado; sitemap `https://www.noticiascaracol.com/content-sitemap.xml` | `robots.txt` bloquea por nombre a GPTBot y ChatGPT-user; los bots genéricos están permitidos | Incluida |
| Blu Radio | Sin RSS encontrado; sitemap `https://www.bluradio.com/content-sitemap-latest.xml` | `robots.txt` bloquea GPTBot y ChatGPT-user | Incluida |
| Citytv (citytv.eltiempo.com) | Sin RSS; sitemap de noticias `https://citytv.eltiempo.com/sitemap-news.xml` | `robots.txt` bloquea por nombre varios rastreadores de IA | Incluida |
| YouTube Data API | `videos.list` con `chart=mostPopular`: 1 unidad de cuota; cuota por defecto de 10 000 unidades/día ([fuente](https://developers.google.com/youtube/v3/determine_quota_cost)) | `regionCode=CO`: **NO VERIFICADO**. Costo de la búsqueda por palabra clave con `search.list`: **NO VERIFICADO** | Incluida |
| Google Trends | RSS `https://trends.google.com/trending/rss?geo=CO`: funciona, pero es **no oficial** (sin garantía de estabilidad; sus términos, **NO VERIFICADO**). La API oficial está en alfa con acceso bajo petición ([fuente](https://developers.google.com/search/apis/trends)) | Consultado el 2026-09-29 | Incluida con riesgo |
| Mastodon | Solo `GET /api/v1/trends/tags` y `/links`: públicos, sin autenticación ([fuente](https://docs.joinmastodon.org/methods/trends/)). `/statuses` queda excluido porque devuelve publicaciones y autores | Tendencias globales por instancia, no específicas de Colombia | Incluida |

Términos de uso de los medios: **revisados manualmente por la persona responsable el 2026-09-29**. Ninguno de los 5 prohíbe leer sus RSS o sitemaps para mostrar titulares con enlace a la noticia original, dado el uso informativo. La revisión la hizo una persona; no hay cita literal de cada cláusula en este documento.

## 5. Fuentes excluidas

| Fuente | Motivo |
|---|---|
| X | Sin nivel gratuito ([fuente](https://docs.x.com/x-api/getting-started/pricing)). |
| Reddit | Ahora exige aprobación previa de la aplicación (Responsible Builder Policy); las cifras, **NO VERIFICADO**. |
| CNN en Español | HTTP 451 desde el entorno de investigación y su `robots.txt` bloquea bots de IA. |
| Facebook | Trending eliminado en 2018; Page Public Content Access exige verificación de empresa; CrowdTangle cerró el 2024-08-14; Meta Content Library es solo académica vía ICPSR. |
| Instagram | Sin API de tendencias; Hashtag Search exige cuenta profesional, revisión de la app por Meta y un límite de 30 hashtags por 7 días; Basic Display API cerró el 2024-12-04. Se decidió no hacer la prueba. |
| TikTok | La Research API no está disponible para Colombia ([fuente](https://developers.tiktok.com/products/research-api)); la Display API solo entrega los datos del propio usuario autenticado; automatizar Creative Center va contra sus términos (fuentes secundarias). |

## 6. Arquitectura (resumen)

Cuatro servicios desplegables, decisión registrada en [ADR 0003](adr/0003-agrupacion-microservicios.md):

| Servicio | Responsabilidad |
|---|---|
| `gateway` (FastAPI) | Autenticación (JWT y roles), usuarios, temas favoritos, API de búsqueda, registro de auditoría, límite de tasa |
| `worker-noticias` | Lee los RSS y sitemaps de los medios |
| `worker-tendencias` | YouTube, Google Trends RSS y etiquetas y enlaces en tendencia de Mastodon |
| `worker-analisis` | Agrupa la misma noticia entre medios y calcula el sentimiento en español |

La comunicación pasa por RabbitMQ; los datos, por PostgreSQL; los secretos de servicio (clave de la API de YouTube, credenciales de base de datos, clave de firma JWT), por Vault. El frontend es una SPA en React (requisito del curso).

## 7. Stack

Todas las versiones están **por verificar (AGENTS.md §3)** antes de fijarlas.

| Capa | Tecnología |
|---|---|
| Frontend | React (SPA) |
| Gateway | FastAPI |
| Workers | Python (Celery o consumidores simples: se decide en E3) |
| Broker / datos / secretos | RabbitMQ / PostgreSQL / Vault |
| Sentimiento | `pysentimiento` 0.7.3 (publicada el 2024-03-04) con el modelo `pysentimiento/robertuito-sentiment-analysis` |
| Orquestación / IaC | K3s ejecutado localmente con k3d (en contenedores) / Terraform con los proveedores `kubernetes` y `helm` |
| CI/CD | GitHub Actions |
| Seguridad | Gitleaks (ya en CI y pre-commit), Semgrep, Bandit, Trivy, OWASP ZAP, Checkov o tfsec, OWASP Threat Dragon |

Notas: `pysentimiento` requiere `torch`, así que la imagen es pesada; el modelo se incluirá en la imagen para funcionar sin conexión. NLTK VADER solo sirve para inglés y se descartó ([fuente](https://www.nltk.org/api/nltk.sentiment.vader.html)). El clúster se define en un archivo de configuración de k3d versionado; `terraform.tfstate` puede contener secretos y nunca se sube al repositorio.

## 8. Datos y restricciones

- Solo se almacenan titular, enlace, fecha y resumen corto; nunca el artículo completo.
- Atribución obligatoria: cada resultado muestra el nombre del medio, el autor cuando la fuente lo publica, la fecha y el enlace a la noticia original, que es donde se lee el contenido completo. Nunca se presenta el contenido de un medio como propio.
- Se respetan `robots.txt` y los términos de uso de cada fuente. El bot usa un `User-Agent` propio e identificable y nunca suplanta a un navegador ni a otro bot; si el `robots.txt` de una fuente lo bloquea, esa fuente se desactiva.
- El contenido que llega de las fuentes (titulares, resúmenes, XML de RSS y sitemaps, respuestas de API) es entrada no confiable: se analiza sin entidades externas (XXE), se escapa al mostrarlo (XSS) y solo se consultan dominios de una lista fija (SSRF). Se detalla en el modelo de amenazas (E1).
- No se recogen datos personales como objetivo: solo titular, enlace, fecha y resumen de noticias, y etiquetas y enlaces en tendencia. De los usuarios de la aplicación solo se guarda lo mínimo para autenticarse; el registro de auditoría de una búsqueda guarda el identificador de usuario y no más datos personales.
- Imágenes en Docker Hub bajo el namespace `h4tt3rxplo1tt` (doble t): `h4tt3rxplo1tt/h4tt3r-1nf0rm4t1v0-<servicio>:vX.Y.Z` más `latest`. Existe una cuenta parecida, `h4tt3rxplo1t` (una sola t), que **no está confirmada como del proyecto**: usar siempre el nombre exacto (riesgo de typosquatting). CI publica con un token de acceso de Docker Hub de alcance mínimo, guardado como secreto de GitHub por la persona responsable; nunca desde una máquina personal.
- Sin secretos en el repositorio: valores ficticios y `.env.example`.

## 9. Historia de usuario de la sustentación

Sección 4.6 del enunciado (distinta de la autenticación):

> «Como lector, quiero escribir un tema y ver en un solo lugar las noticias de los principales medios y los videos relacionados, agrupados por noticia y con su tono (positivo, negativo o neutral), para informarme rápido y comparar cómo lo cubre cada medio.»

Criterios de aceptación:

1. La búsqueda por tema exige un usuario autenticado; sin sesión válida responde 401.
2. Los resultados incluyen noticias de al menos un medio y videos de YouTube relacionados con el tema.
3. Las noticias que tratan el mismo hecho se muestran agrupadas en una sola noticia, con los medios que la cubren.
4. Cada noticia muestra una etiqueta de sentimiento: positivo, negativo o neutral.
5. El texto libre de la búsqueda se valida y no permite inyección ni ejecución de contenido (objetivo del DAST con OWASP ZAP).
6. Cada búsqueda deja un registro de auditoría con el identificador del usuario, sin más datos personales.
7. Si una fuente falla o no responde, la búsqueda devuelve las demás y avisa cuáles fallaron (degradación controlada).

## 10. Decisiones (2026-09-29)

| # | Decisión |
|---|---|
| 1 | Alojamiento: este repositorio; el traslado a una rama del repositorio del curso es la última tarea. |
| 2 | Arquitectura: 4 servicios (gateway FastAPI, worker de noticias, worker de tendencias, worker de análisis) más PostgreSQL, RabbitMQ y Vault (ADR 0003). |
| 3 | Fuentes: RCN y Semana (RSS); Caracol, Blu Radio y Citytv (sitemaps); YouTube; Google Trends RSS CO; Mastodon. Excluidas: Facebook, TikTok, Instagram, X, Reddit y CNN en Español. |
| 4 | Historia de usuario de la sustentación: búsqueda por tema. |
| 5 | Licencia Apache 2.0; la licencia del modelo de `pysentimiento` se declara aparte. |
| 6 | Orquestación con K3s mediante k3d; IaC con Terraform (proveedores `kubernetes` y `helm`). |
| 7 | Docker Hub: `h4tt3rxplo1tt`; la cuenta parecida `h4tt3rxplo1t` no está confirmada como propia. |

## 11. Riesgos abiertos

| Riesgo | Detalle | Acción |
|---|---|---|
| Términos de uso de los medios | Revisados manualmente por la persona el 2026-09-29: ninguno prohíbe el uso informativo con enlace; pueden cambiar | Repetir la revisión antes de la entrega final y atribuir siempre la fuente |
| Google Trends no oficial | Sin garantía de estabilidad; términos **NO VERIFICADO** | Degradación controlada (criterio 7); vigilar cambios |
| Licencia de `pysentimiento` | La licencia en PyPI no está declarada y algunos datasets de entrenamiento son de uso no comercial | Declararla aparte; aceptable para un proyecto académico; **NO VERIFICADO** para otros usos |
| Typosquatting en Docker Hub | Cuenta parecida `h4tt3rxplo1t` | Usar siempre `h4tt3rxplo1tt`; verificar el namespace antes de publicar |
| Cuotas de YouTube | 10 000 unidades/día por defecto; costo de `search.list` **NO VERIFICADO** | Caché y límite de consultas |
| Imagen pesada del worker de análisis | `torch` y el modelo dentro de la imagen | Medir el tamaño en E3; valorar imagen base mínima |

## 12. Plan por milestones

Estado de cada fase según AGENTS.md §6.

| Fase | Estado | Resumen |
|---|---|---|
| E0 Descubrimiento | Aplica, en curso (issue #15) | Ficha, ADR 0003 y propuesta escrita para el profesor |
| E1 Requisitos y diseño seguro | Aplica, pendiente | Modelo de amenazas (Threat Dragon, STRIDE, DFD 0 y 1) y ADR iniciales |
| E2 Base de ingeniería | Aplica, parcial | Ya hay protección de rama, hooks y CI de secretos; faltan estructura de servicios, lockfiles y CODEOWNERS |
| E3 Incrementos funcionales | Aplica, pendiente | Flujo de búsqueda por tema y sus pruebas |
| E4 Verificación continua | Aplica, pendiente | SAST, SCA, imágenes y pruebas en CI |
| E5 Plataforma e infraestructura | Aplica, pendiente | k3d, Terraform y Checkov o tfsec |
| E6 Seguridad en ejecución | Aplica, pendiente | JWT, roles, Vault y límite de tasa |
| E7 Release y cadena de suministro | Aplica, pendiente | Imágenes versionadas en Docker Hub desde CI, SBOM y firma según el nivel SLSA acordado |
| E8 Operación | No verificado | Observabilidad es opcional en el enunciado; se decide tras E5 |
| E9 Validación y transferencia | Aplica, pendiente | Informe, video, riesgos residuales |
| Traslado | Aplica, pendiente (último) | Traslado a la rama del repositorio del curso |

Primeros issues (borradores para que la persona responsable los cree):

- **E1: Modelo de amenazas con Threat Dragon.** Objetivo: DFD nivel 0 y 1 y amenazas STRIDE por flujo, con controles enlazados a pruebas, en `docs/threat-model.md`.
- **E3: Flujo de búsqueda por tema.** Objetivo: implementar el recorrido de la historia de usuario (§9): API de búsqueda autenticada, agrupación por noticia, sentimiento, auditoría y degradación controlada, con pruebas.
