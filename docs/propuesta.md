# Propuesta de proyecto: H4tt3r_1nf0rm4t1v0

**Trabajo final:** Pipeline DevSecOps de ciclo completo para una aplicación contenerizada de libre uso
**Autor:** H4TT3R_XPLO1T
**Fecha:** 2026-09-29
**Licencia del producto:** Apache 2.0

## 1. Solicitud

Solicito la validación por escrito (sección 2 del enunciado) de una **propuesta propia**: H4tt3r_1nf0rm4t1v0, un agregador de noticias y tendencias. Esta propuesta **reemplaza a la aplicación sugerida, Identix**, y con ello **renuncio a la bonificación de 1 punto** asociada a esa aplicación.

## 2. Problema y justificación

Una misma noticia aparece en muchos medios con enfoques distintos, y el lector tiene que recorrerlos uno a uno para compararlos. H4tt3r_1nf0rm4t1v0 reúne en un solo lugar las noticias más relevantes de medios colombianos y de habla hispana, junto con tendencias, y permite buscar por tema. Los resultados se agrupan por noticia entre medios y llevan una etiqueta de sentimiento. Encaja con el ejemplo del enunciado «Plataforma de detección de desinformación y verificación de fuentes», porque permite contrastar cómo cubre cada medio un mismo hecho.

Se eligió primero Identix y se descartó: su OSINT sobre personas reales exigía verificar la titularidad de cada identificador, recoger consentimiento y borrar datos, una carga de protección de datos que excedía el alcance, y las redes sociales principales no ofrecen acceso legítimo y gratuito. Esta aplicación no recoge datos personales como objetivo: solo titulares, enlaces, fechas y resúmenes de noticias, y etiquetas y enlaces en tendencia.

## 3. Objetivos

- Construir una aplicación de microservicios funcional a nivel de especialización.
- Diseñar, asegurar y automatizar su ciclo de vida completo con un pipeline DevSecOps (planificación, codificación, integración, pruebas, despliegue).
- Documentar las decisiones, los riesgos y la evidencia de seguridad.

## 4. Funcionalidad

- Registro e inicio de sesión con JWT y roles; temas favoritos por usuario.
- Lectura periódica de noticias de RCN, Semana, Caracol, Blu Radio y Citytv (RSS y sitemaps).
- Tendencias de YouTube, Google Trends (RSS) y Mastodon (solo etiquetas y enlaces, sin publicaciones ni cuentas).
- Búsqueda por tema con resultados agrupados por noticia y sentimiento en español (positivo, negativo o neutral).
- Registro de auditoría de las búsquedas.

## 5. Arquitectura

Cuatro servicios desplegables (ADR 0003, [`adr/0003-agrupacion-microservicios.md`](adr/0003-agrupacion-microservicios.md)) y tres componentes de datos e infraestructura:

| Componente | Función |
|---|---|
| Frontend (React, SPA) | Interfaz de búsqueda y resultados |
| `gateway` (FastAPI) | Autenticación, usuarios, búsqueda, auditoría, límite de tasa |
| `worker-noticias` | Lee RSS y sitemaps de los medios |
| `worker-tendencias` | YouTube, Google Trends y Mastodon |
| `worker-analisis` | Agrupación por noticia y sentimiento |
| RabbitMQ | Comunicación asíncrona entre servicios |
| PostgreSQL | Datos de la aplicación |
| Vault | Secretos de servicio |

Despliegue en K3s ejecutado localmente con k3d, definido con Terraform.

## 6. Cumplimiento de los requisitos del curso

| Requisito | Cómo se cumple |
|---|---|
| Frontend SPA (3.1) | React |
| Backend / API Gateway (3.1) | FastAPI |
| Al menos un worker (3.1) | Tres workers de Python: noticias, tendencias y análisis |
| Base de datos (3.1) | PostgreSQL |
| Autenticación (3.1) | JWT con control de roles |
| Contenerización (3.2) | Un Dockerfile por servicio, `docker-compose.yml` local, imágenes versionadas en Docker Hub (`h4tt3rxplo1tt`) |
| Fase 1, Planificación | OWASP Threat Dragon, DFD 0 y 1, STRIDE |
| Fase 2, Codificación | Gitleaks en pre-commit y CI, Semgrep y Bandit (SAST), Trivy (SCA) |
| Fase 3, Integración | Construcción de imágenes en CI, escaneo con Trivy o Grype, falla con CVE críticos sin excepción documentada |
| Fase 4, Pruebas | Pytest y Jest, DAST con OWASP ZAP contra staging |
| Fase 5, Despliegue | Terraform, Checkov o tfsec, K3s |
| Fase 6, Operación (opcional) | Se decide más adelante |

## 7. Fuentes y enfoque legal y ético

Solo se almacenan titular, enlace, fecha y un resumen corto, nunca el artículo completo. Se respetan `robots.txt` y los términos de uso, el bot se identifica con un `User-Agent` propio que no suplanta a otro (si una fuente lo bloquea, se desactiva), se usa únicamente acceso gratuito y legítimo y no se recogen datos personales como objetivo. El contenido de las fuentes se trata como entrada no confiable. Se excluyeron X, Reddit, Facebook, Instagram, TikTok y CNN en Español por no ofrecer acceso gratuito y legítimo (detalle y fuentes en `docs/PROJECT_CONTEXT.md`). Los términos de uso de los 5 medios se revisaron manualmente el 2026-09-29 y ninguno prohíbe este uso informativo. Cada resultado atribuye la fuente: nombre del medio, autor cuando se publica, fecha y enlace a la noticia original.

## 8. Historia de usuario para la sustentación

> «Como lector, quiero escribir un tema y ver en un solo lugar las noticias de los principales medios y los videos relacionados, agrupados por noticia y con su tono (positivo, negativo o neutral), para informarme rápido y comparar cómo lo cubre cada medio.»

Criterios de aceptación: búsqueda autenticada; resultados de al menos un medio y de YouTube; agrupación por noticia; etiqueta de sentimiento; validación del texto libre frente a entradas maliciosas; registro de auditoría sin más datos personales que el identificador de usuario; degradación controlada si una fuente falla.

## 9. Validación solicitada

Quedo atento a la validación de esta propuesta. Ruego indicar si el alcance y las fuentes son aceptables y si hay observaciones antes de continuar con la implementación.
