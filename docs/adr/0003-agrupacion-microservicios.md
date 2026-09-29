# ADR 0003: Agrupación de los servicios lógicos en cuatro servicios desplegables

## Estado

Aceptado, 2026-09-29.

## Contexto

El enunciado exige una arquitectura de microservicios con frontend, gateway,
al menos un worker, base de datos y autenticación (sección 3.1). El diagrama
de referencia del curso para Identix (vista 1) dibuja 8 servicios lógicos
(usuarios, conectores, privacidad, publicación, alertas, análisis,
credenciales y auditoría) más Kong o NGINX, TimescaleDB, MinIO, Redis y
Jaeger.

H4tt3r_1nf0rm4t1v0 es un agregador de noticias y tendencias con búsqueda por
tema (ver `docs/PROJECT_CONTEXT.md`). Es un proyecto individual, y lo que se
evalúa es el pipeline DevSecOps, no el número de servicios. Cada servicio
añade un Dockerfile, un manifiesto, escaneos, pruebas y superficie de
operación que hay que mantener y asegurar.

## Opciones consideradas

1. **Los 8 servicios lógicos tal como están dibujados.** Descartada: muchos
   servicios quedarían casi vacíos (privacidad, credenciales, publicación no
   tienen equivalente en esta aplicación) y el costo operativo restaría
   tiempo al pipeline.
2. **Un monolito.** Descartada: no cumple el requisito de microservicios ni
   permite separar los procesos asíncronos de lectura de fuentes y análisis.
3. **Cuatro servicios agrupados por responsabilidad.** Elegida.

## Decisión

Cuatro servicios desplegables:

| Servicio | Responsabilidad |
|---|---|
| `gateway` (FastAPI) | Autenticación (JWT y roles), usuarios, temas favoritos, API de búsqueda, registro de auditoría y límite de tasa |
| `worker-noticias` | Lee los RSS y sitemaps de los medios |
| `worker-tendencias` | YouTube, Google Trends RSS y etiquetas y enlaces en tendencia de Mastodon |
| `worker-analisis` | Agrupa la misma noticia entre medios y calcula el sentimiento en español |

La comunicación entre servicios pasa por RabbitMQ. Los datos viven en
PostgreSQL. Los secretos de servicio (clave de la API de YouTube,
credenciales de base de datos y clave de firma JWT) viven en Vault. El
frontend es una SPA en React, requisito del curso.

Se aplazan hasta que haya una necesidad medida: TimescaleDB, MinIO, Redis,
Jaeger y un producto de API gateway independiente (Kong o NGINX).

## Consecuencias

- Menos carga operativa (cuatro imágenes, cuatro manifiestos) y más tiempo
  para el pipeline, que es lo evaluado.
- El `gateway` concentra varias responsabilidades (autenticación, búsqueda,
  auditoría, límite de tasa). Eso acopla esas preocupaciones y hace del
  gateway un componente crítico: deberá tener el mayor cuidado en pruebas y
  revisión de seguridad.
- Los workers sí se separan por su distinto perfil: `worker-analisis`
  incluye `torch` y el modelo de sentimiento (imagen pesada) y no debe
  arrastrar a los otros dos.
- Cuándo dividir un servicio: si crece la carga de auditoría o de búsqueda,
  si hace falta escalar por separado, o si se necesitan fronteras de
  confianza distintas (por ejemplo, aislar la autenticación).
- Cada servicio incorporado después requiere actualizar el modelo de
  amenazas (E1) y este ADR.
