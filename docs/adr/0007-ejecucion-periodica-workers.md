# ADR 0007: Ejecución periódica de `worker-noticias` con un bucle propio, sin Celery

## Estado

Aceptado, 2026-10-16.

## Contexto

`worker-noticias` (ADR 0003) lee de forma periódica cinco fuentes fijas: los
RSS de RCN y Semana y los sitemaps de noticias de RCN, Caracol, Blu Radio y
Citytv. Hay que decidir cómo se programa esa lectura periódica.

RabbitMQ todavía no está desplegado: la comunicación por broker llega con
`worker-analisis`. Cada dependencia nueva amplía la cadena de suministro, que
es lo que el proyecto evalúa y debe vigilar.

La decisión la tomó la persona responsable el 2026-10-16.

## Opciones consideradas

1. **Celery con beat.** Descartada por ahora: exige un broker y un proceso
   `beat` ya, y añade un árbol de dependencias grande para programar cinco
   lecturas.
2. **APScheduler u otra biblioteca de planificación.** Descartada: una
   dependencia más (con su mantenimiento y sus vulnerabilidades) para una
   necesidad que cubren unas pocas líneas.
3. **Bucle propio con intervalo medido con `time.monotonic` y aislamiento por
   fuente.** Elegida.

## Decisión

`worker-noticias` ejecuta un bucle propio: en cada ciclo recorre las fuentes,
lee cada una dentro de su propio manejo de errores y espera hasta cumplir el
intervalo, medido con `time.monotonic` (no se ve afectado por cambios del
reloj del sistema). El fallo, el tiempo agotado o la desactivación de una
fuente no detienen a las demás y se registran sin volcar su contenido.

## Consecuencias

- Sin dependencias nuevas de planificación ni proceso `beat`.
- No hay agenda persistente ni bloqueo distribuido: tras un reinicio se
  empieza un ciclo nuevo. Debe correr **una sola réplica**. Dos réplicas
  leerían dos veces las mismas fuentes; la restricción de enlace único de la
  tabla de noticias (tarea T5 del issue #60) hace que el efecto sea inocuo
  (sin filas duplicadas), pero se duplica el tráfico hacia los medios.
- Se reconsidera cuando existan RabbitMQ y más workers que compartan un
  mecanismo común de programación.
- Alternativa para E5: un `CronJob` de Kubernetes que ejecute un ciclo y
  termine, con la programación y la política de concurrencia delegadas al
  clúster.
- Hay que probar el bucle (aislamiento por fuente, intervalo) porque el
  código de programación es propio.
