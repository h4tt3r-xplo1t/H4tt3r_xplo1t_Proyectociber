# ADR 0008: Contrato de mensajes y colas de RabbitMQ entre `worker-noticias` y `worker-analisis`

## Estado

Aceptado, 2026-10-21 (issue #67). Lo aprobó la persona responsable.

## Contexto

El ADR 0003 decide que los servicios se comunican por RabbitMQ, pero no fija el
formato de los mensajes ni las colas. `worker-noticias` (issue #60) ya guarda
noticias en `noticias.news_items`; `worker-analisis` (issue #68) debe agruparlas
y calcular su sentimiento. Este ADR fija el primer flujo del broker: el aviso de
noticias nuevas.

Amenazas que condicionan la decisión (`docs/threat-model.md`):

- **18 (suplantación):** alguien publica mensajes falsos en la cola.
- **19 (denegación de servicio):** la cola se satura.
- **33 (elevación de privilegios):** deserialización insegura de los mensajes.

Restricciones ya decididas: sin Celery para la programación (ADR 0007), una
sola réplica de `worker-noticias`, el rol `worker_noticias` no tiene `UPDATE`
y los logs no llevan contenido de las noticias.

Versiones verificadas el 2026-10-21 (tarea T2 del issue #67): RabbitMQ 4.4.0
(imagen oficial `rabbitmq:4.4.0-alpine`, sin el plugin de gestión, fijada por
digest) y `pika` 1.4.4 (PyPI, BSD-3-Clause, mantenedores Gavin M. Roy y Luke
Bakken, Python 3.14 declarado). El detalle está en
`odd/tasks/mensajeria-rabbitmq.md`.

## Opciones consideradas

### Contenido del mensaje

1. **El mensaje lleva la noticia completa** (titular, enlace, resumen).
   Descartada: duplica datos fuera de PostgreSQL, agranda los mensajes y hace
   que un mensaje falso inyecte contenido directamente en el análisis.
2. **El mensaje lleva solo los `id` de `news_items`.** Elegida: el consumidor
   lee el contenido de PostgreSQL, que es la fuente de verdad; un mensaje falso
   como mucho pide analizar filas que ya existen.

### Cliente y marco

1. **Celery.** Descartada: el ADR 0007 la rechazó para la programación y aquí
   solo hace falta publicar y consumir un tipo de mensaje; su `pickle` por
   defecto es justo el riesgo de la amenaza 33.
2. **Cliente AMQP directo (`pika`, síncrono, como el bucle del worker).**
   Elegida, sujeta a la verificación de T2.

### Mensajes perdidos

1. **Aceptar la pérdida y documentarla.** Descartada: una noticia guardada sin
   aviso no se analizaría nunca.
2. **Transactional outbox** (tabla de pendientes en la misma transacción).
   Descartada por ahora: necesita `UPDATE` o `DELETE` sobre una tabla nueva y
   un proceso de reenvío, más complejidad que el problema.
3. **El aviso es una pista; PostgreSQL manda.** Elegida: `worker-analisis`
   procesa los avisos y además, al arrancar y de forma periódica, busca las
   noticias sin analizar. Un aviso perdido solo retrasa el análisis.

## Decisión

### Topología

- Vhost `h4tt3r`.
- Exchange `noticias` de tipo `direct`, durable.
- Cola `analisis.noticias` de tipo quorum, durable, enlazada con la clave
  `news.saved`.
- Cola de mensajes muertos `analisis.noticias.dlq`, de tipo quorum, durable,
  recibiendo del exchange `noticias.dlx`.
- La topología, los usuarios y las políticas se declaran en un archivo de
  definiciones que carga RabbitMQ al arrancar. Los servicios **no** declaran
  colas ni exchanges.

### Usuarios y permisos (amenaza 18)

| Usuario | configure | write | read |
|---|---|---|---|
| `worker_noticias` | (ninguno) | solo `noticias` | (ninguno) |
| `worker_analisis` | (ninguno) | (ninguno) | solo `analisis.noticias` |

- El usuario `guest` se elimina.
- Un usuario de administración solo existe en desarrollo y CI.
- Las contraseñas de desarrollo son ficticias y marcadas como no utilizables;
  fuera de desarrollo vienen del gestor de secretos (E5).
- El puerto AMQP solo escucha en 127.0.0.1 en desarrollo y dentro del clúster
  en E5.

### Política de la cola (amenaza 19)

Valores iniciales, revisables con datos reales:

- `x-max-length` de 10 000 mensajes con `overflow: drop-head`: el más antiguo
  se descarta y va a `analisis.noticias.dlq`.
- `x-message-ttl` de 24 h: un mensaje caducado va a la cola de mensajes
  muertos.
- `x-delivery-limit` de 3 entregas: un mensaje que falla repetidamente va a
  la cola de mensajes muertos (mensaje envenenado).
- `analisis.noticias.dlq` también tiene longitud máxima, para que no crezca
  sin límite.

Como PostgreSQL manda, un mensaje descartado no pierde noticias: la búsqueda
periódica de `worker-analisis` las recupera.

### Formato del mensaje (amenaza 33)

- Cuerpo JSON en UTF-8, `content_type` `application/json` y `delivery_mode`
  persistente.
- Tamaño máximo de 16 KiB. El productor nunca lo supera; el consumidor
  rechaza lo que lo exceda antes de decodificarlo.
- Esquema versión 1:

```json
{
  "schema": "noticias.saved/v1",
  "message_id": "6f1c2d3e-0000-4000-8000-000000000000",
  "source_id": "caracol-sitemap",
  "saved_at": "2026-10-21T12:00:00Z",
  "ids": [101, 102, 103]
}
```

- Validación estricta:
  - sin campos adicionales;
  - `schema` exacto;
  - `message_id` UUID;
  - `source_id` del catálogo fijo;
  - `saved_at` ISO 8601 en UTC;
  - `ids` de 1 a 500 enteros positivos únicos (500 = `MAX_ITEMS_PER_FEED`).
- Nunca se usa `pickle` ni otro formato que ejecute código. Un mensaje que no
  es JSON o no cumple el esquema se rechaza sin reencolar y acaba en la cola de
  mensajes muertos.

### Entrega

- Al menos una vez: el productor usa *publisher confirms*. El consumidor
  confirma (`ack`) después de escribir su resultado y es idempotente, así que
  procesar dos veces el mismo `id` no cambia el resultado.
- `worker-noticias` publica un aviso por fuente después de `save` y solo si
  hubo filas nuevas.
- Si la publicación falla (broker caído, rechazo o confirmación ausente):
  - la fuente se reporta como `broker_error` con un mensaje fijo;
  - las filas ya guardadas se conservan;
  - las demás fuentes siguen.

## Consecuencias

- `store.save()` debe devolver los `id` de las filas nuevas (hoy solo cuenta).
- `worker-analisis` necesita una forma de saber qué noticias ya analizó (sus
  propias tablas, issue #68) para la búsqueda periódica.
- Cambiar el esquema exige una versión nueva (`noticias.saved/v2`); el
  consumidor rechaza las versiones que no conoce.
- Las colas quorum consumen más recursos que las clásicas, aunque en un solo
  nodo; se eligen por `x-delivery-limit`. Según la documentación de
  RabbitMQ 4.4 (verificado en T2): admiten `drop-head`, `reject-publish` y TTL
  por mensaje, y su límite de entregas vale 20 por defecto (aquí se fija en 3).
- `drop-head` solo funciona con el reenvío a mensajes muertos «como mucho una
  vez» (`at-most-once`, el valor por defecto); el «al menos una vez» exige
  `reject-publish`. Por tanto, un mensaje descartado por la longitud máxima
  puede no llegar a `analisis.noticias.dlq`. Se acepta porque PostgreSQL manda
  y la búsqueda periódica recupera esas noticias.
- Al importar definiciones en el arranque, RabbitMQ no crea el usuario `guest`
  ni el vhost por defecto (documentación 4.4).
- AMQP viaja sin TLS dentro del clúster hasta el ADR de cifrado interno
  (antes de E5); en desarrollo solo escucha en 127.0.0.1.
- Celery se puede reconsiderar si aparecen varios tipos de trabajo con
  reintentos y programación compartidos (ADR 0007), siempre con
  `accept_content=["json"]`.
