# Guía de OWASP Threat Dragon para este proyecto

Guía práctica para reproducir y defender el modelo de amenazas ([`docs/threat-model.md`](../threat-model.md)). Cada paso explica el porqué.

## 1. Instalación verificada

Se usa **Threat Dragon v2.6.2**, del repositorio oficial `OWASP/threat-dragon` (licencia Apache-2.0), publicada el 2026-05-10. En Fedora se usa el AppImage (un ejecutable único que no requiere instalar paquetes).

```bash
mkdir -p ~/Aplicaciones && cd ~/Aplicaciones
gh release download v2.6.2 -R OWASP/threat-dragon -p 'Threat-Dragon-ng-2.6.2.AppImage'
echo 'e96cecfc2d8c71df384a99300a7fe5540ce7158167be4a47f7f3d269a2dce7d3311141f5165837b219a053928aa84d8bda0754615fafd071088868f3d3400235  Threat-Dragon-ng-2.6.2.AppImage' | sha512sum -c
chmod +x Threat-Dragon-ng-2.6.2.AppImage
~/Aplicaciones/Threat-Dragon-ng-2.6.2.AppImage
```

- **Por qué se verifica el hash:** un binario descargado puede haber sido alterado en tránsito o en origen; el hash SHA-512 demuestra que es el archivo publicado. El valor esperado se cotejó entre `checksum-linux.yml` y `latest-linux.yml` de la release. Límite: no protege frente a una release comprometida en origen.
- **Por qué `chmod +x`:** el AppImage se descarga sin permiso de ejecución.
- **Por qué en una terminal aparte:** la aplicación ocupa la terminal mientras está abierta.
- **Versión de escritorio sin acceso a GitHub:** el modelo se guarda como archivo local. Es el mínimo privilegio: no se entrega a la herramienta ningún token.

## 2. Las piezas de un DFD

| Pieza | Qué es | Ejemplo en este proyecto |
|---|---|---|
| Actor | Entidad externa que interactúa con el sistema | Lector, Medios de noticias |
| Proceso | Código que transforma o enruta datos | gateway (FastAPI), worker-noticias, RabbitMQ |
| Almacén | Donde los datos reposan | PostgreSQL, Vault |
| Flujo | Datos que se mueven entre dos piezas | «Credenciales y texto de búsqueda» |
| Límite de confianza | Línea entre zonas con distinto nivel de control | «Internet ↔ Clúster» |

RabbitMQ se dibuja como **proceso** (no como almacén): enruta y entrega mensajes, aunque los retenga en cola.

Idea clave: las amenazas se concentran donde un flujo **cruza un límite de confianza**. Sin dibujarlos no se ve dónde validar la entrada.

## 3. Crear el modelo

Campos usados:

| Campo | Valor |
|---|---|
| Título | H4tt3r_1nf0rm4t1v0 |
| Propietario | H4TT3R_XPLO1T |
| Revisor | revisor-seguridad |
| Tipo de diagrama | STRIDE |

Se elige STRIDE (y no LINDDUN) porque el foco es la seguridad del sistema; LINDDUN se centra en privacidad, y la aplicación no recoge datos personales como objetivo.

Guardar en `docs/architecture/threat-model.json`. Ojo: el diálogo puede guardar como `d.json`; hay que renombrarlo y volver a abrir el modelo.

## 4. Nivel 0 y nivel 1

- **Nivel 0:** el sistema como un único proceso y sus interacciones externas. Sirve para acordar el alcance.
- **Nivel 1:** los servicios internos y sus flujos. Ahí se ven los cruces de límites.

Reglas:

- Los flujos apuntan en la dirección en que se mueven los **datos**, no la de la petición. La respuesta a una búsqueda es un flujo distinto del texto de búsqueda.
- No se usa la casilla «Bidireccional»: oculta un flujo y sus amenazas propias.
- Para corregir una flecha invertida, se borra y se redibuja desde el origen.
- Los límites de confianza son líneas libres que cruzan los flujos y **nunca** se pegan a un elemento (si se pegan, se mueven con él y el diagrama miente).

## 5. Amenazas

Seleccionar el elemento o flujo → panel «Amenazas» → nueva amenaza → completar título, tipo, severidad, descripción y mitigación. El estado queda en «Abierta» hasta que una prueba demuestre el control; marcarla antes daría una seguridad falsa.

Etiquetas exactas de tipo STRIDE que guarda Threat Dragon (de `td.vue/src/i18n/es.js` en v2.6.2):

- `Spoofing / Spoofing`
- `Tampering / Manipulación`
- `Repudiation / Repudiación`
- `Information disclosure / Brecha de información`
- `Denial of service / Denegación de servicio`
- `Elevation of privilege / Elevación de privilegios`

## 6. Errores frecuentes vistos en esta sesión

| Error | Consecuencia y remedio |
|---|---|
| Guardar como `d.json` | El modelo queda con otro nombre; renombrar y reabrir |
| Límites pegados a elementos | Se mueven con el elemento; dejarlos como líneas libres |
| Flujo desconectado al arrastrar una punta | Parece conectado pero no lo está; comprobar con el fragmento del paso 8 |
| Texto de relleno en la descripción | Queda en el modelo; revisar todas las descripciones |
| Tipo equivocado en el desplegable | La amenaza cuenta en otra categoría; corregir el tipo |
| Guardar en la aplicación tras editar el JSON por fuera | La aplicación sobrescribe la edición; cerrar sin guardar y reabrir |

## 7. Exportar

Menú «Exportar» → PNG, a `docs/architecture/dfd-nivel-0.png` y `docs/architecture/dfd-nivel-1.png`. Son las imágenes que incrusta el documento del modelo de amenazas.

## 8. Cómo verificar la integridad del modelo

Comprueba que cada flujo tiene origen y destino en celdas existentes y que cada tipo de amenaza es una de las 6 etiquetas. Se ejecuta con `python3` desde la raíz del repositorio.

```python
import json

TIPOS = {
    "Spoofing / Spoofing", "Tampering / Manipulación",
    "Repudiation / Repudiación", "Information disclosure / Brecha de información",
    "Denial of service / Denegación de servicio",
    "Elevation of privilege / Elevación de privilegios",
}
modelo = json.load(open("docs/architecture/threat-model.json"))
errores = []
for dg in modelo["detail"]["diagrams"]:
    ids = {c["id"] for c in dg["cells"]}
    for c in dg["cells"]:
        if c["data"]["type"] == "tm.Flow":
            for extremo in ("source", "target"):
                if c.get(extremo, {}).get("cell") not in ids:
                    errores.append(f"{dg['title']}: flujo {c['data']['name']!r} sin {extremo}")
        for t in c["data"].get("threats", []):
            if t["type"] not in TIPOS:
                errores.append(f"amenaza {t['number']}: tipo no válido {t['type']!r}")
print(errores or "modelo íntegro")
```
