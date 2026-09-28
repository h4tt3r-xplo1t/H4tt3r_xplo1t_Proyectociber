# ADR 0001: Protección de la rama `main`

## Estado

Aceptado, 2026-09-28.

## Contexto

Parte del trabajo de este proyecto se realiza desde Claude Code web o desde
el cliente de iPhone, entornos donde el hook local `guardia.sh` y los hooks
de `pre-commit` del repositorio no se ejecutan. Cualquier control que dependa
únicamente de esas capas locales puede evitarse simplemente trabajando desde
uno de esos clientes, así que la protección real de `main` debe vivir del
lado de GitHub, aplicada por la plataforma sin importar el cliente usado.

Al revisar la configuración actual del repositorio se encontró un ruleset
existente llamado `protege` (id `24097824`) con las siguientes
características relevantes:

- Una lista de bypass `always` que exime del ruleset al rol Admin y a tres
  integraciones instaladas en el repositorio.
- Reglas activas de `update`, `creation` y `required_signatures`.
- Reglas de `code_scanning` (CodeQL, Snyk, Trivy), `code_quality` y
  `code_coverage`, todas referidas a herramientas que hoy no están
  configuradas en el repositorio.

Un ruleset con bypass `always` para Admin no protege frente al propio
desarrollador trabajando en solitario (que además es Admin del repositorio),
y las reglas de escaneo/calidad/cobertura apuntan a integraciones inexistentes,
por lo que no bloquean nada en la práctica. El ruleset da una falsa sensación
de protección.

## Opciones consideradas

1. **Conservar `protege` y añadir un ruleset nuevo en paralelo.** Descartada:
   dos rulesets sobre la misma rama son más difíciles de auditar y el bypass
   `always` de `protege` seguiría vigente, neutralizando parte del beneficio.
2. **Reemplazar `protege`** con una configuración versionada como código,
   sin lista de bypass. Reduce a un único ruleset auditable en el repositorio.
3. **Branch protection clásica** (no rulesets). Descartada: es el mecanismo
   más antiguo de GitHub, no se puede versionar como archivo en el repositorio
   y GitHub recomienda rulesets para configuraciones nuevas.

## Decisión

Se reemplaza `protege` (vía `PUT` sobre el ruleset existente, id `24097824`)
por una definición versionada en `.github/rulesets/main.json`, con las
siguientes reglas:

- Bloquear borrado de la rama y `force push`.
- Exigir pull request antes de fusionar, con 0 aprobaciones mínimas: el
  desarrollador solo puede trabajar en solitario y GitHub no permite
  autoaprobar el propio PR, así que exigir 1+ aprobaciones bloquearía todo
  el flujo.
- Descartar aprobaciones obsoletas ante nuevos commits.
- Exigir conversaciones resueltas antes de fusionar.
- Fusión exclusivamente por squash (con los merge commits y el rebase merge
  deshabilitados también en la configuración general del repositorio).
- Checks requeridos: `secretos`, `workflows` y `pruebas` (los tres jobs del
  workflow `Seguridad`), con la rama actualizada (`strict`) antes de fusionar.
- Historial lineal.
- Sin lista de bypass.

El CI que respalda estos checks usa los binarios oficiales de `gitleaks` y
`actionlint`, descargados y verificados por `sha256` en el propio workflow,
en vez de la acción `gitleaks/gitleaks-action`: esa acción de terceros usa
una licencia personalizada no reconocida por SPDX y requiere `GITHUB_TOKEN`
con permisos adicionales, mientras que el binario oficial fijado por hash no
necesita ni lo uno ni lo otro.

Esta ADR cubre solo la definición de la política (Fase 1). La aplicación
remota del `PUT` sobre `protege` y el cambio de configuración de fusión del
repositorio quedan para la Fase 2, en una rama distinta y solo con
autorización explícita del usuario para la operación remota, según lo exigido
por `AGENTS.md` (sección 2, MODOS DE TRABAJO).

## Consecuencias

**Positivas**

- Los controles se aplican desde cualquier cliente (CLI local, web, iPhone),
  porque dependen de GitHub y no de hooks locales.
- La política de protección queda como código versionado y revisable en
  `.github/rulesets/main.json`, con una única fuente de verdad en vez de
  configuración manual dispersa en la interfaz de GitHub.

**Negativas**

- Sin lista de bypass, ni siquiera el rol Admin puede hacer push directo a
  `main`: todo cambio, incluidos los de emergencia, pasa por pull request.
- Se elimina la regla `required_signatures` presente en `protege`. Se anota
  como una concesión consciente a revisar más adelante (retomar firma de
  commits cuando el flujo de trabajo lo permita).
- Los binarios de `gitleaks` y `actionlint` están fijados por versión y
  `sha256` en el workflow; Dependabot no los actualiza automáticamente (solo
  cubre `github-actions` y `pip`/`npm`/etc., no descargas por `curl`), así que
  requieren bump manual periódico.
- El ruleset solo se aplica en la Fase 2, después de que los tres checks
  (`secretos`, `workflows`, `pruebas`) se hayan ejecutado al menos una vez en
  un PR real y se confirme que pasan, para no bloquear la fusión con checks
  que nunca han corrido.
