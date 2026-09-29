# ADR 0002: Alcance y modelo de amenaza de `guardia.sh`

## Estado

Aceptado, 2026-09-28.

## Contexto

`.claude/hooks/guardia.sh` es un hook `PreToolUse` de Claude Code. Antes de
que se ejecute cada comando de la herramienta Bash, inspecciona su **texto**
y bloquea (código de salida 2) acciones contrarias al flujo del proyecto:

- commit o merge en `main`;
- saltarse los hooks de git;
- push forzado o push a `main`.

Durante el issue #1 (PR A) el hook se reescribió para fallar cerrado y cubrir
muchas formas de invocar git. Después, una revisión de seguridad reprodujo 19
evasiones más, de tres familias:

1. **Estructural.** El parser interpreta mal git bien escrito, por ejemplo
   `git --namespace x commit`, `switch main && cherry-pick`,
   `push -o x origin` en `main`, o `push HEAD:heads/main`.
2. **Configuración persistente.** Cambios de config que desvían el push o
   los hooks sin nombrarlos en el comando, por ejemplo
   `git config remote.origin.push HEAD:main`, alias de git o
   `GIT_CONFIG_COUNT`.
3. **Expansión del shell.** El shell construye la palabra `git` en tiempo
   de ejecución, por ejemplo `git${IFS}commit`, `{git,commit,-m,x}` o
   `$'\x67it' commit`.

Un análisis del texto de un comando de shell no puede anticipar todas las
formas en que el shell expande y ejecuta ese texto. Cada parche contra la
tercera familia abre otra variante y añade falsos positivos y complejidad a
un script que se ejecuta antes de cada comando.

## Opciones consideradas

1. **Parchear también la expansión del shell.** Descartada: no tiene fin,
   aumenta los falsos positivos y hace el hook frágil.
2. **Fusionar sin más cambios y documentar las 19 evasiones.** Descartada:
   deja abiertos errores estructurales y de configuración que son baratos de
   cerrar y que un agente puede cometer por descuido.
3. **Cerrar las familias estructural y de configuración, y declarar la
   expansión del shell como límite inherente.** Elegida.

## Decisión

El modelo de amenaza de `guardia.sh` es **el error del agente**: un comando
bienintencionado que viola el flujo por descuido (un commit en `main`, un
`push --force`, un `--no-verify`). Contra esa amenaza el hook debe ser
fiable, fallar cerrado y tener pruebas de regresión.

`guardia.sh` **no** es una frontera de seguridad frente a un agente o un
atacante que intenta evadirlo a propósito. Esa protección la dan capas que
no dependen del texto del comando:

| Capa | Dónde actúa | Qué garantiza |
|---|---|---|
| `guardia.sh` | Claude Code, antes de ejecutar | Frena errores del agente; falla cerrado |
| `pre-commit` (`no-commit-to-branch`, gitleaks) | Máquina local, en el commit real | Usa la rama real, no el texto del comando |
| Ruleset `protege` (ADR 0001) | GitHub, en el servidor | Nada entra en `main` sin PR, checks y squash, sin importar el cliente |

## Consecuencias

**Positivas**

- Expectativas explícitas: una evasión por expansión del shell no es un
  fallo del hook, sino un caso fuera de su alcance.
- El hook conserva un tamaño y una complejidad revisables, con una suite de
  regresión que corre en CI (job `pruebas`, issue #9).

**Negativas**

- Siguen fuera de alcance:
  - la expansión del shell (`${IFS}`, llaves, `$'...'`, globs);
  - variables que contienen `git`, alias y funciones de shell, y `eval`;
  - alias de git ya existentes en la configuración del usuario (por ejemplo
    `ci = commit` en `~/.gitconfig`); el hook solo impide crear alias nuevos;
  - scripts ejecutados indirectamente (`bash script.sh`, `make`), incluida
    la edición directa de `.git/config`, borrar `.git/hooks/*` o
    `pre-commit uninstall`;
  - `rebase`, `pull` (merge o rebase local) y `reset`/`update-ref`/`branch -f`
    sobre `main`;
  - lecturas de contenido **registrado** por git con pathspecs (`git log -p`,
    `git diff --cached`, globs como `'*.env'`): no alcanzan un `.env`
    ignorado; si un secreto llegara a registrarse, el control es gitleaks.

  Todos actúan en local: el ruleset impide que un push lleve esos cambios a
  `main` en GitHub. La otra vía hacia `main`, fusionar un PR, sí la bloquea
  el hook (`gh pr merge`), porque la fusión la hace una persona
  (AGENTS.md §5). Una fusión mediante `gh api` (endpoint de merge del PR)
  no se cubre y queda como límite conocido.
- Falsos positivos aceptados (fail-closed):
  - `-n` en cualquier parte de un comando con `git commit`;
  - `echo git commit` en `main`;
  - `git -C <ruta>`, `--git-dir` o `--work-tree` con commit o push sin
    refspec, aunque la ruta sea el propio proyecto (la rama destino se
    considera desconocida);
  - `cd "$VAR"` o `cd` con sustitución de comandos antes de un commit, porque
    el destino no se puede resolver; también un `cd` dentro de un subshell,
    que afecta a los segmentos posteriores;
  - una rama destino de push que termine en `/main` (`feat/main`);
  - opciones globales de git no reconocidas (por ejemplo `-C.`);
  - cualquier comando cuyo texto mencione `core.hooksPath`, las claves de
    config bloqueadas, `--no-verify`, `SKIP=`, `PRE_COMMIT_ALLOW_NO_CONFIG=`
    o las variables `GIT_CONFIG_*` bloqueadas, incluidas las líneas de un
    mensaje de commit o un cuerpo de PR pasados en la línea de comandos.

  Los textos se pasan por archivo (`-F`, `--body-file`), y los `cd` con la
  ruta literal del proyecto.
