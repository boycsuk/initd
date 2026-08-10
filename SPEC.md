# SPEC — `users.lock-root` deja de preguntar y escanea el host

> Rama: `fix/lock-root-scan`. Estado: planificado, sin implementar.

## Context

`users.lock-root` abre un formulario pidiendo «Account that keeps access», con
un chooser que ofrece las 23 cuentas del host. El valor no se usa para nada
salvo comprobarlo: la tarea no bloquea esa cuenta, no la modifica y no la
escribe en ningún sitio. El propio hint lo admite — *«root is locked; this one
is only checked»*.

Es una pregunta cuya respuesta la máquina ya tiene. Y no es la primera vez que
se intenta arreglar por la vía equivocada: el comentario en `users.rs:382-386`
narra una ronda previa en la que se cambió la *etiqueta* porque el campo se
confundía con «la cuenta a bloquear». La etiqueta no era el problema.

El resultado buscado: la tarea comprueba sola que el host conserva una vía de
entrada, y la confirmación *enseña* cuál en vez de pedir que se adivine.

### Por qué el guardia se vuelve más fuerte, no más débil

Hoy `NoWayBackIn` significa «la cuenta que escribiste no sirve» — el operador
prueba otra. Tras el cambio significa **«este host no tiene salida»**, que es
la afirmación que la tarea siempre quiso hacer y no podía. Un escaneo que
aprueba si *alguna* cuenta pasa es correcto en seguridad: si existe una vía de
entrada, existe.

### Lo descartado y por qué (no reabrir sin datos nuevos)

Se evaluó comprobar que la sesión no viene del propio root. **No es
implementable como guardia**, por dos razones independientes:

1. **Ningún comando responde.** `whoami` es literalmente `id -un`: ambos leen
   el UID *efectivo* del proceso, que bajo `sudo` ya es 0. `id -gn` tampoco,
   porque `sudo` reemplaza credenciales de usuario y de grupo en la misma
   llamada. `logname` reporta `root` y `who am i` está vacío sin TTY
   controlador — ambos ya medidos en `debian:13` y `alpine:3.23`, ver
   `users.rs:23-36`. Los cuatro describen *el proceso*, que para entonces es
   root. Solo `SUDO_USER`/`DOAS_USER` describen quién lo hizo root.
2. **La señal la controla el sujeto.** Son variables de entorno, y quien ya es
   root las fija al valor que quiera. Un guardia falsificable por su propio
   sujeto da una garantía que no tiene.

Y aunque el grupo respondiera, no distinguiría lo que se buscaba: root *es*
administrador, así que la pertenencia al grupo admin no separa «admin que
escaló» de «root directo».

De ahí que quede como **aviso**, nunca como bloqueo — respetando la regla que
`users.rs:32-36` ya fijó: `None` significa *«esto no se puede comprobar»*,
nunca *«no hay nada que comprobar»*. Rechazar sobre una pregunta incontestable
dejaría inutilizable la consola de rescate del proveedor, que entra como root
directo — precisamente el caso para el que existe la tarea.

## Decisiones tomadas

| # | Decisión | Motivo |
|---|----------|--------|
| 1 | Escaneo puro; campo `admin` eliminado | Un solo camino de decisión; no hay guardia y recheck que puedan divergir |
| 2 | Aviso no bloqueante si `SUDO_USER`/`DOAS_USER` vacío | Ver arriba: no medible y falsificable |
| 3 | La confirmación lista **todas** las cuentas que pasan, con su credencial | El operador comprueba si la suya está; cancela si ninguna lo es |
| 4 | El rango **ordena** el escaneo, nunca lo filtra | `posix_accounts.rs:50-52`: el umbral es convención, no regla |
| 5 | Las tres variantes de error se conservan como **diagnóstico por cuenta** | El detalle de openSUSE sigue siendo necesario |
| 6 | `NoWayBackIn` dice cuántas cuentas se miraron y por qué falló cada una | No afirmar más de lo medido |
| 7 | La lista se **desplaza** si no cabe | Ninguna cuenta oculta en el diálogo más peligroso |

### Sobre la decisión 4, y el coste que fija

`list_accounts` (`posix_accounts.rs:78-104`) ya clasifica cada cuenta como
`Root`/`Human`/`System` al parsear el uid, y **descarta ese dato** al devolver
solo nombres. Recuperarlo permite consultar primero las humanas.

Pero el rango **no filtra**. El comentario en `posix_accounts.rs:50-52` es
explícito: 1000 es una convención de las cinco familias, «no una regla — por eso
solo *ordena* la lista y nunca la filtra. Un sitio que numera una cuenta real
por debajo todavía la encuentra, más abajo». Convertirlo en filtro perdería una
cuenta con uid 999 y shell de login, y reportaría «sin salida» a un host que la
tiene. `Rank` también marca como `System` cualquier shell de
`NON_LOGIN_SHELLS`, lo que amplía lo que un filtro descartaría.

**Consecuencia que hay que aceptar: el escaneo no puede parar en la primera
cuenta que pasa.** Parar sería lo barato, y es incompatible con las decisiones
3 y 6 — sin recorrer todas no hay lista que enseñar ni diagnóstico que dar. Así
que el coste real es **~25 comandos privilegiados** al abrir la confirmación,
frente a ~4 hoy. Se paga a cambio de que la afirmación sea completa. Si resulta
lento en un host grande, la salida es cachear el resultado del escaneo dentro
de la apertura del diálogo, **no** volver a cortar el recorrido.

**Rechazado: leer `/etc/group` una vez.** Sería 1 comando fijo, pero no ve a
quien tenga el grupo admin como **grupo primario** — eso vive en `/etc/passwd`,
no en `/etc/group`. Esa cuenta quedaría sin contar y el escaneo rechazaría un
host que sí tiene salida. `id -nG` sí resuelve ambos casos.

### Sobre la decisión 5 — de error a diagnóstico

Las tres variantes dejan de abortar la tarea y pasan a ser el motivo por el que
*cada cuenta concreta* quedó descartada, visible en el reporte:

```
Scanning accounts...
  cosmin   in wheel, but wheel grants nothing
           /usr/etc/sudoers line 24 is commented
  deploy   not in wheel
  ci-bot   key + wheel  -> KEEPS ACCESS
```

`AdminGroupGrantsNothing` es la que justifica esta decisión: describe un hecho
de la distribución —no un error de lo que el operador tecleó— y nombra el
fichero y la línea a descomentar. Esa información sigue siendo necesaria
aunque ya no venga de un campo.

Los ocho tests de `users.rs:1207-1481` se reescriben contra el diagnóstico en
vez de contra el `Err`, conservando el caso que cada uno cubre.

## Files to touch

| Fichero | Cambio |
|---------|--------|
| `src/backend/posix_accounts.rs` | Hacer `Rank` público (o exponer `list_with_rank`) sin romper `list` |
| `src/domain/accounts.rs` | Método que devuelve cuentas con rango; `list` sigue igual para los choosers |
| `src/tasks/users.rs` | `LockRoot::params()` → vacío; `verify_a_way_back_in` barre cuentas y devuelve las que pasan; eliminar `LockRoot::ADMIN` |
| `src/tui/dispatch.rs` | `open_confirmation` (~809) deja de leer `LockRoot::ADMIN`; nueva advertencia desde el escaneo, siguiendo `deletion_warning` |
| `src/i18n/mod.rs` + `en.rs` (+ resto de locales) | `ConfirmRootLockout` pasa de una cuenta a una lista; mensajes nuevos para credencial y aviso de sesión |
| `src/error.rs` | Revisar variantes que dejan de ser alcanzables (ver Open questions) |
| `docs/cli.md` | Líneas 261 y 332-339: la descripción dice «another account exists» refiriéndose a una que se nombra |
| `docs/user-stories.md` | La historia cambia: ya no se elige cuenta |
| `CHANGELOG.md` | Entrada en `[Unreleased] → Changed` |

**No rompe contrato de scripts:** `users.lock-root` ya es *interactive only* en
la CLI (`docs/cli.md:194-203`), así que ningún script pasa `admin=`.

## Steps in order (vertical slices)

### Paso 1 — El rango sale del backend
Exponer la clasificación que `list_accounts` ya calcula, sin tocar `list` ni su
contrato de sugerencias. Tests: uid 0 es `Root`; uid ≥ 1000 con shell de login
es `Human`; uid bajo el umbral **o** shell en `NON_LOGIN_SHELLS` es `System`.

### Paso 2 — El escaneo, con la tarea aún pidiendo el campo
Escribir la función que barre **todas** las cuentas, en orden de rango, y
devuelve para cada una si conserva acceso y —si no— por qué no. Aún no se toca
la UI: se prueba en aislamiento con `MockExecutor`.

Criterios por cuenta (los cuatro de hoy, sobre cada candidata):
existe · en grupo admin · el grupo concede escalada en esta familia · tiene
clave **o** contraseña.

Tests: ninguna pasa → lista vacía **y** un motivo por cuenta; varias pasan →
todas listadas con su credencial; una cuenta `System` con sudo y clave **sí**
se consulta y cuenta como salida (decisión 4); el recorrido no se detiene en la
primera que pasa.

### Paso 3 — La tarea usa el escaneo
`params()` vacío; `verify_a_way_back_in` llama al escaneo. `NoWayBackIn` deja de
nombrar una cuenta y pasa a llevar el recuento de las examinadas y el motivo de
cada descarte (decisión 6).

**Crítico:** el recheck previo al paso irreversible (`users.rs:424-437`) debe
hacer *la misma* pregunta que el guardia. El comentario allí avisa de que una
comprobación más estricta rechazaría al operador que acababa de aceptar. Con el
escaneo eso significa: volver a escanear, no comprobar una cuenta concreta.

### Paso 4 — La confirmación
`open_confirmation` construye la advertencia desde el escaneo, con la lista
desplazable (decisión 7). Marcar la cuenta de la sesión cuando
`SUDO_USER`/`DOAS_USER` responda; añadir el aviso cuando no.

### Paso 5 — Docs y CHANGELOG
`/update-docs` y entrada en `[Unreleased]`.

## Verification

- `cargo nextest run` — la suite completa
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --all`
- Contenedor: host sin ninguna cuenta válida → rechaza; host con dos → aprueba y
  lista ambas. Es el caso que un mock no puede dar, y este repo tiene historial
  de bugs que solo aparecieron en contenedor.
- **Confirmar que el escaneo falla contra el código anterior**, no asumirlo —
  la regla que el árbol ya aprendió con `no_copy_of_the_key_file_is_ever_kept`,
  un test que pasaba sobre el bug que debía impedir.

## What NOT to include

- **No** bloquear por origen de sesión. Ver «Lo descartado».
- **No** añadir un `initd revert` ni exponer `lock-root` en la CLI.
- **No** conceder escalada automáticamente donde el grupo no la da. El guardia
  refuse deliberadamente (`users.rs:507-520`): bloquear una cuenta no debe
  editar la política de escalada de paso.
- **No** tocar `list` para los choosers. Su contrato — sugerencias, nunca el
  conjunto permitido (`accounts.rs:27-30`) — sigue vigente.
- **No** mezclar el refactor del rango con el cambio de comportamiento en un
  mismo commit.
- **No** usar el rango como filtro, ni cortar el recorrido en la primera cuenta
  que pasa. Ver decisión 4: ambas cosas son la optimización obvia y ambas rompen
  lo que la confirmación promete enseñar.

## Preguntas resueltas durante la entrevista

1. **Las tres variantes de error** → se conservan como diagnóstico por cuenta
   (decisión 5). Los ocho tests se reescriben contra el diagnóstico.
2. **Umbral de uid** → medido: `FIRST_HUMAN_UID = 1000`, igual en las cinco
   familias, y `Human` exige además shell fuera de `NON_LOGIN_SHELLS`. Resuelta
   por medición, no por decisión.
3. **Cuenta `System` con acceso real** → ya no se descarta: el rango ordena pero
   no filtra (decisión 4), así que cuenta como salida.
4. **Desborde del diálogo** → panel desplazable (decisión 7), con el precedente
   de `Form::render`, que mantiene su propio estado de scroll por lo mismo.

## Open questions

Ninguna pendiente de decisión. Dos cosas a *medir* al implementar:

- **Coste real del escaneo** en un host con muchas cuentas. Si molesta, cachear
  dentro de la apertura del diálogo — nunca recortar el recorrido.
- **Si `NON_LOGIN_SHELLS` basta** en las cinco familias. Sólo afecta al orden,
  no a la cobertura, pero un `nologin` con otra ruta pondría cuentas humanas al
  final de la cola.
