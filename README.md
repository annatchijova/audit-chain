# Audit Chain — Rust vs C vs Java

Mismo spec exacto implementado en los tres lenguajes: un audit log
append-only con cadena de hashes SHA-256 tamper-evident (mismo patrón que
`SecurityAudit` en VIGÍA / el chain de raven-memory), verificación de
integridad completa, y un benchmark de escritura concurrente con múltiples
threads.

```
Entry = { index, timestamp_ms, event, prev_hash, hash }
hash  = SHA256(index | timestamp_ms | event | prev_hash)
Chain válida <=> cada prev_hash matchea el hash anterior,
              y cada hash matchea su propio recómputo.
```

## Cómo correr cada uno

```bash
# C
gcc -O2 -Wall -Wextra -pthread -o audit_chain audit_chain.c
./audit_chain [n_entries] [n_threads]

# Rust
cargo build --release
./target/release/audit_chain [n_entries] [n_threads]

# Java
javac AuditChain.java
java AuditChain [n_entries] [n_threads]
```

## Resultados (N=500,000 entradas, 4 threads)

| Métrica                        | C          | Rust       | Java        |
|--------------------------------|-----------:|-----------:|------------:|
| Escritura secuencial (entr/s)   | 409,247    | 362,247    | 405,464*    |
| Verificación (entr/s)           | 486,386    | 402,019    | 1,158,514*  |
| Escritura concurrente (entr/s)  | 441,423    | 268,889    | 448,658*    |
| Cadena válida tras concurrencia | ✓          | ✓          | ✓           |
| Líneas de código (sin blancos/comentarios) | 276 | 140 | 112 |

\* Java: número tomado *después* de que el JIT ya calentó (ver nota de
warmup abajo). En una corrida en frío con N=200,000 la escritura
secuencial arrancó en 47,416 entr/s — 5x más lento — hasta que se corrigió
un error de rendimiento propio (ver hallazgo #1).

## Hallazgos concretos

### 1. El hex-encoding "obvio" en Java y Rust es una trampa de rendimiento real

La primera versión de Java usaba `String.format("%02x", b)` por cada byte del
hash — parece idiomático, pero pasa por el parser de format-string en cada
llamada. La primera versión de Rust usaba `format!("{:02x}", b)` por byte, lo
que hace 32 allocaciones heap por hash bajo contención de threads.

Cambiar a tabla de lookup (`char[] HEX_DIGITS` en Java, `const HEX: &[u8; 16]`
+ `String::with_capacity(64)` en Rust) subió el rendimiento de Java más de 5x y
eliminó el cuello de botella del allocator en Rust en escritura concurrente.
Esto no es un defecto del lenguaje — es una trampa de API que cualquier profiler
destaparía en producción; queda documentado porque es exactamente el tipo de
hallazgo que un ingeniero recién llegado no vería venir.

### 2. JIT warmup es visible y medible

En la misma corrida, `Sequential write` (405K entr/s) fue más lento que
`Verify` (1.15M entr/s) — **casi 3x** — a pesar de hacer trabajo
equivalente (mismo hashing, mismo volumen). La diferencia es que `verify()`
corre *después* de que el JIT ya compiló el hot path de hashing durante
`append()`. Ni C ni Rust pagan este costo: su binario ya está compilado a
nativo desde el arranque.

### 3. Seguridad de memoria: dónde cada lenguaje pone el trabajo

| Aspecto | C | Rust | Java |
|---|---|---|---|
| Crecimiento del buffer de entradas | `realloc()` manual, hay que chequear el retorno | `Vec::push`, crece solo | `ArrayList.add`, crece solo |
| Límite de tamaño de evento | `MAX_EVENT_LEN` fijo, hay que validar antes de copiar | Ninguno — `String` no tiene tamaño fijo | Ninguno — `String` no tiene tamaño fijo |
| Acceso concurrente | `pthread_mutex_t` — lock/unlock manual, fácil de olvidar | `Mutex<T>` — el compilador rechaza el código si no se pasa por el lock | `synchronized` — monitor built-in, pero nada impide tocar el estado sin sincronizar en otro método |
| Liberación de memoria | `free()` manual — un olvido es un leak | Automática (RAII / Drop) | Automática (GC) |
| Clase de bug más probable si algo sale mal | Buffer overflow, use-after-free, leak | Error de compilación (no corre hasta que compila) | GC pause bajo carga sostenida, NPE si se descuida un null |

La fila de concurrencia es la más importante: en C, olvidarse de un
`pthread_mutex_lock` antes de tocar `chain->count` compila sin error y
produce una race condition que solo aparece bajo carga — el bug clásico de
"funciona en mi máquina, falla en producción". En Rust, el mismo error
(tocar `chain` sin pasar por `Arc<Mutex<>>`) **no compila** — el error se
mueve de "bug de producción a las 3am" a "error de compilación a las 3pm".
Java está en el medio: `synchronized` es fácil de usar correctamente en
código nuevo, pero el compilador no fuerza su uso en cada punto de acceso.

## La parte que faltaba: ¿realmente detecta el tamper?

Toda la infraestructura de arriba (hash-chain, verify(), benchmarks) no
prueba nada por sí sola si nunca se intentó romperla. Tres revisiones
independientes de este proyecto coincidieron en el mismo señalamiento:
se construyó todo el aparato de integridad y nunca se lo atacó de
verdad. Un audit log que nunca fue atacado está compilado, no probado.

Cada una de las tres implementaciones tiene un modo `attack` que
corre cuatro escenarios contra una cadena de 10 entradas:

```bash
./audit_chain attack
./target/release/audit_chain attack
java AuditChain attack
```

| # | Escenario | `verify()` esperado | Resultado real (los 3 lenguajes) |
|---|---|---|---|
| 1 | **Tamper ingenuo** — cambiar el `event` de una entrada, dejar su `hash` intacto | `false` | `false` ✓ |
| 2 | **Reorder** — intercambiar dos entradas adyacentes | `false` | `false` ✓ |
| 3 | **Borrado** — eliminar una entrada intermedia | `false` | `false` ✓ |
| 4 | **Forjado en cascada** — cambiar una entrada, recomputar su hash, y recomputar en cascada el `prev_hash`/`hash` de todas las entradas siguientes | **`true`** | **`true`** ✓ (y esto es lo importante) |

### El hallazgo real: el escenario 4

Los escenarios 1-3 son ediciones *parciales* — el atacante cambia algo y
no ajusta el resto de la cadena. `verify()` los atrapa porque el enlace
`prev_hash`/`hash` deja de coincidir.

El escenario 4 es distinto: un atacante con acceso de escritura completo
al log **y conocimiento de la fórmula de hash (que es pública)** puede
recomputar la cadena entera desde el punto de la manipulación hacia
adelante — exactamente lo que hubiera producido un append legítimo,
solo que con contenido distinto. `verify()` no tiene forma de distinguir
esto de una cadena genuina, porque **es** una cadena internamente
consistente.

Esto no es un bug de ninguna de las tres implementaciones — es una
propiedad matemática de cualquier hash-chain que no tenga un ancla
externa. Es exactamente la misma limitación que ya está documentada en
`KNOWN_LIMITATIONS.md` de VIGÍA para `generate_forensic_hash`: un hash
prueba que el contenido no cambió *después* de que alguien lo selló,
nunca que el contenido era legítimo *antes* de eso — y tampoco protege
contra alguien con acceso total que puede re-sellar una versión forjada
de punta a punta.

La integridad real requiere un ancla que el atacante no pueda también
reescribir: una firma offline con clave que nunca vive en la misma
máquina que el log editable, un transparency log externo separado,
timestamping RFC3161, o un HMAC cuya clave el atacante no tenga —
ninguna de estas tres implementaciones tiene eso hoy, y está bien que no
lo tengan: el punto del ejercicio era sentir la diferencia entre
"detecta ediciones torpes" y "es criptográficamente inviolable", que no
son lo mismo.

### Nota sobre Java y `final`

El escenario de ataque en Java usa reflection (`setAccessible(true)`)
para mutar campos declarados `final` en `Entry`. Esto es deliberado: es
un recordatorio de que la inmutabilidad de Java es una convención de
compilación, no una garantía dura, frente a un atacante que ya tiene
acceso a la JVM y puede usar reflection.

## Propiedades formales — invariantes ejecutables

Más allá de los escenarios de ataque, el proyecto tiene una suite de
invariantes formales que documentan exactamente qué promete (y qué no
promete) la cadena, como checks ejecutables:

```bash
./audit_chain invariants
./target/release/audit_chain invariants
java AuditChain invariants
```

| # | Invariante | Tipo |
|---|---|---|
| INV-1 | `append(A,B,C)` → `verify() == true` | Positiva (soundness) |
| INV-2 | `mutate(B)` → `verify() == false` | Positiva (mutation detection) |
| INV-3 | `reorder(A,B,C)` → `verify() == false` | Positiva (order detection) |
| INV-4 | `verify()` → `verify()` → mismo resultado | Positiva (idempotencia) |
| INV-5 | `hash(B) == SHA256(payload(B) \| hash(A))` | Positiva (derivación explícita) |
| INV-6 | `cascade_forgery` → `verify() == true` | **Negativa (limitación documentada)** |

INV-6 es la más interesante: el test *pasa* cuando `verify()` devuelve
`true`, porque eso es el comportamiento correcto y esperado de una hash-chain
sin ancla externa. Formalizar las limitaciones hace el sistema más confiable
que ocultarlas.

## Otros hallazgos de la auditoría cruzada, corregidos

- **C — `snprintf` sin chequear el valor de retorno (severidad HIGH).**
  `snprintf` retorna cuántos bytes *habría* escrito si el buffer fuera
  suficientemente grande. Si ese número es mayor o igual al tamaño del
  buffer, hubo truncamiento — y el código original lo ignoraba
  silenciosamente, hasheando contenido truncado sin ninguna advertencia.
  Para un log forense esto es inaceptable: dos eventos distintos que
  compartan los primeros ~264 bytes producirían el mismo hash sin que
  nadie lo note. Se corrigió con `snprintf_checked()`, que aborta
  ruidosamente (`abort()`) si detecta truncamiento — en un sistema
  forense, fallar fuerte es estrictamente más seguro que continuar con
  evidencia corrupta.

- **Rust — `GENESIS_HASH` tenía 67 caracteres, no 64.** El slicing
  `[..64]` lo cortaba correctamente en cada uso, así que no rompía nada
  en la práctica — pero era una mina para cualquier código futuro que
  asumiera `GENESIS_HASH.len() == 64` sin verificarlo. Se corrigió
  construyendo el string con `"0".repeat(64)`, igual que ya hacía la
  versión Java, eliminando la posibilidad de que el conteo esté mal.

Quedan documentados pero **no corregidos** (por alcance, no por
descuido) otros hallazgos menores de las auditorías: timestamps no
monotónicos en las tres versiones (`CLOCK_REALTIME`/`SystemTime`/
`currentTimeMillis()` pueden retroceder por ajustes NTP), `verify()`
sin lock en C (no es race condition en este programa porque se llama
después de los `join()`, pero la función no lo garantiza), y
`CountDownLatch.await()` sin timeout en Java. Ninguno afecta la
conclusión del ejercicio.

## Layout

```
audit-chain/
├── audit_chain.c   — SHA-256 propio, gestión manual de memoria, pthread
├── main.rs         — Vec/String, Arc<Mutex<>>, crate sha2
├── Cargo.toml      — dependencia: sha2 = "0.10"
├── AuditChain.java — MessageDigest built-in, ArrayList, synchronized
└── README.md       — este archivo
```
