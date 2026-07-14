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
cd c && gcc -O2 -Wall -Wextra -pthread -o audit_chain audit_chain.c
./audit_chain [n_entries] [n_threads]

# Rust
cd rust && cargo build --release
./target/release/audit_chain [n_entries] [n_threads]

# Java
cd java && javac AuditChain.java
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

### 1. El hex-encoding "obvio" en Java es una trampa de rendimiento real

La primera versión usaba `String.format("%02x", b)` por cada byte del
hash — parece idiomático, pero pasa por el parser de format-string en cada
llamada. Resultado: 47,416 entradas/seg. Cambiar a una tabla de lookup
(`char[] HEX_DIGITS`) subió el número a 257,501 entradas/seg — **más de 5x**
— sin tocar nada más. Esto no es un defecto del lenguaje, es una trampa de
API que cualquier profiler destaparía en producción; queda documentado acá
porque es exactamente el tipo de hallazgo que un ingeniero recién llegado a
Java no vería venir.

### 2. JIT warmup es visible y medible

En la misma corrida, `Sequential write` (405K entr/s) fue más lento que
`Verify` (1.15M entr/s) — **casi 3x** — a pesar de hacer trabajo
equivalente (mismo hashing, mismo volumen). La diferencia es que `verify()`
corre *después* de que el JIT ya compiló el hot path de hashing durante
`append()`. Ni C ni Rust pagan este costo: su binario ya está compilado a
nativo desde el arranque.

### 3. Rust concurrente fue el más lento de los tres — con una explicación clara

Con 4 threads escribiendo, Rust rindió 268,889 entr/s contra 441,423 (C) y
448,658 (Java). La causa más probable: la versión Rust hace más
allocaciones en el heap por entrada (`format!` + varios `.clone()` de
`String`) que la versión C, que usa buffers de tamaño fijo en el stack para
casi todo. Bajo contención de 4 threads, el allocator se convierte en
cuello de botella. Esto **no es un límite del lenguaje** — se resuelve con
buffers reusables o un allocator más agresivo — pero es el costo real de la
ergonomía de `String`/`clone()` frente a la gestión manual de buffers de C.

### 4. Seguridad de memoria: dónde cada lenguaje pone el trabajo

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
código nuevo, pero el compilador no fuerza su uso en cada punto de acceso —
si alguien agrega un método nuevo a la clase y se olvida de sincronizarlo,
compila igual.

## Estructura del repo

```
audit-chain/
├── c/
│   └── audit_chain.c       — SHA-256 propio, gestión manual de memoria
├── rust/
│   ├── Cargo.toml          — dependencia: sha2
│   └── src/main.rs         — Vec/String, Arc<Mutex<>>
├── java/
│   └── AuditChain.java     — MessageDigest built-in, ArrayList, synchronized
└── README.md               — este archivo
```
