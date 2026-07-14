/*
 * audit_chain.c — Tamper-evident hash-chain audit log (C version)
 *
 * Spec (identical across C/Rust/Java):
 *   Entry = { index, timestamp_ms, event, prev_hash, hash }
 *   hash  = SHA256(index | timestamp_ms | event | prev_hash)
 *   Chain is valid iff every entry's prev_hash matches the previous
 *   entry's hash, and every entry's hash matches its own recomputed hash.
 *
 * This C version manages ALL memory manually: entries are heap-allocated,
 * strings are fixed-size buffers with explicit bounds checks. This is the
 * version where a buffer overflow or use-after-free is a real, compileable
 * possibility if you're not careful — that's the point of the comparison.
 *
 * Uses a public-domain SHA-256 implementation (no OpenSSL dependency,
 * so the binary is self-contained and portable).
 *
 * Build:   gcc -O2 -pthread -o audit_chain audit_chain.c
 * Run:     ./audit_chain [n_entries] [n_threads]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

/* ======================= SHA-256 (public domain) ======================= */
/* Minimal, self-contained SHA-256 implementation (Brad Conte's public
 * domain code, adapted). No external dependency required. */

#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            hash[j * 4 + i] = (ctx->state[j] >> (24 - i * 8)) & 0x000000ff;
        }
    }
}

static void sha256_hex(const char *input, size_t len, char out_hex[65]) {
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)input, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i) {
        /* snprintf into a fixed 3-byte window: bounds are explicit here.
         * This is exactly the kind of line that becomes a buffer overflow
         * in C if the destination size is ever miscalculated. */
        snprintf(out_hex + i * 2, 3, "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

/* Auditor finding (HIGH): snprintf's return value was previously unchecked
 * at every call site that builds the canonical content string. snprintf
 * returns the number of bytes it WOULD have written if the buffer were
 * big enough — if that exceeds the buffer size, truncation occurred
 * silently, and the hash would be computed over truncated content with
 * no indication anything was wrong. For a forensic hash chain, silently
 * hashing truncated data is unacceptable: two different long events
 * sharing the same first ~264 bytes would produce the same hash, and
 * nobody auditing the chain would know truncation happened.
 *
 * Fix: check the return value at every call site. Fail loudly (abort)
 * rather than proceed with a truncated forensic hash — this is a case
 * where "crash immediately" is strictly safer than "continue with
 * corrupted evidence." */
static int snprintf_checked(char *buf, size_t bufsize, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, bufsize, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= bufsize) {
        fprintf(stderr,
                "FATAL: content string truncated or encoding error "
                "(would-be length=%d, buffer size=%zu) — refusing to hash "
                "truncated forensic content.\n", n, bufsize);
        abort();
    }
    return n;
}

/* ======================= Audit chain data model ======================= */

#define MAX_EVENT_LEN 200
#define HASH_HEX_LEN  64

typedef struct {
    uint64_t index;
    uint64_t timestamp_ms;
    char event[MAX_EVENT_LEN + 1];   /* +1 for NUL; fixed-size buffer */
    char prev_hash[HASH_HEX_LEN + 1];
    char hash[HASH_HEX_LEN + 1];
} AuditEntry;

typedef struct {
    AuditEntry *entries;   /* heap-allocated, manually grown */
    size_t count;
    size_t capacity;
    char last_hash[HASH_HEX_LEN + 1];
    pthread_mutex_t lock;  /* protects count/capacity/entries/last_hash */
} AuditChain;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void chain_init(AuditChain *chain, size_t initial_capacity) {
    chain->entries = malloc(sizeof(AuditEntry) * initial_capacity);
    if (!chain->entries) {
        fprintf(stderr, "OOM allocating initial chain capacity\n");
        exit(1);
    }
    chain->count = 0;
    chain->capacity = initial_capacity;
    memset(chain->last_hash, '0', HASH_HEX_LEN);
    chain->last_hash[HASH_HEX_LEN] = '\0';  /* genesis prev_hash = all zeros */
    pthread_mutex_init(&chain->lock, NULL);
}

static void chain_free(AuditChain *chain) {
    free(chain->entries);          /* manual free — forget this, it's a leak */
    chain->entries = NULL;
    pthread_mutex_destroy(&chain->lock);
}

/* Manual dynamic array growth — the classic C responsibility. Get the
 * realloc wrong (e.g. forget to update the pointer on failure) and you
 * corrupt or leak memory. */
static void chain_ensure_capacity(AuditChain *chain) {
    if (chain->count >= chain->capacity) {
        size_t new_capacity = chain->capacity * 2;
        AuditEntry *new_entries = realloc(chain->entries, sizeof(AuditEntry) * new_capacity);
        if (!new_entries) {
            fprintf(stderr, "OOM growing chain to capacity %zu\n", new_capacity);
            exit(1);
        }
        chain->entries = new_entries;
        chain->capacity = new_capacity;
    }
}

/* Thread-safe append. Returns 0 on success, -1 if event too long. */
static int chain_append(AuditChain *chain, const char *event) {
    size_t event_len = strlen(event);
    if (event_len > MAX_EVENT_LEN) {
        return -1;  /* caller must check this — C will not check for you */
    }

    pthread_mutex_lock(&chain->lock);

    chain_ensure_capacity(chain);
    AuditEntry *e = &chain->entries[chain->count];
    e->index = chain->count;
    e->timestamp_ms = now_ms();
    memcpy(e->event, event, event_len);
    e->event[event_len] = '\0';
    memcpy(e->prev_hash, chain->last_hash, HASH_HEX_LEN + 1);

    /* Canonical content string: index|timestamp|event|prev_hash */
    char content[MAX_EVENT_LEN + HASH_HEX_LEN + 64];
    int n = snprintf_checked(content, sizeof(content), "%llu|%llu|%s|%s",
                      (unsigned long long)e->index,
                      (unsigned long long)e->timestamp_ms,
                      e->event, e->prev_hash);
    sha256_hex(content, (size_t)n, e->hash);

    memcpy(chain->last_hash, e->hash, HASH_HEX_LEN + 1);
    chain->count++;

    pthread_mutex_unlock(&chain->lock);
    return 0;
}

/* Verify the full chain: recompute every hash, confirm linkage. */
static int chain_verify(const AuditChain *chain) {
    char expected_prev[HASH_HEX_LEN + 1];
    memset(expected_prev, '0', HASH_HEX_LEN);
    expected_prev[HASH_HEX_LEN] = '\0';

    for (size_t i = 0; i < chain->count; ++i) {
        const AuditEntry *e = &chain->entries[i];

        if (strcmp(e->prev_hash, expected_prev) != 0) {
            fprintf(stderr, "CHAIN BROKEN at index %zu: prev_hash mismatch\n", i);
            return 0;
        }

        char content[MAX_EVENT_LEN + HASH_HEX_LEN + 64];
        int n = snprintf_checked(content, sizeof(content), "%llu|%llu|%s|%s",
                          (unsigned long long)e->index,
                          (unsigned long long)e->timestamp_ms,
                          e->event, e->prev_hash);
        char recomputed[HASH_HEX_LEN + 1];
        sha256_hex(content, (size_t)n, recomputed);

        if (strcmp(recomputed, e->hash) != 0) {
            fprintf(stderr, "CHAIN BROKEN at index %zu: hash tampered\n", i);
            return 0;
        }
        memcpy(expected_prev, e->hash, HASH_HEX_LEN + 1);
    }
    return 1;
}

/* ======================= Concurrency demo ======================= */

typedef struct {
    AuditChain *chain;
    int thread_id;
    int entries_per_thread;
} WriterArgs;

static void *writer_thread(void *arg) {
    WriterArgs *args = (WriterArgs *)arg;
    char event[64];
    for (int i = 0; i < args->entries_per_thread; ++i) {
        snprintf(event, sizeof(event), "thread_%d_write_%d", args->thread_id, i);
        chain_append(args->chain, event);
    }
    return NULL;
}

/* ======================= Attack / tamper demo ======================= */
/*
 * Three auditors (independent reviews) converged on the same finding:
 * we built the whole integrity apparatus and never actually attacked it.
 * A hash chain that was never attacked is compiled, not proven.
 *
 * This section runs four tamper scenarios against a small chain and
 * reports whether verify() catches each one:
 *
 *   1. NAIVE TAMPER    — modify one entry's event, leave its hash alone.
 *                        Expected: verify() catches it AT that index
 *                        (recomputed hash != stored hash).
 *   2. REORDER         — swap two adjacent entries in place.
 *                        Expected: verify() catches it (prev_hash link
 *                        no longer matches).
 *   3. DELETION        — remove one entry, shift the rest down.
 *                        Expected: verify() catches it (prev_hash link
 *                        broken at the seam).
 *   4. CASCADE FORGERY — modify one entry's event AND recompute that
 *                        entry's hash AND recompute every entry after it
 *                        so the whole chain is internally consistent
 *                        again. Expected: verify() DOES NOT catch it.
 *
 * Scenario 4 is the important one. A pure hash chain, on its own, proves
 * "nothing changed after I looked at the final hash" — it does NOT
 * prove "nothing changed, period," if the attacker has full write access
 * to the log AND knows the hash function (which is public). Full
 * cascade forgery is always possible against a bare hash chain. Real
 * tamper-evidence needs an external anchor: a hash published/signed
 * somewhere the attacker cannot also rewrite (offline signature, a
 * separate append-only transparency log, RFC3161 timestamping, HMAC
 * with a key never available to whoever can edit the log file). This
 * is the exact same limitation VIGIA's own KNOWN_LIMITATIONS.md
 * documents for generate_forensic_hash: the hash proves the content
 * didn't change since it was sealed, not that it was legitimate before
 * that, and not that a full-access attacker cannot reseal a forged
 * version end to end.
 */

static AuditChain *build_small_chain(int n) {
    AuditChain *c = malloc(sizeof(AuditChain));
    chain_init(c, 32);
    char event[64];
    for (int i = 0; i < n; ++i) {
        snprintf(event, sizeof(event), "genuine_event_%d", i);
        chain_append(c, event);
    }
    return c;
}

/* Recompute one entry's hash from its (possibly tampered) fields. */
static void recompute_entry_hash(AuditEntry *e) {
    char content[MAX_EVENT_LEN + HASH_HEX_LEN + 64];
    int n = snprintf_checked(content, sizeof(content), "%llu|%llu|%s|%s",
                      (unsigned long long)e->index,
                      (unsigned long long)e->timestamp_ms,
                      e->event, e->prev_hash);
    sha256_hex(content, (size_t)n, e->hash);
}

static void run_attack_demo(void) {
    printf("\n=== C: tamper / attack demo ===\n");

    /* --- Scenario 1: naive tamper --- */
    {
        AuditChain *c = build_small_chain(10);
        strcpy(c->entries[3].event, "TAMPERED_EVENT_no_hash_fix");
        int ok = chain_verify(c);
        printf("[1] Naive tamper (event changed, hash left alone):     "
               "verify()=%s  (expected: false)\n", ok ? "true" : "false");
        chain_free(c);
        free(c);
    }

    /* --- Scenario 2: reorder --- */
    {
        AuditChain *c = build_small_chain(10);
        AuditEntry tmp = c->entries[3];
        c->entries[3] = c->entries[4];
        c->entries[4] = tmp;
        int ok = chain_verify(c);
        printf("[2] Reorder (swap entries 3 and 4 in place):           "
               "verify()=%s  (expected: false)\n", ok ? "true" : "false");
        chain_free(c);
        free(c);
    }

    /* --- Scenario 3: deletion --- */
    {
        AuditChain *c = build_small_chain(10);
        for (size_t i = 3; i < c->count - 1; ++i) {
            c->entries[i] = c->entries[i + 1];
        }
        c->count -= 1;
        int ok = chain_verify(c);
        printf("[3] Deletion (remove entry 3, shift rest down):        "
               "verify()=%s  (expected: false)\n", ok ? "true" : "false");
        chain_free(c);
        free(c);
    }

    /* --- Scenario 4: full cascade forgery --- */
    {
        AuditChain *c = build_small_chain(10);
        strcpy(c->entries[3].event, "FORGED_EVENT_fully_recomputed");
        /* Attacker knows the hash function (it's public) and has full
         * write access to the log file. They recompute entry 3's hash,
         * then propagate the new hash into entry 4's prev_hash, and so
         * on to the end — exactly what a legitimate append would have
         * produced, just with different content. */
        recompute_entry_hash(&c->entries[3]);
        for (size_t i = 4; i < c->count; ++i) {
            memcpy(c->entries[i].prev_hash, c->entries[i - 1].hash, HASH_HEX_LEN + 1);
            recompute_entry_hash(&c->entries[i]);
        }
        int ok = chain_verify(c);
        printf("[4] Cascade forgery (tamper + recompute forward):      "
               "verify()=%s  (expected: TRUE — this is the limitation)\n",
               ok ? "true" : "false");
        chain_free(c);
        free(c);
    }

    printf("\nConclusion: a bare hash chain proves \"nothing changed after\n"
           "the fact I'm holding\" — it does NOT prove \"nothing changed,\n"
           "period,\" against an attacker with full write access who knows\n"
           "the (public) hash function. Scenarios 1-3 are caught because\n"
           "they're PARTIAL edits. Scenario 4 is not caught because a\n"
           "consistent chain can always be re-derived from the tamper\n"
           "point forward. Real integrity requires an external anchor\n"
           "the attacker cannot also rewrite: an offline signature, a\n"
           "separate transparency log, RFC3161 timestamping, or an HMAC\n"
           "key that never lives on the same machine as the editable log.\n");
}

/* ======================= Benchmark + main ======================= */

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "attack") == 0) {
        run_attack_demo();
        return 0;
    }

    long n_entries = (argc > 1) ? atol(argv[1]) : 100000;
    int n_threads  = (argc > 2) ? atoi(argv[2]) : 4;

    printf("=== C audit chain benchmark ===\n");
    printf("entries=%ld threads=%d\n\n", n_entries, n_threads);

    /* --- Single-threaded sequential benchmark --- */
    AuditChain chain;
    chain_init(&chain, 1024);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < n_entries; ++i) {
        char event[64];
        snprintf(event, sizeof(event), "sequential_write_%ld", i);
        if (chain_append(&chain, event) != 0) {
            fprintf(stderr, "append failed at %ld\n", i);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double write_secs = elapsed_seconds(t0, t1);
    printf("Sequential write: %.4f s  (%.0f entries/sec)\n",
           write_secs, n_entries / write_secs);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int valid = chain_verify(&chain);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double verify_secs = elapsed_seconds(t0, t1);
    printf("Verify:           %.4f s  (%.0f entries/sec)  chain_valid=%s\n",
           verify_secs, n_entries / verify_secs, valid ? "true" : "false");

    chain_free(&chain);

    /* --- Concurrent writer benchmark --- */
    printf("\n--- Concurrent writers (%d threads) ---\n", n_threads);
    AuditChain cchain;
    chain_init(&cchain, 1024);

    int entries_per_thread = (int)(n_entries / n_threads);
    pthread_t *tids = malloc(sizeof(pthread_t) * n_threads);
    WriterArgs *wargs = malloc(sizeof(WriterArgs) * n_threads);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < n_threads; ++i) {
        wargs[i].chain = &cchain;
        wargs[i].thread_id = i;
        wargs[i].entries_per_thread = entries_per_thread;
        pthread_create(&tids[i], NULL, writer_thread, &wargs[i]);
    }
    for (int i = 0; i < n_threads; ++i) {
        pthread_join(tids[i], NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double cwrite_secs = elapsed_seconds(t0, t1);
    long total_written = (long)entries_per_thread * n_threads;
    printf("Concurrent write: %.4f s  (%.0f entries/sec)  total=%ld\n",
           cwrite_secs, total_written / cwrite_secs, total_written);

    int cvalid = chain_verify(&cchain);
    printf("Chain valid after concurrent writes: %s (count=%zu)\n",
           cvalid ? "true" : "false", cchain.count);

    free(tids);
    free(wargs);
    chain_free(&cchain);

    return 0;
}
