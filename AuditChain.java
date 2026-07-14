/*
 * AuditChain.java — Tamper-evident hash-chain audit log (Java version)
 *
 * Same spec as the C and Rust versions:
 *   Entry = { index, timestamp_ms, event, prev_hash, hash }
 *   hash  = SHA256(index | timestamp_ms | event | prev_hash)
 *   Chain is valid iff every entry's prev_hash matches the previous
 *   entry's hash, and every entry's hash matches its own recomputed hash.
 *
 * Where C manages memory manually and Rust enforces exclusive access at
 * compile time via the borrow checker, Java hands memory management to the
 * garbage collector entirely: no malloc/free, no ownership rules to satisfy
 * the compiler — objects are reclaimed once unreachable, full stop. The
 * cost of that convenience is what this benchmark is partly designed to
 * surface: GC pauses under sustained allocation, visible in the numbers
 * below as latency variance that C and Rust do not have to pay.
 *
 * Concurrency here uses `synchronized` — a monitor built into every
 * object, no separate Mutex type to construct. Simpler to write than the
 * C pthread_mutex_t or the Rust Arc<Mutex<T>>, but with a real trade-off:
 * the compiler will happily let you touch shared state without
 * synchronizing anywhere else in the class, unlike Rust, where the type
 * system makes that a compile error.
 *
 * Build:  javac AuditChain.java
 * Run:    java AuditChain [n_entries] [n_threads]
 */

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class AuditChain {

    // ======================= Data model =======================

    /** Immutable audit entry. No manual buffer sizing: String and the JVM
     * heap grow as needed — there is no MAX_EVENT_LEN to violate. */
    static final class Entry {
        final long index;
        final long timestampMs;
        final String event;
        final String prevHash;
        final String hash;

        Entry(long index, long timestampMs, String event, String prevHash, String hash) {
            this.index = index;
            this.timestampMs = timestampMs;
            this.event = event;
            this.prevHash = prevHash;
            this.hash = hash;
        }
    }

    private static final String GENESIS_HASH =
            "0".repeat(64);

    private final List<Entry> entries = new ArrayList<>(1024);
    private String lastHash = GENESIS_HASH;

    // ======================= Hashing =======================

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /** Built-in MessageDigest — no external crypto dependency needed,
     * unlike the C version's self-contained SHA-256 or Rust's `sha2` crate.
     *
     * Hex encoding uses a lookup table, not String.format("%02x", b) per
     * byte — the latter is idiomatic-looking but goes through format-string
     * parsing on every call and is a well-known hot-path trap in Java.
     * A fair language comparison uses the idiom a competent Java engineer
     * would actually reach for once profiling flagged the naive version. */
    private static String sha256Hex(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            char[] out = new char[hashBytes.length * 2];
            for (int i = 0; i < hashBytes.length; i++) {
                int v = hashBytes[i] & 0xFF;
                out[i * 2] = HEX_DIGITS[v >>> 4];
                out[i * 2 + 1] = HEX_DIGITS[v & 0x0F];
            }
            return new String(out);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every JVM; this is here only
            // because the checked-exception model forces us to handle it.
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    // ======================= Append / verify =======================

    /** Synchronized: only one thread may execute this method on a given
     * instance at a time. The JVM associates a monitor with every object;
     * `synchronized` acquires and releases it automatically, no separate
     * lock object to construct (contrast: Rust's Mutex<T>, C's
     * pthread_mutex_t + explicit init/destroy). */
    synchronized void append(String event) {
        long index = entries.size();
        long timestampMs = System.currentTimeMillis();
        String prevHash = lastHash;

        String content = index + "|" + timestampMs + "|" + event + "|" + prevHash;
        String hash = sha256Hex(content);

        entries.add(new Entry(index, timestampMs, event, prevHash, hash));
        lastHash = hash;
    }

    /** Verify the full chain: recompute every hash, confirm linkage. */
    synchronized boolean verify() {
        String expectedPrev = GENESIS_HASH;

        for (Entry e : entries) {
            if (!e.prevHash.equals(expectedPrev)) {
                System.err.println("CHAIN BROKEN at index " + e.index + ": prev_hash mismatch");
                return false;
            }

            String content = e.index + "|" + e.timestampMs + "|" + e.event + "|" + e.prevHash;
            String recomputed = sha256Hex(content);

            if (!recomputed.equals(e.hash)) {
                System.err.println("CHAIN BROKEN at index " + e.index + ": hash tampered");
                return false;
            }
            expectedPrev = e.hash;
        }
        return true;
    }

    synchronized int size() {
        return entries.size();
    }

    // ======================= Benchmark + main =======================

    /**
     * Three independent reviews of this project converged on the same
     * finding: we built the whole integrity apparatus and never attacked
     * it. This runs four tamper scenarios and reports whether verify()
     * catches each — including scenario 4, which it should NOT catch:
     * a full cascade forgery. See the C version's comment for the full
     * explanation of why that is a fundamental limitation of bare hash
     * chains, not a bug in any one implementation.
     *
     * Java's Entry is declared with `final` fields, which normally means
     * immutable — but reflection can bypass that, and that is exactly
     * what this demo does, deliberately, to simulate an attacker with
     * full write access to the underlying data structure (equivalent to
     * an attacker with filesystem access rewriting a persisted log).
     */
    private static void runAttackDemo() throws Exception {
        System.out.println("\n=== Java: tamper / attack demo ===");

        java.lang.reflect.Field eventField = Entry.class.getDeclaredField("event");
        eventField.setAccessible(true);
        java.lang.reflect.Field hashField = Entry.class.getDeclaredField("hash");
        hashField.setAccessible(true);
        java.lang.reflect.Field prevHashField = Entry.class.getDeclaredField("prevHash");
        prevHashField.setAccessible(true);

        // --- Scenario 1: naive tamper ---
        {
            AuditChain c = buildSmallChain(10);
            eventField.set(c.entries.get(3), "TAMPERED_EVENT_no_hash_fix");
            boolean ok = c.verify();
            System.out.printf(
                "[1] Naive tamper (event changed, hash left alone):     verify()=%b  (expected: false)%n",
                ok);
        }

        // --- Scenario 2: reorder ---
        {
            AuditChain c = buildSmallChain(10);
            Entry tmp = c.entries.get(3);
            c.entries.set(3, c.entries.get(4));
            c.entries.set(4, tmp);
            boolean ok = c.verify();
            System.out.printf(
                "[2] Reorder (swap entries 3 and 4 in place):           verify()=%b  (expected: false)%n",
                ok);
        }

        // --- Scenario 3: deletion ---
        {
            AuditChain c = buildSmallChain(10);
            c.entries.remove(3);
            boolean ok = c.verify();
            System.out.printf(
                "[3] Deletion (remove entry 3, shift rest down):        verify()=%b  (expected: false)%n",
                ok);
        }

        // --- Scenario 4: full cascade forgery ---
        {
            AuditChain c = buildSmallChain(10);
            Entry e3 = c.entries.get(3);
            eventField.set(e3, "FORGED_EVENT_fully_recomputed");
            String newHash3 = sha256Hex(e3.index + "|" + e3.timestampMs + "|" + e3.event + "|" + e3.prevHash);
            hashField.set(e3, newHash3);
            String prevHash = newHash3;
            for (int i = 4; i < c.entries.size(); i++) {
                Entry e = c.entries.get(i);
                prevHashField.set(e, prevHash);
                String newHash = sha256Hex(e.index + "|" + e.timestampMs + "|" + e.event + "|" + prevHash);
                hashField.set(e, newHash);
                prevHash = newHash;
            }
            boolean ok = c.verify();
            System.out.printf(
                "[4] Cascade forgery (tamper + recompute forward):      verify()=%b  (expected: TRUE — this is the limitation)%n",
                ok);
        }

        System.out.println(
            "\nConclusion: a bare hash chain proves \"nothing changed after\n" +
            "the fact I'm holding\" — it does NOT prove \"nothing changed,\n" +
            "period,\" against an attacker with full write access who knows\n" +
            "the (public) hash function. Scenarios 1-3 are caught because\n" +
            "they're PARTIAL edits. Scenario 4 is not caught because a\n" +
            "consistent chain can always be re-derived from the tamper\n" +
            "point forward. Real integrity requires an external anchor the\n" +
            "attacker cannot also rewrite: an offline signature, a separate\n" +
            "transparency log, RFC3161 timestamping, or an HMAC key that\n" +
            "never lives on the same machine as the editable log.\n" +
            "\n" +
            "Note: this demo used reflection to bypass `final` on Entry's\n" +
            "fields — a reminder that Java's immutability is a compile-time\n" +
            "convention, not a hard guarantee, against a JVM-resident\n" +
            "attacker with reflection access."
        );
    }

    private static AuditChain buildSmallChain(int n) {
        AuditChain c = new AuditChain();
        for (int i = 0; i < n; i++) {
            c.append("genuine_event_" + i);
        }
        return c;
    }

    /**
     * Formal invariant suite. Run with:  java AuditChain invariants
     *
     * INV-1 (soundness)   : a well-formed chain always verifies.
     * INV-2 (mutation)    : mutating an entry's event without updating its hash
     *                       breaks verify().
     * INV-3 (order)       : reordering entries breaks verify().
     * INV-4 (idempotency) : calling verify() twice returns the same result.
     * INV-5 (derivation)  : entry[i].hash == SHA256(canonical(entry[i]) | entry[i-1].hash).
     * INV-6 (limitation)  : a full cascade forgery passes verify() — expected
     *                       behavior, not a bug. Documents the boundary of what
     *                       a bare hash chain without external anchoring promises.
     */
    private static void runInvariantTests() throws Exception {
        System.out.println("\n=== Java: formal invariant tests ===");
        int pass = 0, fail = 0;

        java.lang.reflect.Field efld = Entry.class.getDeclaredField("event");
        efld.setAccessible(true);
        java.lang.reflect.Field hfld = Entry.class.getDeclaredField("hash");
        hfld.setAccessible(true);
        java.lang.reflect.Field phfld = Entry.class.getDeclaredField("prevHash");
        phfld.setAccessible(true);

        // INV-1: a well-formed chain always verifies.
        {
            AuditChain c = buildSmallChain(3);
            boolean ok = c.verify();
            System.out.printf("[%s] INV-1  append(A,B,C) -> verify() == true%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        // INV-2: mutating an entry's event without updating its hash breaks the chain.
        {
            AuditChain c = buildSmallChain(3);
            efld.set(c.entries.get(1), "MUTATED");
            boolean ok = !c.verify();
            System.out.printf("[%s] INV-2  mutate(B) -> verify() == false%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        // INV-3: reordering entries breaks the chain.
        {
            AuditChain c = buildSmallChain(3);
            Entry tmp = c.entries.get(0);
            c.entries.set(0, c.entries.get(1));
            c.entries.set(1, tmp);
            boolean ok = !c.verify();
            System.out.printf("[%s] INV-3  reorder(A,B,C) -> verify() == false%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        // INV-4: idempotency — verify() called twice returns the same result.
        {
            AuditChain c = buildSmallChain(3);
            boolean v1 = c.verify();
            boolean v2 = c.verify();
            boolean ok = (v1 == v2);
            System.out.printf("[%s] INV-4  verify() idempotent (same result twice)%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        // INV-5: hash derivation — entries.get(1).hash is SHA256 of its own
        // fields using entries.get(0).hash as prev_hash, independently recomputed.
        // Confirms: hash(B) = SHA256(payload(B) | hash(A)).
        {
            AuditChain c = buildSmallChain(2);
            Entry a = c.entries.get(0);
            Entry b = c.entries.get(1);
            String expected = sha256Hex(b.index + "|" + b.timestampMs + "|" + b.event + "|" + a.hash);
            boolean ok = expected.equals(b.hash);
            System.out.printf("[%s] INV-5  hash(B) == SHA256(payload(B) | hash(A))%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        // INV-6 (negative): a full cascade forgery passes verify() — expected
        // property of any hash chain without external anchoring. verify() == true
        // is the CORRECT result; the check passes when it returns true.
        {
            AuditChain c = buildSmallChain(5);
            Entry e2 = c.entries.get(2);
            efld.set(e2, "FORGED_cascade");
            String h2 = sha256Hex(e2.index + "|" + e2.timestampMs + "|" + e2.event + "|" + e2.prevHash);
            hfld.set(e2, h2);
            String prev = h2;
            for (int i = 3; i < c.entries.size(); i++) {
                Entry e = c.entries.get(i);
                phfld.set(e, prev);
                String h = sha256Hex(e.index + "|" + e.timestampMs + "|" + e.event + "|" + e.prevHash);
                hfld.set(e, h);
                prev = h;
            }
            boolean ok = c.verify();
            System.out.printf("[%s] INV-6  cascade forgery -> verify() == true (expected limitation)%n", ok ? "PASS" : "FAIL");
            if (ok) pass++; else fail++;
        }

        System.out.printf("%nInvariant tests: %d passed, %d failed.%n", pass, fail);
    }

    public static void main(String[] args) throws Exception {
        // Force UTF-8 stdout regardless of platform default charset — the
        // attack demo's conclusion text uses em-dashes, and a JVM running
        // with a non-UTF-8 default (common outside en_US.UTF-8 locales)
        // would otherwise mangle them into '?'.
        System.setOut(new java.io.PrintStream(System.out, true, "UTF-8"));

        if (args.length > 0 && args[0].equals("attack")) {
            runAttackDemo();
            return;
        }
        if (args.length > 0 && args[0].equals("invariants")) {
            runInvariantTests();
            return;
        }

        long nEntries = args.length > 0 ? Long.parseLong(args[0]) : 200_000L;
        int nThreads = args.length > 1 ? Integer.parseInt(args[1]) : 4;

        System.out.println("=== Java audit chain benchmark ===");
        System.out.printf("entries=%d threads=%d%n%n", nEntries, nThreads);

        // --- Single-threaded sequential benchmark ---
        AuditChain chain = new AuditChain();

        long t0 = System.nanoTime();
        for (long i = 0; i < nEntries; i++) {
            chain.append("sequential_write_" + i);
        }
        double writeSecs = (System.nanoTime() - t0) / 1e9;
        System.out.printf("Sequential write: %.4f s  (%.0f entries/sec)%n",
                writeSecs, nEntries / writeSecs);

        t0 = System.nanoTime();
        boolean valid = chain.verify();
        double verifySecs = (System.nanoTime() - t0) / 1e9;
        System.out.printf("Verify:           %.4f s  (%.0f entries/sec)  chain_valid=%b%n",
                verifySecs, nEntries / verifySecs, valid);

        // --- Concurrent writer benchmark ---
        System.out.println("\n--- Concurrent writers (" + nThreads + " threads) ---");
        AuditChain cchain = new AuditChain();
        long entriesPerThread = nEntries / nThreads;
        CountDownLatch latch = new CountDownLatch(nThreads);

        t0 = System.nanoTime();
        for (int t = 0; t < nThreads; t++) {
            final int tid = t;
            Thread thread = new Thread(() -> {
                for (long i = 0; i < entriesPerThread; i++) {
                    cchain.append("thread_" + tid + "_write_" + i);
                }
                latch.countDown();
            });
            thread.start();
        }
        latch.await();
        double cwriteSecs = (System.nanoTime() - t0) / 1e9;
        long totalWritten = entriesPerThread * nThreads;
        System.out.printf("Concurrent write: %.4f s  (%.0f entries/sec)  total=%d%n",
                cwriteSecs, totalWritten / cwriteSecs, totalWritten);

        boolean cvalid = cchain.verify();
        System.out.printf("Chain valid after concurrent writes: %b (count=%d)%n",
                cvalid, cchain.size());
    }
}
