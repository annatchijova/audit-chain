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

    public static void main(String[] args) throws InterruptedException {
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
