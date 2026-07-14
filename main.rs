//! audit_chain — Tamper-evident hash-chain audit log (Rust version)
//!
//! Same spec as the C and Java versions:
//!   Entry = { index, timestamp_ms, event, prev_hash, hash }
//!   hash  = SHA256(index | timestamp_ms | event | prev_hash)
//!   Chain is valid iff every entry's prev_hash matches the previous
//!   entry's hash, and every entry's hash matches its own recomputed hash.
//!
//! Where the C version manages memory manually (malloc/realloc/free,
//! fixed-size buffers with explicit bounds checks), this version leans on
//! ownership: `Vec<AuditEntry>` grows safely, `String` cannot overflow a
//! fixed buffer, and the borrow checker enforces at compile time that only
//! one thread can mutate the chain at a time — the same invariant C enforces
//! at runtime with a pthread_mutex_t, except here it's a compile error to
//! get it wrong, not a race condition to debug.
//!
//! Build:  cargo build --release
//! Run:    ./target/release/audit_chain [n_entries] [n_threads]

use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// Exactly 64 hex chars (SHA-256 digest length), built with `.repeat()`
// the same way the Java version does (`"0".repeat(64)`) — auditor
// finding: an earlier version of this constant was a hardcoded literal
// with 67 characters that relied on `[..64]` slicing elsewhere to
// truncate it correctly. Functionally harmless (every use site sliced
// to 64), but a landmine for any future reader who assumes
// `GENESIS_HASH.len() == 64` without checking. Building it
// programmatically removes the possibility of the count being wrong.
fn genesis_hash() -> String {
    "0".repeat(64)
}

#[derive(Clone, Debug)]
struct AuditEntry {
    index: u64,
    timestamp_ms: u64,
    event: String,
    prev_hash: String,
    hash: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

fn sha256_hex(content: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    // Lookup table instead of format!("{:02x}", b) per byte: that pattern
    // allocates one String per byte (32 allocations per hash call), which
    // is the dominant throughput bottleneck under concurrent write load.
    // With_capacity(64) makes one allocation; the lookup table avoids
    // format-string parsing entirely.
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// The audit chain itself. No manual capacity management: `Vec::push`
/// handles growth; there is no realloc failure path to get wrong because
/// Rust aborts cleanly on allocation failure rather than returning a null
/// pointer you might forget to check.
struct AuditChain {
    entries: Vec<AuditEntry>,
    last_hash: String,
}

impl AuditChain {
    fn new() -> Self {
        AuditChain {
            entries: Vec::with_capacity(1024),
            last_hash: genesis_hash(),
        }
    }

    /// Append one entry. Takes `&mut self` — the borrow checker guarantees
    /// at compile time that no other reference to this chain exists while
    /// this call is in progress, in a single-threaded context. For the
    /// concurrent case below, that guarantee is upgraded to a runtime lock
    /// via `Mutex`, but the *shape* of the safety is the same idea taken
    /// further: exclusive access, enforced structurally.
    fn append(&mut self, event: &str) {
        let index = self.entries.len() as u64;
        let timestamp_ms = now_ms();
        let prev_hash = self.last_hash.clone();

        let content = format!("{}|{}|{}|{}", index, timestamp_ms, event, prev_hash);
        let hash = sha256_hex(&content);

        self.last_hash = hash.clone();
        self.entries.push(AuditEntry {
            index,
            timestamp_ms,
            event: event.to_string(),
            prev_hash,
            hash,
        });
    }

    /// Verify the full chain: recompute every hash, confirm linkage.
    /// Takes `&self` (shared, read-only borrow) — the type system documents
    /// that verification cannot mutate the chain, which is not something
    /// the C signature `int chain_verify(const AuditChain *chain)` enforces
    /// beyond a `const` that a careless cast could discard.
    fn verify(&self) -> bool {
        let mut expected_prev = genesis_hash();

        for e in &self.entries {
            if e.prev_hash != expected_prev {
                eprintln!("CHAIN BROKEN at index {}: prev_hash mismatch", e.index);
                return false;
            }

            let content = format!(
                "{}|{}|{}|{}",
                e.index, e.timestamp_ms, e.event, e.prev_hash
            );
            let recomputed = sha256_hex(&content);

            if recomputed != e.hash {
                eprintln!("CHAIN BROKEN at index {}: hash tampered", e.index);
                return false;
            }
            expected_prev = e.hash.clone();
        }
        true
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn build_small_chain(n: u64) -> AuditChain {
    let mut c = AuditChain::new();
    for i in 0..n {
        c.append(&format!("genuine_event_{}", i));
    }
    c
}

fn recompute_hash(e: &AuditEntry) -> String {
    sha256_hex(&format!(
        "{}|{}|{}|{}",
        e.index, e.timestamp_ms, e.event, e.prev_hash
    ))
}

/// Three independent reviews of this project converged on the same
/// finding: we built the whole integrity apparatus and never attacked
/// it. This runs four tamper scenarios and reports whether `verify()`
/// catches each — including scenario 4, which it should NOT catch: a
/// full cascade forgery. See the C version's comment for the full
/// explanation of why that is a fundamental limitation of bare hash
/// chains, not a bug in this implementation.
fn run_attack_demo() {
    println!("\n=== Rust: tamper / attack demo ===");

    // --- Scenario 1: naive tamper ---
    {
        let mut c = build_small_chain(10);
        c.entries[3].event = "TAMPERED_EVENT_no_hash_fix".to_string();
        let ok = c.verify();
        println!(
            "[1] Naive tamper (event changed, hash left alone):     verify()={}  (expected: false)",
            ok
        );
    }

    // --- Scenario 2: reorder ---
    {
        let mut c = build_small_chain(10);
        c.entries.swap(3, 4);
        let ok = c.verify();
        println!(
            "[2] Reorder (swap entries 3 and 4 in place):           verify()={}  (expected: false)",
            ok
        );
    }

    // --- Scenario 3: deletion ---
    {
        let mut c = build_small_chain(10);
        c.entries.remove(3);
        let ok = c.verify();
        println!(
            "[3] Deletion (remove entry 3, shift rest down):        verify()={}  (expected: false)",
            ok
        );
    }

    // --- Scenario 4: full cascade forgery ---
    {
        let mut c = build_small_chain(10);
        c.entries[3].event = "FORGED_EVENT_fully_recomputed".to_string();
        // Attacker knows the hash function (it's public) and has full
        // write access. Recompute entry 3's hash, then propagate into
        // entry 4's prev_hash, and so on to the end.
        c.entries[3].hash = recompute_hash(&c.entries[3]);
        for i in 4..c.entries.len() {
            c.entries[i].prev_hash = c.entries[i - 1].hash.clone();
            let new_hash = recompute_hash(&c.entries[i]);
            c.entries[i].hash = new_hash;
        }
        let ok = c.verify();
        println!(
            "[4] Cascade forgery (tamper + recompute forward):      verify()={}  (expected: TRUE — this is the limitation)",
            ok
        );
    }

    println!(
        "\nConclusion: a bare hash chain proves \"nothing changed after\n\
         the fact I'm holding\" — it does NOT prove \"nothing changed,\n\
         period,\" against an attacker with full write access who knows\n\
         the (public) hash function. Scenarios 1-3 are caught because\n\
         they're PARTIAL edits. Scenario 4 is not caught because a\n\
         consistent chain can always be re-derived from the tamper\n\
         point forward. Real integrity requires an external anchor the\n\
         attacker cannot also rewrite: an offline signature, a separate\n\
         transparency log, RFC3161 timestamping, or an HMAC key that\n\
         never lives on the same machine as the editable log."
    );
}

/// Formal invariant suite. Run with:  ./audit_chain invariants
///
/// INV-1 (soundness)   : a well-formed chain always verifies.
/// INV-2 (mutation)    : mutating an entry's event without updating its hash
///                       breaks verify().
/// INV-3 (order)       : reordering entries breaks verify().
/// INV-4 (idempotency) : verify() called twice returns the same result.
/// INV-5 (derivation)  : entry[i].hash == SHA256(canonical(entry[i]) | entry[i-1].hash).
/// INV-6 (limitation)  : a full cascade forgery passes verify() — expected
///                       behavior, not a bug. Documents what a bare hash
///                       chain without external anchoring actually promises.
fn run_invariant_tests() {
    println!("\n=== Rust: formal invariant tests ===");
    let mut pass = 0u32;
    let mut fail = 0u32;

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
                println!("[PASS] {}", $label);
                pass += 1;
            } else {
                println!("[FAIL] {}", $label);
                fail += 1;
            }
        };
    }

    // INV-1: a well-formed chain always verifies.
    {
        let c = build_small_chain(3);
        check!("INV-1  append(A,B,C) -> verify() == true", c.verify());
    }

    // INV-2: mutating an entry's event without updating its hash breaks the chain.
    {
        let mut c = build_small_chain(3);
        c.entries[1].event = "MUTATED".to_string();
        check!("INV-2  mutate(B) -> verify() == false", !c.verify());
    }

    // INV-3: reordering entries breaks the chain.
    {
        let mut c = build_small_chain(3);
        c.entries.swap(0, 1);
        check!("INV-3  reorder(A,B,C) -> verify() == false", !c.verify());
    }

    // INV-4: idempotency — verify() called twice returns the same result.
    {
        let c = build_small_chain(3);
        let v1 = c.verify();
        let v2 = c.verify();
        check!("INV-4  verify() idempotent (same result twice)", v1 == v2);
    }

    // INV-5: hash derivation — entries[1].hash is SHA256 of its own fields
    // with entries[0].hash as prev_hash, independently recomputed here.
    // Confirms: hash(B) = SHA256(payload(B) | hash(A)).
    {
        let c = build_small_chain(2);
        let a_hash = c.entries[0].hash.clone();
        let b = &c.entries[1];
        let expected = sha256_hex(&format!(
            "{}|{}|{}|{}",
            b.index, b.timestamp_ms, b.event, a_hash
        ));
        check!(
            "INV-5  hash(B) == SHA256(payload(B) | hash(A))",
            expected == b.hash
        );
    }

    // INV-6 (negative): a full cascade forgery passes verify() — expected
    // property of any hash chain without external anchoring. verify() == true
    // is the CORRECT result; the check passes when it returns true.
    {
        let mut c = build_small_chain(5);
        c.entries[2].event = "FORGED_cascade".to_string();
        c.entries[2].hash = recompute_hash(&c.entries[2]);
        for i in 3..c.entries.len() {
            let prev = c.entries[i - 1].hash.clone();
            c.entries[i].prev_hash = prev;
            let new_hash = recompute_hash(&c.entries[i]);
            c.entries[i].hash = new_hash;
        }
        check!(
            "INV-6  cascade forgery -> verify() == true (expected limitation)",
            c.verify()
        );
    }

    println!("\nInvariant tests: {} passed, {} failed.", pass, fail);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(|s| s.as_str()) == Some("attack") {
        run_attack_demo();
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("invariants") {
        run_invariant_tests();
        return;
    }

    let n_entries: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let n_threads: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    println!("=== Rust audit chain benchmark ===");
    println!("entries={} threads={}\n", n_entries, n_threads);

    // --- Single-threaded sequential benchmark ---
    let mut chain = AuditChain::new();

    let t0 = Instant::now();
    for i in 0..n_entries {
        chain.append(&format!("sequential_write_{}", i));
    }
    let write_secs = t0.elapsed().as_secs_f64();
    println!(
        "Sequential write: {:.4} s  ({:.0} entries/sec)",
        write_secs,
        n_entries as f64 / write_secs
    );

    let t0 = Instant::now();
    let valid = chain.verify();
    let verify_secs = t0.elapsed().as_secs_f64();
    println!(
        "Verify:           {:.4} s  ({:.0} entries/sec)  chain_valid={}",
        verify_secs,
        n_entries as f64 / verify_secs,
        valid
    );

    // --- Concurrent writer benchmark ---
    // Arc<Mutex<AuditChain>>: shared ownership across threads (Arc) plus
    // exclusive-access-on-write (Mutex). The compiler will not let this
    // code build if a thread tries to touch `chain` without going through
    // the lock — there is no way to "forget" the mutex the way a C
    // function can forget to call pthread_mutex_lock before touching
    // shared state. Fearless concurrency: the fear is moved from runtime
    // debugging to compile-time rejection.
    println!("\n--- Concurrent writers ({} threads) ---", n_threads);
    let cchain = Arc::new(Mutex::new(AuditChain::new()));
    let entries_per_thread = n_entries / n_threads as u64;

    let t0 = Instant::now();
    let mut handles = Vec::new();
    for tid in 0..n_threads {
        let chain_ref = Arc::clone(&cchain);
        let handle = thread::spawn(move || {
            for i in 0..entries_per_thread {
                let event = format!("thread_{}_write_{}", tid, i);
                // Lock scope is minimal: acquire, append, drop before the
                // next loop iteration's format! runs — the lock guard's
                // Drop impl releases it automatically, no unlock() to forget.
                let mut c = chain_ref.lock().expect("mutex poisoned");
                c.append(&event);
            }
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().expect("writer thread panicked");
    }
    let cwrite_secs = t0.elapsed().as_secs_f64();
    let total_written = entries_per_thread * n_threads as u64;
    println!(
        "Concurrent write: {:.4} s  ({:.0} entries/sec)  total={}",
        cwrite_secs,
        total_written as f64 / cwrite_secs,
        total_written
    );

    let cchain_locked = cchain.lock().expect("mutex poisoned");
    let cvalid = cchain_locked.verify();
    println!(
        "Chain valid after concurrent writes: {} (count={})",
        cvalid,
        cchain_locked.len()
    );
}
