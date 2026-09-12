//! Where a key refresh runs, what bounds it, and what the revocation bound does not cover.
//!
//! The cells in `super` and in `super::review` assert the two triggers, the rate limit and the
//! one-read-per-window bound under concurrency. These assert the three things none of them could
//! see, because all three are about a look that is slow, that fails, or that hands back something
//! this deployment will not adopt:
//!
//! | Cell | What it holds |
//! | --- | --- |
//! | [`a_held_source_read_does_not_block_the_executor`] | the read and the parse are off the async worker thread |
//! | [`a_read_lasting_beyond_its_window_does_not_start_a_second_one`] | one look in flight, whatever the windows say - which is also what makes two looks completing out of order unreachable |
//! | [`a_source_that_stays_unreadable_keeps_the_keys_and_says_how_stale_they_are`] | the availability half of the policy, and the measurement the documented bound lacked |
//! | [`a_document_that_stays_unusable_is_never_a_successful_refresh`] | a rejected document does not become a freshness stamp by being read twice |
//! | [`a_refresh_that_recovers_confirms_the_keys_again`] | the policy is not one-way: a source that comes back resets it |
//! | [`a_key_set_document_over_the_byte_bound_is_refused_rather_than_read`] | the bound on the work itself, in the one source that ships |
//!
//! **The instrument is a fake at the port**, [`ScriptedSource`], and the two timing cells hold one
//! look inside it on a `std::sync::Barrier` released by an OS thread that is **not** the runtime's.
//! That is what makes the failing direction a failure rather than a deadlock: on a build whose read
//! runs inline on the executor, nothing scheduled on the runtime could ever let the read go.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sutura_config::KeyFamily;

use super::KID;
use super::fixtures::{jwks, key_pair};
use crate::inbound::keys::{FileKeySet, KeyId, KeySetCache, KeySetSource, KeySetUnavailable, MAX_KEY_SET_BYTES, Refreshed};

/// How long a held look stays held.
///
/// **A liveness grace and not a proof.** It is the window in which a free executor has to run a
/// one-millisecond ticker at least once; on a build whose read blocks the executor **no** grace
/// produces a single tick, so this number cannot turn a red into a green in either direction - only
/// a green into a red, and only on a machine that cannot schedule a task in a fifth of a second.
const GRACE: Duration = Duration::from_millis(200);

/// Both windows wide open, so every cell here decides when a look happens by the instant it passes.
const IMMEDIATELY: Duration = Duration::from_millis(1);

/// A document that parses as JSON and holds no key this deployment could verify with.
const UNUSABLE: &str = "{\"keys\":[]}";

/// A key set source a cell scripts look by look, and may hold one look inside.
///
/// **One fake rather than three**, because these cells differ only in the script. Two things
/// distinguish it from `super::fixtures::StubSource`, and each is a case that one cannot express:
/// a look past the end of the script **fails** rather than repeating the last document, which is
/// what a source that primes and then goes away looks like; and one look can be **held**, which is
/// what a slow source looks like.
struct ScriptedSource {
    /// One entry per look, in order. `None` is a look that fails, and so is a look past the end.
    script: Vec<Option<String>>,
    /// Which look waits at [`Self::gate`], if any. Look zero is the priming read, so a cell that
    /// wants the first *refresh* held names look one.
    hold_at: Option<usize>,
    /// Two waiters: the held look, and whoever releases it.
    gate: Arc<std::sync::Barrier>,
    /// How many looks have been taken. `AtomicUsize` rather than a lock, because `clippy.toml` bans
    /// `std::sync::Mutex` and there is nothing here to mutate but a counter.
    calls: AtomicUsize,
}

impl KeySetSource for ScriptedSource {
    fn read(&self) -> Result<String, KeySetUnavailable> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hold_at == Some(call) {
            // Blocking, on whichever thread this is. That is the whole instrument: a cell asserts
            // what the rest of the process can still do while this line has not returned.
            let _released = self.gate.wait();
        }
        self.script
            .get(call)
            .cloned()
            .flatten()
            .ok_or_else(|| KeySetUnavailable::Unreadable {
                path: std::path::PathBuf::from("a scripted source"),
                cause: std::io::Error::other("this look was scripted to fail"),
            })
    }
}

/// So a cell keeps the counter and the gate while the cache owns the source.
impl KeySetSource for Arc<ScriptedSource> {
    fn read(&self) -> Result<String, KeySetUnavailable> {
        self.as_ref().read()
    }
}

/// A primed cache over a script, and the source to read afterwards.
///
/// Both windows are [`IMMEDIATELY`], so a look happens whenever an instant a cell passes is past
/// the last attempt - which is what lets every cell here be written without a sleep. The family is
/// the elliptic-curve one because every generated key here is.
fn scripted(script: &[Option<String>], hold_at: Option<usize>, now: Instant) -> (KeySetCache, Arc<ScriptedSource>) {
    let source = Arc::new(ScriptedSource {
        script: script.to_vec(),
        hold_at,
        gate: Arc::new(std::sync::Barrier::new(2)),
        calls: AtomicUsize::new(0),
    });
    let cache = KeySetCache::primed_with_window(
        Box::new(Arc::clone(&source)),
        KeyFamily::EllipticCurve,
        String::from("ES256"),
        IMMEDIATELY,
        IMMEDIATELY,
        now,
    )
    .expect("the first look primes the cache");
    (cache, source)
}

/// Lets the held look go, from a thread that is not the runtime's.
///
/// It sleeps first rather than waiting for the look to arrive: `Barrier::wait` already blocks until
/// the other waiter is there, so the sleep is only the grace the cell needs, and there is nothing
/// for this thread to observe.
fn releases_after_the_grace(source: &Arc<ScriptedSource>) -> std::thread::JoinHandle<()> {
    let gate = Arc::clone(&source.gate);
    std::thread::spawn(move || {
        std::thread::sleep(GRACE);
        let _released = gate.wait();
    })
}

// ------------------------------------------------- where the read and the parse run ----

#[tokio::test]
async fn a_held_source_read_does_not_block_the_executor() {
    // **The first half of the finding.** `KeySetSource::read` is synchronous and the parse behind it
    // is CPU work over a foreign document, and both ran inline in an `async fn` - so a slow key set
    // read blocked the worker thread that was serving requests, from the timer as much as from a
    // caller.
    //
    // This runs on the default current-thread runtime ON PURPOSE: with one executor thread, "another
    // task made progress" and "the read is not on the executor" are the same statement. The ticker
    // is what makes it observable, and the OS thread that releases the read is what makes the
    // failing direction terminate - see this module's header.
    let pair = key_pair();
    let now = Instant::now();
    let (cache, source) = scripted(&[Some(jwks(KID, &pair)), Some(jwks(KID, &pair))], Some(1), now);
    let releaser = releases_after_the_grace(&source);

    let beats = Arc::new(AtomicUsize::new(0));
    let ticker = tokio::spawn({
        let beats = Arc::clone(&beats);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                let _previous = beats.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let outcome = cache.poll_once(now + Duration::from_secs(1)).await;
    ticker.abort();
    releaser.join().expect("the releasing thread does not panic");

    assert_eq!(source.calls.load(Ordering::SeqCst), 2, "the held look happened");
    assert_eq!(outcome, Refreshed::Unchanged, "the same document came back: {outcome:?}");
    assert!(
        beats.load(Ordering::SeqCst) > 0,
        "no task made any progress while a source read was in flight, so the read ran on the executor"
    );
}

#[tokio::test]
async fn a_read_lasting_beyond_its_window_does_not_start_a_second_one() {
    // Moving the read off the executor is not by itself a bound: a started blocking task cannot be
    // aborted, so without a second gate a source slower than its own window accumulates one detached
    // read per window - and two of them completing out of order install the OLDER document, because
    // `adopt` compares against the last bytes examined and a late arrival therefore looks like a
    // change. `Cached::reading` makes that unreachable, which is why there is no separate ordering
    // cell: with one look in flight there is no ordering to get wrong.
    //
    // The third document is the assertion's teeth. If a second look happened it would rotate the key
    // set, so `describe` says whether one did even beyond the count.
    let first = key_pair();
    let second = key_pair();
    let now = Instant::now();
    let (cache, source) = scripted(
        &[
            Some(jwks(KID, &first)),
            Some(jwks(KID, &first)),
            Some(jwks("the-next-key", &second)),
        ],
        Some(1),
        now,
    );
    let releaser = releases_after_the_grace(&source);
    let cache = Arc::new(cache);

    let held = tokio::spawn({
        let cache = Arc::clone(&cache);
        async move { cache.poll_once(now + Duration::from_secs(1)).await }
    });
    // Let the held look start. One yield is enough - the reservation and the spawn both happen before
    // the task's first await - and the loop is bounded so that a build which never starts a look
    // fails on the assertions below rather than spinning here.
    for _ in 0..64_u16 {
        if source.calls.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // A second trigger a whole window later, while the first look is still inside the source.
    let outcome = cache.poll_once(now + Duration::from_secs(2)).await;
    assert_eq!(
        outcome,
        Refreshed::NotDue,
        "a look already in flight has to win the reservation: {outcome:?}"
    );
    let held = held.await.expect("the held task does not panic");
    assert_eq!(held, Refreshed::Unchanged, "{held:?}");
    releaser.join().expect("the releasing thread does not panic");

    assert_eq!(
        source.calls.load(Ordering::SeqCst),
        2,
        "a read outlasting its own window must not start a second one"
    );
    let (count, ids) = cache.describe().await;
    assert_eq!(count, 1);
    assert_eq!(ids, vec![String::from(KID)], "nothing may rotate behind a held look");
}

// ----------------------------------- what a failing refresh does, and does not, bound ----

#[tokio::test]
async fn a_source_that_stays_unreadable_keeps_the_keys_and_says_how_stale_they_are() {
    // **The second half of the finding, and the policy.** The documented bound is `MAX_KEY_SET_AGE`
    // plus one source read; a reservation stamps the ATTEMPT, so under a dead source that number
    // stays one window old for as long as the process lives while nothing has confirmed the keys
    // since boot. Both halves are asserted here on purpose:
    //
    // - the keys keep verifying, which is the availability decision. Refusing instead would take a
    //   deployment's authentication down over a sidecar mid-rewrite, and which way that default
    //   points is `github.com/telekom/sutura#141`'s call rather than this file's.
    // - the reported staleness grows, which is the correctness decision. A retained key set with no
    //   measurement is what let a finite bound be claimed for a case that has none.
    let pair = key_pair();
    let now = Instant::now();
    // One usable document and then nothing: every look past the script fails.
    let (cache, source) = scripted(&[Some(jwks(KID, &pair))], None, now);
    let id = KeyId::parse(KID).expect("a test key id is a key id");

    for window in 1..=10_u64 {
        let later = now + Duration::from_secs(window);
        let outcome = cache.poll_once(later).await;
        assert_ne!(
            outcome,
            Refreshed::Unchanged,
            "a source that answered nothing is not an unchanged document"
        );
        assert_eq!(outcome, Refreshed::Unavailable, "{outcome:?}");
        drop(
            cache
                .key_for(&id, later)
                .await
                .expect("the keys in use keep verifying while refresh is unavailable"),
        );
        assert_eq!(
            cache.stale_for(later).await,
            Duration::from_secs(window),
            "staleness is measured from the last SUCCESS, and the boot read is the only one there was"
        );
    }
    assert_eq!(
        source.calls.load(Ordering::SeqCst),
        11,
        "a dead source is still read at most once per window - the rate limit is stamped on the attempt"
    );
}

#[tokio::test]
async fn a_document_that_stays_unusable_is_never_a_successful_refresh() {
    // **The trap this cell exists for.** `adopt` records a rejected document as EXAMINED, so that
    // identical bytes on the next look are silent rather than an error once per interval forever -
    // and the look after a rejection therefore returns `Refreshed::Unchanged` over bytes this
    // deployment refused. A freshness stamp taken on that variant would be stamped by a document the
    // deployment would not use, which is the exact shape of the defect being fixed. It is decided by
    // the candidate's own parse instead.
    let pair = key_pair();
    let now = Instant::now();
    let (cache, _source) = scripted(
        &[
            Some(jwks(KID, &pair)),
            Some(String::from(UNUSABLE)),
            Some(String::from(UNUSABLE)),
            Some(String::from(UNUSABLE)),
        ],
        None,
        now,
    );
    let id = KeyId::parse(KID).expect("a test key id is a key id");

    let first = now + Duration::from_secs(1);
    assert_eq!(cache.poll_once(first).await, Refreshed::Rejected);
    assert_eq!(cache.stale_for(first).await, Duration::from_secs(1));
    // The two looks that matter: identical unusable bytes, reported as unchanged, and NOT a success.
    for window in 2..=3_u64 {
        let later = now + Duration::from_secs(window);
        assert_eq!(cache.poll_once(later).await, Refreshed::Unchanged);
        assert_eq!(
            cache.stale_for(later).await,
            Duration::from_secs(window),
            "a second look at a document this deployment rejected must not count as a refresh"
        );
    }
    drop(
        cache
            .key_for(&id, now + Duration::from_secs(3))
            .await
            .expect("the previous keys keep verifying when a candidate is refused"),
    );
}

#[tokio::test]
async fn a_refresh_that_recovers_confirms_the_keys_again() {
    // The policy is not one-way, which is the half an availability argument has to show: a source
    // that comes back rotates and resets the measurement, so the staleness is a live number rather
    // than a ratchet. Without this cell, "nothing refuses on it" and "nothing ever clears it" would
    // read the same.
    let old = key_pair();
    let new = key_pair();
    let now = Instant::now();
    let (cache, _source) = scripted(
        &[Some(jwks(KID, &old)), None, None, Some(jwks("the-next-key", &new))],
        None,
        now,
    );

    for window in 1..=2_u64 {
        let later = now + Duration::from_secs(window);
        assert_eq!(cache.poll_once(later).await, Refreshed::Unavailable);
        assert_eq!(cache.stale_for(later).await, Duration::from_secs(window));
    }
    let recovered = now + Duration::from_secs(3);
    assert_eq!(cache.poll_once(recovered).await, Refreshed::Rotated);
    assert_eq!(
        cache.stale_for(recovered).await,
        Duration::ZERO,
        "a successful refresh is the only thing that resets the measurement"
    );
    let (count, ids) = cache.describe().await;
    assert_eq!(count, 1);
    assert_eq!(ids, vec![String::from("the-next-key")]);
}

// -------------------------------------------------- the bound on the work itself ----

#[test]
fn a_key_set_document_over_the_byte_bound_is_refused_rather_than_read() {
    // `std::fs::read_to_string` read whatever was at the path, so the read and the parse behind it
    // were work proportional to the file - a denial-of-service primitive whatever else it is, and one
    // a sidecar mistake reaches as easily as anything else does.
    //
    // The real source and not a fake, because the bound lives in the implementor: the port hands back
    // an owned `String`, so nothing above it could object once the allocation had happened. The
    // scratch file is named after the process and removed again, which is what the one other
    // filesystem cell in this suite does.
    let path = std::env::temp_dir().join(format!("sutura-oversized-jwks-{}.json", std::process::id()));
    let oversized = "x".repeat(MAX_KEY_SET_BYTES + 1);
    std::fs::write(&path, &oversized).expect("the scratch key set is writable");
    let refused = FileKeySet::at(&path)
        .read()
        .expect_err("a document over the bound is not read");
    let KeySetUnavailable::TooLarge { limit, .. } = refused else {
        panic!("expected a refusal about size, got {refused:?}");
    };
    assert_eq!(limit, MAX_KEY_SET_BYTES);

    // And a document exactly at the bound is accepted, so the refusal is about the limit rather than
    // about reading one byte less than whatever is there.
    std::fs::write(&path, "x".repeat(MAX_KEY_SET_BYTES)).expect("the scratch key set is writable");
    let read = FileKeySet::at(&path).read().expect("a document at the bound is read");
    assert_eq!(read.len(), MAX_KEY_SET_BYTES);
    std::fs::remove_file(&path).expect("the scratch key set is removable");
}
