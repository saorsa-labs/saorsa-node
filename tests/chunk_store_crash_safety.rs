//! What survives a process dying part-way through a write.
//!
//! The store rests on being able to stop at any moment and start again: every step is
//! idempotent and re-derived from the filesystem. That is easy to assert and hard to
//! believe without trying it, so these tests kill a real child process at a real point in
//! the work and then open the store in this one and check what is there.
//!
//! **What this does and does not prove.** A killed process loses nothing the kernel has
//! already accepted, so this covers ordering and bookkeeping: a chunk is whole or absent
//! and never half-indexed, and what an interrupted write leaves behind is swept. It does
//! not cover power loss, where the kernel loses what it accepted and never wrote. That is
//! still a fleet gate.
//!
//! These tests came from the harness that proved the migration off the old chunk store.
//! Most of that harness went with the migration; these two did not belong to it. They are
//! about the store's own publish path, which is now the only one there is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use ant_node::storage::{ChunkStore, ChunkStoreConfig};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

/// Run this test binary again as a child in the mode named by `role`, wait until it has
/// reached the named point, and kill it there.
///
/// A child process rather than a thread, because the point is to lose everything the
/// process was holding: buffers, in-memory index, locks, half-finished intentions.
///
/// The wait is a handshake, not a sleep. An earlier version of this slept and hoped, and
/// on a quick machine the child had finished everything before the kill arrived, so the
/// test was checking a clean shutdown while claiming to check a crash. The child now stops
/// at a failpoint inside the write and says so by writing a marker; this waits for the
/// marker and then kills it, so the process always dies at the same point in the same
/// operation.
fn kill_child_at_failpoint(role: &str, root: &Path, failpoint: &str, let_through: u64) -> PathBuf {
    let marker = root.join(format!("reached-{role}"));
    let _ = std::fs::remove_file(&marker);

    let exe = std::env::current_exe().expect("this test binary");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(role)
        .arg("--nocapture")
        .arg("--ignored")
        .env("ANT_CRASH_TEST_ROOT", root)
        .env(failpoint, &marker)
        .env(
            ant_node::storage::chunk_store::HALT_AFTER,
            let_through.to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the child");

    // Generous, but not unbounded. Without a deadline a failpoint that stopped working
    // would hang the job rather than fail it, and a hang says nothing about the code.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the child exited before reaching the failpoint: {status}");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the child never reached the failpoint");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    child.kill().expect("kill the child");
    let _ = child.wait();
    marker
}

/// Where the child was told to work.
fn child_root() -> PathBuf {
    PathBuf::from(std::env::var("ANT_CRASH_TEST_ROOT").expect("the child needs a root"))
}

/// Child mode: write chunks into a file store until killed.
#[tokio::test]
#[ignore = "child process of a crash test, not run on its own"]
async fn child_writes_until_killed() {
    let root = child_root();
    let store = ChunkStore::new(ChunkStoreConfig {
        root_dir: root,
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    })
    .await
    .expect("open");

    // Always a chunk it has not written before, so the kill lands in real work rather
    // than in a re-offer of something already on disk. An earlier version cycled the same
    // hundred keys and spent almost all its time confirming duplicates.
    let mut n = 0usize;
    loop {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        let _ = store.put(&address, &content).await;
        n += 1;
    }
}

/// A process killed inside a publish leaves no chunk it cannot serve.
///
/// The child is stopped at the last moment before the chunk's name exists on disk: on Unix
/// the bytes written to a temporary file with the rename not yet made, off Unix the point
/// before the file is created at all, since that platform writes under the final name
/// because a rename there carries no durability guarantee. The failure this guards against
/// is the same on both: a name outliving its bytes. The index is built from filenames at
/// startup, so a partial file wearing a real chunk name would be advertised, committed to,
/// and unservable.
#[tokio::test]
async fn a_process_killed_mid_publish_leaves_no_chunk_it_cannot_serve() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    // Twenty chunks land before the crash, so the store this reopens has real content in
    // it. Stopping the very first write would leave nothing indexed and the loop below
    // would pass by iterating over nothing.
    let marker = kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::chunk_store::HALT_BEFORE_PUBLISH,
        20,
    );
    assert!(
        marker.exists(),
        "the child must have reached the failpoint before it was killed"
    );

    // Reopening is itself part of the assertion: a store that cannot start after a crash
    // is a node that cannot start.
    let store = reopen(&root).await;
    // The child discards its put results and the failpoint counts arrivals, not successes,
    // so every publish before the kill could in principle have failed. An empty store makes
    // the loop below pass over nothing, which is the one outcome that would let this test
    // report success having checked no chunk at all.
    let held = store.all_keys().await.expect("all_keys");
    assert!(
        !held.is_empty(),
        "the child published nothing before it was killed, so there is nothing to check"
    );
    for key in held {
        let served = store.get(&key).await;
        assert!(
            matches!(served, Ok(Some(_))),
            "chunk {} is claimed after a crash but cannot be served: {served:?}",
            hex::encode(key)
        );
    }
}

/// The temporary file a killed publish left behind is swept, not indexed.
///
/// It carries no chunk name, so it can never be served, and leaving it would cost disk
/// for the life of the node.
///
/// Unix only, because the leftover only exists on Unix. Off Unix the store creates the
/// file under its final name and flushes it, deliberately, since a rename there is not
/// documented to be durable. So there is no temporary file to sweep and the equivalent
/// hazard is different: a real chunk name over bytes that are short or wrong. That one is
/// covered by the store's own tests, which run on every platform, and by the
/// re-hash-everything pass the retirement does before it deletes anything.
#[cfg(unix)]
#[tokio::test]
async fn the_leftovers_of_a_killed_publish_are_swept() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::chunk_store::HALT_BEFORE_PUBLISH,
        5,
    );

    let before = temp_files(&root.join("chunks"));
    assert!(
        before > 0,
        "the child should have left a temporary file behind when it was killed"
    );

    let store = reopen(&root).await;
    store.wait_idle().await;
    assert_eq!(
        temp_files(&root.join("chunks")),
        0,
        "the store should sweep what an interrupted write left"
    );
    drop(store);
}

/// How many partly-written files are under `chunks_dir`.
#[cfg(unix)]
fn temp_files(chunks_dir: &Path) -> usize {
    let Ok(shards) = std::fs::read_dir(chunks_dir) else {
        return 0;
    };
    shards
        .flatten()
        .filter_map(|shard| std::fs::read_dir(shard.path()).ok())
        .flat_map(std::iter::IntoIterator::into_iter)
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| !name.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .count()
}

/// Open the store the way a restart would.
async fn reopen(root: &Path) -> ChunkStore {
    let config = ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    ChunkStore::new(config)
        .await
        .expect("the store must open after a crash")
}

/// Deterministic content for chunk `n`. `n` goes in verbatim so no two differ only by a
/// wrap and collapse into one chunk.
fn chunk_bytes(n: usize) -> Vec<u8> {
    let mut content = vec![0u8; 4096];
    content[..8].copy_from_slice(&(n as u64).to_le_bytes());
    for (i, byte) in content.iter_mut().enumerate().skip(8) {
        *byte = ((i.wrapping_mul(17)).wrapping_add(n) % 251) as u8;
    }
    content
}
