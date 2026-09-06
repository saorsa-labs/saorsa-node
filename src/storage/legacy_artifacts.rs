//! What a node does when it finds the old chunk store still on disk.
//!
//! Chunks used to live in an LMDB environment at `{root}/chunks.mdb`. One release copied
//! them into a file per chunk and deleted that environment; this build has no code that
//! can read it. So a node starting with one still there is a node whose migration did not
//! happen or did not finish, and something has to decide what that means.
//!
//! Starting anyway is the tempting answer and it is the wrong one. Those chunks are
//! unreachable, but the commitment the node published before the upgrade claimed them, and
//! a commitment stays answerable to its neighbours for three hours. The one accusation the migration
//! releases suspended was "you did not have a chunk you were supposed to hold"; the
//! commitment-bound audit was never suspended in any release, precisely because it rests
//! on a signed claim. So a node that starts half-migrated spends those hours failing audits
//! for keys it cannot read, on the lane that always counted.
//!
//! Refusing everything is also wrong, and for a duller reason: a migration that finished
//! and then failed to delete the directory leaves one behind that is safe to ignore. A node
//! whose only fault is a failed `remove_dir_all` should not be held offline for it.
//!
//! So the question is not "is there an environment here" but "was it retired". The
//! retirement wrote a mark inside the directory before deleting anything, and that mark is
//! the only durable evidence there is. Not the migration marker file: the filesystem is
//! authoritative, and a live environment beside a marker that says the migration finished
//! means the marker is wrong, which is a state the previous release explicitly handles by
//! believing the filesystem.

use crate::error::{Error, Result};
use crate::logging::warn;
use std::path::{Path, PathBuf};

/// The directory the old chunk store lived in.
pub const LEGACY_ENV_DIR: &str = "chunks.mdb";

/// What retirement renamed it to before deleting it.
pub const RETIRED_SUFFIX: &str = ".retired";

/// The file retirement wrote inside a directory to say it had finished with it.
const RETIRED_MARKER: &str = "RETIRED";

/// What a directory's own contents say about whether it was retired.
///
/// Three answers, not two, for the reason the release that wrote these marks needed three:
/// reading one can fail for a reason that is neither yes nor no, and folding that into "no
/// mark" is what turns an unreadable directory into one this node refuses to start over
/// forever, while folding it into "retired" would let a live environment be ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetirementMark {
    /// It carries its mark. The migration got as far as deciding this was finished with.
    Present,
    /// It carries no mark, and that is known rather than assumed.
    Absent,
    /// Whether it carries one could not be determined.
    Unknown,
}

/// Read a directory's retirement mark.
fn retirement_mark(dir: &Path) -> RetirementMark {
    match std::fs::symlink_metadata(dir) {
        // A link is never treated as retired, whatever it points at: the mark would have
        // been written through it into somebody else's directory.
        Ok(meta) if meta.file_type().is_symlink() => return RetirementMark::Absent,
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RetirementMark::Absent,
        Err(_) => return RetirementMark::Unknown,
    }
    match dir.join(RETIRED_MARKER).try_exists() {
        Ok(true) => RetirementMark::Present,
        Ok(false) => RetirementMark::Absent,
        Err(_) => RetirementMark::Unknown,
    }
}

/// Every leftover of the old chunk store under `root_dir`, live name and tombstones alike.
///
/// The tombstones matter as much as the live name. Retirement renamed the directory aside
/// before deleting it, so a crash between the rename and the mark leaves an intact
/// environment wearing a retired-looking name. The previous release would have restored and
/// reopened it; this one cannot, so it must not be waved through on the strength of what it
/// is called.
fn legacy_directories(root_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();

    // `symlink_metadata`, not `try_exists`. The latter follows links, so a looping or
    // dangling one at the live name reads as nothing being there. And an error is not an
    // absence: a root that can be traversed but not queried would hide the environment
    // this function exists to find, and the caller would start.
    let live = root_dir.join(LEGACY_ENV_DIR);
    match std::fs::symlink_metadata(&live) {
        Ok(_) => found.push(live),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::Storage(format!(
                "Cannot tell whether {} is there ({e}), so this node cannot tell whether it \
                 has chunks in a store this build cannot read. Refusing to start rather \
                 than assume it does not.",
                live.display()
            )))
        }
    }

    // The same for the tombstones. A directory that cannot be listed hides every one of
    // them, and a single unreadable entry inside it hides that one.
    let prefix = format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}");
    let entries = match std::fs::read_dir(root_dir) {
        Ok(entries) => entries,
        // A root that is not there yet holds nothing, which is every node starting for the
        // first time and every test that names a directory before creating it. That is an
        // answer, not a failure to get one.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => {
            return Err(Error::Storage(format!(
                "Cannot list {} ({e}), so this node cannot tell what the storage migration \
                 left behind. Refusing to start rather than assume it left nothing.",
                root_dir.display()
            )))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|e| {
            Error::Storage(format!(
                "Cannot read an entry in {} ({e}), so this node cannot tell what the storage \
                 migration left behind. Refusing to start rather than skip it.",
                root_dir.display()
            ))
        })?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(&prefix))
        {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// Is this directory empty?
///
/// An error is not an emptiness. A directory that cannot be listed might hold anything, and
/// the caller uses this to decide whether it is safe to ignore.
fn is_empty(dir: &Path) -> Result<bool> {
    let mut entries = std::fs::read_dir(dir).map_err(|e| {
        Error::Storage(format!(
            "Cannot list {} ({e}), so this node cannot tell whether it still has chunks in \
             it. Refusing to start rather than assume it is empty.",
            dir.display()
        ))
    })?;
    Ok(entries.next().is_none())
}

/// Refuse to start if this node still has chunks in a store this build cannot read.
///
/// Called before the file store is opened, so a node that is going to refuse does not
/// create anything first.
///
/// # Errors
///
/// Returns [`Error::Storage`] naming the directory when one is present without a
/// retirement mark, when whether it carries one cannot be determined, or when the node
/// root cannot be read well enough to say whether one is there at all.
pub fn refuse_if_unmigrated(root_dir: &Path) -> Result<()> {
    for dir in legacy_directories(root_dir)? {
        match retirement_mark(&dir) {
            // Retired before this build ever ran. Its chunks are in the file store and the
            // deletion simply did not finish. Left exactly where it is: this build has no
            // migration code, so it has no business deciding that a directory it cannot
            // read is safe to delete.
            RetirementMark::Present => warn!(
                "{} is a leftover of the storage migration. It was already retired, so \
                 its chunks are in the file store and nothing is missing. It is costing \
                 disk until it is removed by hand.",
                dir.display()
            ),
            // A directory with nothing in it holds no chunks, so it cannot be hiding any.
            // The previous release's reaper emptied a tombstone, removed its mark and then
            // removed the directory, so a crash between the last two steps leaves exactly
            // this: empty, unmarked, and fully migrated. That release recognised the state
            // and cleaned it up. Refusing to start over it would hold a node offline for a
            // directory that has nothing in it.
            RetirementMark::Absent if is_empty(&dir)? => warn!(
                "{} is an empty leftover of the storage migration, which is what an \
                 interrupted cleanup leaves. Nothing is in it. It can be removed.",
                dir.display()
            ),
            RetirementMark::Absent => {
                return Err(Error::Storage(format!(
                    "{} is still here and this build cannot read it. Chunks in there were \
                     never copied into the file store, and starting without them would \
                     leave this node failing audits for keys its own published commitment \
                     still claims. Run a build with the storage migration, let it finish, \
                     then upgrade again. Refusing to start rather than serve a fraction of \
                     what this node is committed to.",
                    dir.display()
                )))
            }
            RetirementMark::Unknown => {
                return Err(Error::Storage(format!(
                    "{} is still here and this node cannot tell whether its chunks were \
                     ever copied out of it. Check that the directory and everything in it \
                     can be read. Refusing to start rather than guess, in either \
                     direction.",
                    dir.display()
                )))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn retired(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mkdir");
        std::fs::write(dir.join(RETIRED_MARKER), b"retired").expect("mark");
    }

    /// A node with nothing left over starts, which is every node that migrated.
    #[test]
    fn a_node_with_no_leftovers_starts() {
        let dir = TempDir::new().expect("temp dir");
        assert!(refuse_if_unmigrated(dir.path()).is_ok());
    }

    /// A node whose root does not exist yet starts.
    ///
    /// Every node starting for the first time, and every caller that names a directory
    /// before creating it. Reading a missing root fails, and treating that failure the way
    /// the unreadable cases are treated would refuse every fresh node on the network. A
    /// root that is not there holds nothing, which is an answer.
    #[test]
    fn a_root_that_does_not_exist_yet_is_not_a_refusal() {
        let dir = TempDir::new().expect("temp dir");
        let never_created = dir.path().join("node").join("deeper");
        assert!(refuse_if_unmigrated(&never_created).is_ok());
    }

    /// A directory that says it was retired is not a reason to stay down.
    ///
    /// The migration finished and the deletion did not. Its chunks are in the file store,
    /// so the node has everything it is committed to and holding it offline would cost
    /// availability for a directory that is only costing disk.
    #[test]
    fn a_retired_leftover_is_not_a_reason_to_refuse() {
        let dir = TempDir::new().expect("temp dir");
        retired(&dir.path().join(LEGACY_ENV_DIR));
        assert!(refuse_if_unmigrated(dir.path()).is_ok());

        // Under the name retirement renames to, as well.
        let dir = TempDir::new().expect("temp dir");
        retired(&dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}")));
        assert!(refuse_if_unmigrated(dir.path()).is_ok());
        let dir = TempDir::new().expect("temp dir");
        retired(
            &dir.path()
                .join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}.3")),
        );
        assert!(refuse_if_unmigrated(dir.path()).is_ok());
    }

    /// An empty leftover is not a reason to stay down.
    ///
    /// The previous release's cleanup emptied the directory, removed its mark, and then
    /// removed the directory. A crash between the last two steps leaves an empty, unmarked
    /// one behind: fully migrated, nothing in it, and indistinguishable by name from a
    /// store that was never copied. That release recognised the state and tidied it up.
    /// Holding a node offline for a directory with nothing in it would be an outage for
    /// bookkeeping.
    #[test]
    fn an_empty_leftover_is_not_a_reason_to_refuse() {
        for name in [
            LEGACY_ENV_DIR.to_string(),
            format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"),
            format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}.2"),
        ] {
            let dir = TempDir::new().expect("temp dir");
            std::fs::create_dir_all(dir.path().join(&name)).expect("mkdir");
            assert!(
                refuse_if_unmigrated(dir.path()).is_ok(),
                "{name} has nothing in it and must not stop the node"
            );
        }
    }

    /// An environment nobody retired stops the node.
    ///
    /// The chunks in it were never copied out, and the commitment this node last published
    /// claims them. Serving the rest would be failing audits for the difference.
    #[test]
    fn an_unretired_environment_stops_the_node() {
        let dir = TempDir::new().expect("temp dir");
        let env = dir.path().join(LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).expect("mkdir");
        std::fs::write(env.join("data.mdb"), b"chunks that were never copied").expect("seed");

        let err = refuse_if_unmigrated(dir.path()).expect_err("this node must not start");
        let said = format!("{err}");
        assert!(said.contains("chunks.mdb"), "{said}");
        assert!(
            said.contains("migration"),
            "the message must say what to do: {said}"
        );
    }

    /// And so does one wearing a retired name with no mark inside it.
    ///
    /// A crash between the rename and the mark leaves an intact environment under the name
    /// retirement uses. The name is not the evidence; the mark is.
    #[test]
    fn an_unmarked_tombstone_stops_the_node_too() {
        let dir = TempDir::new().expect("temp dir");
        let tombstone = dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
        std::fs::create_dir_all(&tombstone).expect("mkdir");
        std::fs::write(tombstone.join("data.mdb"), b"still every chunk").expect("seed");

        assert!(
            refuse_if_unmigrated(dir.path()).is_err(),
            "a directory that only looks retired is not retired"
        );
    }

    /// A node root that cannot be listed stops the node.
    ///
    /// Finding the leftovers is as load-bearing as classifying them, and an error looking
    /// for one is not the same as there being none. A root that can be traversed but not
    /// listed would hide every tombstone, and the node would start believing it had
    /// nothing left over. This is the same fail-open the classifier itself was written
    /// three-state to avoid, one step earlier in the same function.
    ///
    /// Unix only: the state is staged by taking the permission to list away.
    #[cfg(unix)]
    #[test]
    fn a_root_that_cannot_be_listed_stops_the_node() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let root = dir.path().join("node");
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let refused = refuse_if_unmigrated(&root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let Err(e) = refused else {
            println!("skipped: this user can list a 000 directory");
            return;
        };
        assert!(format!("{e}").contains("Cannot"), "{e}");
    }

    /// A link where the environment should be is not an absence either.
    ///
    /// `try_exists` follows links, so a loop or a dangling target reads as nothing being
    /// there. Whatever that is, it is not proof this node has no chunks in a store this
    /// build cannot read.
    #[cfg(unix)]
    #[test]
    fn a_link_wearing_the_environment_name_is_not_treated_as_absence() {
        let dir = TempDir::new().expect("temp dir");
        let live = dir.path().join(LEGACY_ENV_DIR);
        std::os::unix::fs::symlink(&live, &live).expect("a link to itself");

        assert!(
            refuse_if_unmigrated(dir.path()).is_err(),
            "a link at the environment name must not read as nothing being there"
        );
    }

    /// A directory nobody can classify stops the node rather than being guessed at.
    ///
    /// Unix only: the state is staged with a symbolic link, which makes looking for the
    /// mark return a loop while leaving everything else about the directory alone.
    #[cfg(unix)]
    #[test]
    fn an_unclassifiable_environment_stops_the_node() {
        let dir = TempDir::new().expect("temp dir");
        let env = dir.path().join(LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).expect("mkdir");
        let link = env.join(RETIRED_MARKER);
        std::os::unix::fs::symlink(&link, &link).expect("a link to itself");
        assert_eq!(retirement_mark(&env), RetirementMark::Unknown);

        let err = refuse_if_unmigrated(dir.path()).expect_err("this node must not start");
        assert!(format!("{err}").contains("cannot tell"), "{err}");
    }
}
