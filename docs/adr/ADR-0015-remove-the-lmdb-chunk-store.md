# ADR-0015: Remove the LMDB Chunk Store and Restore the Close-Group Penalty

- **Status:** Proposed
- **Date:** 2026-08-28
- **Decision owners:** Anselme Gaeremynck
- **Reviewers:** David Irvine, Chris O'Neil, Mick van der Most van Spijk
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0014 (one file per chunk, and retiring LMDB), which this completes

## Context

Moving chunks off LMDB shipped as three releases, because the penalty for not holding a
close-group chunk is the *auditor's* decision: a node that has to give chunks up cannot stop
its peers punishing it for that. So the peers stopped first.

1. **First:** suspend that one penalty.
2. **Second:** copy every chunk into a file of its own, then delete `chunks.mdb`. ADR-0014.
3. **Third:** this one.

ADR-0014 describes the third release as flipping the switch back and nothing more. What
actually has to happen is larger, and two parts of it are decisions rather than clean-up.

## Decision

**Restore the penalty, and keep its switch.** The constant goes back to `false`. The
process-wide atomic, the `ANT_SUSPEND_UNHELD_CHUNK_PENALTY` override and the startup
announcement all stay. They are not migration machinery: they are one release-level policy
that several audit paths have to obey identically, and the release that restores a penalty
is exactly the one most likely to need it undone in a hurry. Removing them would discard the
cheapest lever at the moment it is most useful. A test now pins the shipped value, because
the existing tests set the switch both ways on purpose and so could never notice which way
it was compiled.

**Delete the LMDB chunk store and the migration, and keep the name `ChunkStore`.** There is
one store. It is one file per chunk, it lives in `src/storage/chunk_store.rs`, and it is
called `ChunkStore` because that is what it is and what every caller already called it. The
type that used to present two stores as one is gone with the second store.

`heed` stays in the dependency list. The paid-key list has its own LMDB environment, which
this decision does not touch.

**A node that still has an unretired `chunks.mdb` refuses to start.** This is the part worth
arguing.

The tempting answer is to start anyway, serve what is in the file store, and warn. It is
wrong. The chunks in that environment are unreachable to this build, but the commitment this
node published before the upgrade *claimed* them, and a commitment stays answerable to its
neighbours for three hours (`GOSSIP_ANSWERABILITY_TTL`, which is `(RETAINED_GOSSIPED_
COMMITMENTS + 1)` rotations). The accusation the first release suspended was "you did not have a chunk you
were supposed to hold". The commitment-bound subtree audit was never suspended in any
release, precisely because it rests on a signed claim. So a node that starts half-migrated
spends hours failing audits, at the full weight, on the one lane that always counted. It is
not a smaller node; it is a node being slashed for keys it cannot read.

Refusing *everything* is also wrong, for a duller reason: a migration that finished and then
failed to delete the directory leaves one behind that is safe to ignore. A node whose only
fault is a failed `remove_dir_all` should not be held offline for it.

So the question is not "is there an environment here" but "was it retired", and the evidence
is the mark the retirement wrote *inside* the directory before deleting anything:

| what is on disk | what happens |
|---|---|
| nothing, or a root that does not exist yet | start |
| `chunks.mdb` or a tombstone carrying its `RETIRED` mark | start, warn that it is costing disk |
| either one with nothing in it | start, warn that it can be removed |
| either one, non-empty, without that mark | refuse, and name the directory |
| either one whose mark cannot be read | refuse, and say which |
| a root that cannot be read well enough to answer | refuse, and say so |

The empty case is not a nicety. The previous release's cleanup emptied the directory,
removed the mark and then removed the directory, so a crash between the last two steps
leaves one that is empty, unmarked, and fully migrated. That release recognised the state
and tidied it. Refusing over a directory with nothing in it would be an outage for
bookkeeping.

The check runs as soon as the root is known and before the transport is built. Asking later
lets a bind failure mask the answer, and charges a node for a transport it is about to throw
away.

Three states rather than two, for the same reason the release that wrote those marks needed
three: reading one can fail for a reason that is neither yes nor no, and folding that into
"no mark" holds a node offline forever over an unreadable directory, while folding it into
"retired" waves through a live one.

Not the migration marker file. The filesystem is authoritative, and ADR-0014's own recovery
resets a recorded `FilesOnly` phase back to bridging when it finds a live environment, so a
marker saying the migration finished is not evidence that it did.

Tombstones are checked as well as the live name. A crash between the rename and the mark
leaves an intact environment wearing a retired-looking name; the previous release would have
restored and reopened it, and this one cannot, so it must not be waved through on the
strength of what it is called.

Nothing of the old store is deleted. This build has no migration code, so it has no business
deciding that a directory it cannot read is safe to remove, and leaving it is what keeps a
rollback to the previous release possible. To be exact about what "nothing" covers: this
release does not migrate, delete, rename or rewrite `chunks.mdb`, does not rewrite the
migration marker, and does not change the file-store layout. It still does everything a node
normally does to its own chunks, and opening the store still creates the store's own files
and sweeps orphaned temporaries, as the previous release did.

## Consequences

### Positive

- One store, one name, and about 5,600 lines of bridge and driver gone.
- The penalty means what it always meant again.
- A node cannot silently serve a fraction of what it is committed to.
- The per-volume migration lock and its deployment settings go with the migration.

### Negative / Trade-offs

- **A node that never finished migrating will not start.** That population is exactly the
  short-of-disk nodes, and how large it is remains the open fleet question ADR-0014 records.
  If a whole wave refuses at once, that is an availability incident, and the right response
  is to stop the upgrade wave rather than to start those nodes blind. A rollout that cannot
  halt on that signal is unsafe independently of this decision.
- Restoring the penalty and deleting the bridge in one release means the emergency lever for
  the first is a switch, while the second can only be undone by rolling back the binary.
  Shipping them as separate releases was considered and is a legitimate call for whoever
  cuts the train; the two are separate commits so that remains possible.
- `ChunkStore` and its module were renamed from `FileStore` and `file_store.rs`. Callers did
  not change, because they already used the facade's name.

### Neutral / Operational

- `ANT_SUSPEND_UNHELD_CHUNK_PENALTY` still works and still logs loudly when it disagrees
  with the build.
- `storage.migration` and `storage.db_size_gb` are gone from the configuration. The second
  capped a memory map that no longer exists, and a setting that silently does nothing is
  worse than one that is absent. Nothing declares `deny_unknown_fields`, so a config file
  written by the previous release still loads with both keys in it, which is what stops
  every node on the fleet failing to start at once on upgrade. There is a test for that,
  because adding that attribute later would look harmless.
- The `chunks.mdb` a refusing node names can be moved aside by hand once its contents are
  known to be copied. There is no supported way to make this build read one.

## Validation

**Proved here.** A node with no leftovers starts; one with a retired leftover starts; one
with an empty leftover starts; one whose root does not exist yet starts. One with an
unretired environment refuses, and the test reads the message to check it names the
directory; one with an unretired tombstone refuses; one whose mark cannot be read refuses
with a message that says so; one whose root cannot be listed refuses. The warnings the
starting cases emit are not asserted, only the refusals' messages are. The unreadable case is staged with a
symbolic link pointing at itself, so looking for the mark returns a loop while everything
else about the directory keeps working, which is a state any user can reach and root cannot
skip. Restoring the penalty is pinned by a test that fails if the constant is flipped back.

**Deleted, and what replaced it.** ADR-0014's validation section describes four harnesses.
Most of three of them existed to prove the bridge worked: that the disk came back when the
old store was deleted, that a node killed mid-copy lost nothing, and that several nodes on
one disk took turns. There is no bridge left for those to test. The fourth, which measures
what one file per chunk costs at scale, stays.

Not all of it went, and saying it did was wrong. Two tests inside the crash harness were
never about the bridge: that a process killed mid-publish leaves no chunk the store cannot
serve, and that what an interrupted write leaves behind is swept. Those are about the store's
own publish path, which is now the only one there is, so they matter more after this release
rather than less. They are back as `tests/chunk_store_crash_safety.rs` and run in CI. A third
property, that engine shutdown waits for a detached store write, is named under the gaps
below.

That leaves the loopback filesystem job with nothing to run, and deleting it would quietly
drop ext4, XFS and btrfs coverage of the store itself. It now runs the storage unit tests
against each mounted filesystem instead, which is what still has something to say there:
publishing through a temporary and a rename, flushing, deleting, and rebuilding an index
from the names.

**Not proved here, and inherited from ADR-0014.** Forced power loss on the five filesystems.
Scale at one and ten million keys. How many short-of-disk nodes can clear the possession
gate, which this decision makes sharper: under ADR-0014 such a node kept serving from both
stores, and under this one it does not start.

**Coverage this release drops, named rather than lost.** A harness proved that
`ReplicationEngine::shutdown()` waits for a store write whose awaiter was dropped before it
returns. It was written against the old store and went with it. The property is still
current and still claimed by that method's own documentation, and nothing tests it now. It
needs a live P2P node to stage, which is why it is called out here rather than quietly
rewritten in the same change that deleted it.

**A fleet gate this decision adds.** Before this ships, the fleet has to show that nodes are
actually on the file store. The count that answers it is nodes reporting a completed
migration; the ones that cannot are the ones that will refuse to start.

## Notes for AI-assisted work

Drafted with AI assistance. Not to be marked Accepted without human review.
