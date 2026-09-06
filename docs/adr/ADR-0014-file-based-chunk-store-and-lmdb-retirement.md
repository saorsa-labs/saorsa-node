# ADR-0014: One File Per Chunk, and Retiring LMDB Without Losing Data

- **Status:** Proposed
- **Date:** 2026-08-25
- **Decision owners:** Anselme Gaeremynck
- **Reviewers:** David Irvine, Chris O'Neil, Mick van der Most van Spijk
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (gossip-triggered subtree audit), ADR-0003 (possession checks),
  ADR-0004 (commitment-bound quote pricing), ADR-0007 (Windows LMDB map headroom cap,
  retired by this decision)

## Context

The node stores chunks in LMDB. LMDB returns a deleted page to its own free list and never
to the filesystem, so **deleting chunks does not free disk**. In one week the fleet deleted
2.29 million chunks and got back zero bytes. Operators read that as a bug and are tempted
to wipe node directories to reclaim space, which costs the network real replicas.

There is no partial way out. Compaction needs free space equal to the live data, which is
exactly the condition a full node does not meet, and it does not get us off LMDB anyway.
Punching holes in `data.mdb` is Linux-only, needs LMDB internals to identify free pages,
and reads back as zeros. Disk comes back exactly once: when `chunks.mdb` is removed whole.

    peak disk during migration = allocated chunks.mdb (unchanged) + files written so far

So a local migration is possible if and only if `free >= live payload`. On production
volumes today (55 volumes at 492 GiB, free median 25.8 GiB, p10 9.8 GiB, about 12 nodes
per volume, about 38 GiB of LMDB per node of which about 24 GiB is live) migrating one
node costs 24 GiB and returns 38 GiB. One at a time the host gains about 14 GiB per node
and the queue accelerates. All twelve at once need 288 GiB and all twelve stall.

The chunk workload is the easiest possible case for a filesystem: content-addressed,
immutable, write once, read many, delete whole, and **4 MiB**, confirmed by the team
rather than assumed. That size is what makes one file per chunk the right shape; see the
Storj and borgbackup note under Validation for what would change the answer.

## Decision Drivers

- Deleting a chunk must return its blocks to the filesystem, on a full disk, with no free
  space required and no compaction to schedule.
- No chunk may lose its last replica, including during a fleet rollback, a skipped
  upgrade, or a crash halfway through the migration.
- Mass audit failures are as damaging as data loss. Nothing here may cause them.
- It has to work for every operator, not for our fleet. Most node operators are not us and
  cannot be told to attach a second volume.
- No opt-in. Whatever we ship is what every node does by default.

## Considered Options

1. **Stay on LMDB and compact.** Needs free space equal to the live data, which is the
   condition we are trying to escape, and leaves us on LMDB.
2. **Append-only packs** (borg segments, Storj hashstore). Reintroduces compaction, a free
   list, and a cross-file index. That is LMDB's disease with a different allocator.
3. **Fixed-size slots** (Sia `hostd`, Swarm sharky). Cheaper than log packing, and Sia's
   sector size is exactly our 4 MiB. But a freed slot returns space to the *store*, never
   to the *filesystem*: the volume file never shrinks. It is the right design once a node
   has a declared capacity, and the wrong one while our whole complaint is that disks stay
   full as chunk counts drop.
4. **One file per chunk, sharded on the address prefix.** Broken for us, see below.
5. **One file per chunk, sharded on the address suffix.** Chosen.

## Decision

### The store

One immutable file per chunk:

```text
{root}/chunks/layout.json          versioned layout marker
{root}/chunks/<xy>/<64-hex>        xy = the LAST two hex characters of the address
```

**Suffix, never prefix.** A node holds keys it is among the `CLOSE_GROUP_SIZE` closest to,
so its holdings share roughly `log2(N / 7)` leading bits with its own node ID, and that
shared prefix grows as the network grows. Distinct directories a single node would actually
use, sharding on the first hex characters:

| nodes | shared bits | 2 hex | 3 hex | 4 hex |
|---:|---:|---:|---:|---:|
| 1,000 | 7.2 | 1.8 | 29 | 459 |
| 10,000 | 10.5 | 1 | 2.9 | 46 |
| 100,000 | 13.8 | 1 | 1 | 4.6 |
| 1,000,000 | 17.1 | 1 | 1 | 1 |

At today's ~800 nodes a two-hex prefix is already down to about two directories. Prefix
sharding does not degrade, it fails, and it fails later for the nodes that grow into it.
Close-group membership constrains the leading bits and places no constraint at all on the
trailing ones, and the address is a BLAKE3 output, so the last byte is uniform by
construction at every network size. IPFS shipped the same fix for a different reason: its
prefixes were constant because of the CID encoding, not because of clustering, and the
flatfs `_README` still says *"Previously, we used prefixes, we now use the next-to-last two
characters."* The generalisation is the part worth keeping: **shard on bits you can prove
are uniform, not on bits that happen to be uniform today.**

**256 shards, one level.** 23 files per directory at today's ~6,000 chunks per node, 977 at
a 1 TiB node, 39,000 at 10 TiB, for 1 MiB of directory inodes. 4,096 shards only starts to
pay past several million chunks and costs sixteen times the directory overhead for every
node that is not that large.

**Lowercase hex filenames, full 64 characters.** NTFS and default APFS fold case, so under
base64url or base58 two distinct keys can share one case-folded filename, which is a silent
overwrite. No hex string can spell `CON`, `NUL`, `AUX`, `COM1` or `LPT1`, because none of
those letters is in `0-9a-f`. Keeping the whole key in the name means a `find` over the tree
recovers the store even if the directory layer is lost.

**The scheme is recorded in `layout.json` at creation.** Nobody in this survey shipped an
in-place re-sharder and all of them paid for it: IPFS says export and re-import, Storj ran a
multi-year satellite-controlled backend migration, borg rewrites only on the next
compaction. One small file is the difference between changing the default later and never
being able to.

### The index

**The filesystem is the sole authority.** The key set is a `BTreeSet<XorName>` rebuilt at
every open by reading directory entries, names only: no `stat`, no content read. A `stat`
per entry costs about ten times the enumeration on Linux and macOS and fifty to sixty times
on Windows, and buys nothing, because the filename is the key.

No sidecar database, because a persistent index **cannot remove reconciliation**. Commit
the index first and a crash leaves a phantom key; rename the file first and a crash leaves
an unindexed file. Repairing either means looking at the filesystem anyway, so the
filesystem may as well be the authority, and then nothing can drift. Ceph FileStore's
tracker #17177 is the cautionary tale: a crash between `unlink` and the LevelDB flush
orphaned omap keys that were silently reattached to a different object later.

`BTreeSet` rather than a hash set for three reasons: `all_keys()` must be sorted (the
commitment builder truncates the responsible subset with `take(cap)` *before* the Merkle
tree sorts it, so an unstable order would make the published commitment depend on iteration
luck), it never spikes memory while growing, and bulk-building it from a sorted vector packs
every node to capacity where repeated insertion converges on 68% fill for the same keys.

**One process per data directory, enforced.** LMDB was genuinely multi-process safe. This
store is not: two of them keep independent in-memory indices, so both would report the same
write as newly stored and each would keep serving keys the other had deleted. A node whose
store is already held by another process refuses to start and says so.

**Every in-memory mutation mirrors a filesystem operation that has already completed**, and
never anticipates one. Bitcask's issue #114 is what the opposite order looks like: an index
rebuilt at startup and then mutated in place drifted to 2,400 keys pointing at fewer than
100 files.

### Durability

Write, on Unix: reserve capacity, create a temp in the **destination** directory, write,
flush the file, rename, flush the shard directory, then admit the key. The publish is an
intra-directory rename, so it is atomic on every Unix filesystem we support and only that
one directory needs flushing. Off Unix there is no rename at all, for the reason the table
below gives; the file is created under its final name and flushed. Either way the final
name can never appear on partial content, because the name is the hash and a name that does
appear over the wrong bytes is caught on read. Delete: unlink, flush the shard directory,
then drop the key.

Per platform, honestly:

| | rename atomic | fsync(temp) + rename durable | directory fsync |
|---|---|---|---|
| ext4 | yes | **no**, `auto_da_alloc` only orders data before the rename's commit | yes, required |
| XFS | yes | not by that sequence | yes |
| btrfs | yes | **uncertain**, ALICE found reordering | yes |
| APFS | yes | `sync_all` already uses `F_FULLFSYNC` on Apple targets | returns 0, effect undocumented |
| NTFS | **not documented as atomic** | see below | **no documented way** |

On Windows a node cannot make the rename durable through the standard library at all. Two
places in this design leaned on one, and neither leans on it now.

Publishing a chunk off Unix does not rename: it creates the file under its final name and
flushes it, which Microsoft documents as flushing the creation metadata with it. The
content is content-addressed and re-replicable either way, so a file that does not survive
is detected on read and repaired from the network.

Retirement still renames the environment aside before deleting it, and that rename is not
durable off Unix. What makes it safe is that **the mark goes inside the directory, not
beside it**. A power loss that reverts the rename brings the directory back under its live
name still carrying its mark, and a marked directory under the live name is never opened or
served from: its chunks are in the file store, which is what the mark records. A loss
before the mark leaves the directory unmarked under either name, and an unmarked directory
is always restored and reopened. Every one of those four states has a test.

So the earlier position, that Windows should refuse to delete the legacy environment until
an operator overrode it, is not what ships. It has been replaced by a mechanism rather than
by a policy, which is the better answer: a switch nobody turns on is a migration that never
finishes. `ANT_MIGRATION_RETIRE_LEGACY=0` remains, per node, for an operator who wants to
hold retirement off one machine, and the forced power-loss run below is still an open fleet
gate on every platform including this one. What that run is now checking is directory
creation, which has no portable flush.

### Retiring LMDB

Three releases, because slashing is the *auditor's* decision. A node that has to give up
chunks cannot stop its auditors from penalising it, so the auditors have to stop first.

| Release | Penalise a peer for not holding a close-group chunk? | Delete `chunks.mdb`? |
|---|---|---|
| **First**: stop one penalty | no | no |
| **Second**: migrate | no | yes |
| **Third**: restore it | yes | yes |

What the first release withholds is deliberately narrow: only the penalty for **not holding a close-group
chunk you were supposed to be holding**. The commitment-bound subtree audit still
penalises, in every release. So does a responder whose own storage fails: a fetch answered
with an error means the read faulted or the bytes no longer hash to their address, which is
never what a node giving chunks up looks like, and a node that does not hold the chunk says
so with `NotFound` instead. That is not a compromise, it is what makes the rest work: a
node reduces its commitment precisely so its peers hold it to the smaller claim, and
suspending that enforcement would make the reduction meaningless. Audits of both kinds run
and record throughout.

Both are **build constants with environment overrides, never serialised config**. A node
writes its effective configuration back to disk, so shipping them as ordinary fields would
bake the first release's values into every operator's file and the next would change nothing.

Per node, in order:

1. **Open both stores.** Reads are the union, writes go to files. New chunks are also
   written to LMDB **first** while it exists: a chunk uploaded during the bridge to holders
   that all revert to a pre-migration build would otherwise be gone from every one of them,
   and that is client data, not a replica.
2. **Copy closest first**, throttled, stopping at a slack floor above the disk reserve.
3. **Settle.** The node commits only to its file-backed keys from here, while still serving
   everything it ever committed to. Serving reads the union; the commitment reads the
   file-backed set. A node is at worst over-honest. Nothing is deleted at this step: it
   only narrows the claim, so the close group can learn the new one before anything goes.
4. **Verify.** Every chunk both stores hold is re-hashed and recopied from LMDB on
   mismatch. A filename is not proof the bytes behind it are good, and the startup scan
   reads names only.
5. **Retire.** Once the retirement delay has elapsed, at least two commitment rebuilds have
   been published, and no key the node is giving up is still answerable under a retained
   commitment slot: rename `chunks.mdb` aside, flush the parent, record the node as
   file-only, and only then delete it. The rename is what makes the state change atomic,
   because `remove_dir_all` is not: a failure partway through leaves a directory that can
   no longer be opened as an environment, and recording completion on top of that would
   have the node claim it had finished over a half-deleted store. **This is where the disk
   comes back.** The gates that can change while nobody is looking are rechecked inside
   the destructive step itself, in the same critical section that proves no other task
   holds the store: the proof's health generation, the answerability veto, the announced
   writes, and that every legacy-only key is in the approved set. The network gates, rank
   and commitment delivery and possession, are rechecked immediately before that call and
   outside the guard, so the window on those is the seconds it takes to take the guard
   rather than the hours the verification pass can run for. Both matter, and they are not
   the same claim.
6. **Refetch** the shortfall through ordinary replication, with the freed space to do it in.

The delete gate is the pruner's existing retention contract
(`ResponderCommitmentState::is_held`, `GOSSIP_ANSWERABILITY_TTL` three hours). No new
protocol.

**Nothing is given up without proof it exists elsewhere.** Only nodes that cannot fit
their payload give up anything at all, and such a node must clear three gates, in this
order, before a byte is deleted:

1. **It is not near the front of the group for the chunk.** Only the last two positions of
   the *admission group* (`storage_admission_width`, the close group plus its margin) are
   eligible, which is the width the pruner treats as strictly in-range and refuses to
   delete inside. A one-off migration must not be more willing to drop a chunk than the
   thing that runs every day.
2. **Its close group has received the reduced commitment.** The node narrows what it claims
   first, and only once peers have demonstrably received that narrower claim, proven by
   them answering a neighbour sync that carried it, may anything be deleted. Until then
   they audit it against the set it used to hold, and a wave of audit failures is as
   damaging as losing the chunks.
3. **Other nodes have proven they hold the chunk, and are currently publishing a claim.**
   All but one of its current close group must answer a cryptographic possession challenge
   over a nonce they have never seen. This is the pruner's own evidence, reused
   deliberately, and it is deliberately not the cheap `VerificationRequest`: that carries a
   self-reported `present: bool`, and a node that has silently lost a chunk still answers
   yes. A peer only counts if this node has also heard a commitment from it recently, which
   excludes a peer sitting between a retired commitment and its next rotation. That gap is
   exactly what a node in the middle of its own migration looks like, and counting it would
   let two migrating nodes each conclude the other was covering the chunk.

Rank alone would not do. Being far from a chunk says something about who *should* hold it,
not about who *does*, and in a fleet-wide migration the nodes that should hold it are
exactly the ones that may also be short of space. Without gate 3 the safety property is
merely statistical: every holder could be short at once and each drop the same chunk, and a
per-volume lock cannot see that, because it serialises one volume and this is a
network-wide question.

A node that cannot clear these gates keeps both stores, does not free its disk, and tells
the operator to add storage. That is the correct answer, not a smaller replica count.

Gates 2 and 3 are re-checked immediately before the environment is removed, not once when
the node settled hours earlier. The group moves, and two paths can put a key back into the
legacy-only set in between: a file that failed verification and is now being served from
the legacy copy, and a write whose file half failed.

**Two of a close group at a time, not seven.** The gates above are per chunk, and they are
safe, but on their own they deadlock: if every holder migrates at once, none can prove to
the others that a copy survives and the whole group sits waiting. So each node derives a
migration wave from a hash of its own ID, and a group of seven is split into four waves.
Wave `w` opens `w * wave_hours` after the build first starts. It needs no coordination and
no protocol change, which matters because a node cannot usefully ask its close group "are
you migrating?" and would not trust the answer by the time it arrived.

It is a stagger, not a guarantee: seven IDs hashed into four waves will not always land two,
two, two, one. What makes it safe rather than merely tidy is that it composes with the
possession gate. A node whose turn has come still cannot give a chunk up until its
neighbours prove they hold it, so an unlucky wave waits instead of over-shedding. Only nodes
that have to give something up wait for a wave; a node with room copies and retires
immediately, because it is never unable to serve.

Separately, a host-wide advisory lock serialises migrations sharing a volume, held from the
first copy through retirement, so a node cannot release it and let eleven others start
before it has finished copying. It is released when the environment is unlinked and its
directory renamed aside, not when the last byte comes back: the deletion itself runs
detached so the node can serve while it happens, and it can take minutes on a large store.
So the next node in the queue can begin its copy while the previous one's tombstone is
still on the disk. That is deliberate, and it is worth stating rather than claiming a
tighter guarantee than there is. The two limits answer different questions: the lock is
about one machine's disk, the wave is about one chunk's replicas.

Where the lock file lives is a deployment fact, and the wrong answer is silent: nodes that
cannot see each other's lock each take one and report success. A host whose nodes do not
share a `/tmp`, which is any host using `PrivateTmp=true`, has to be told where the lock
lives through `ANT_MIGRATION_LOCK_DIR`. The node logs the path it locked at so this can be
answered from a log rather than inferred from a unit file.

## What the review added

Five mechanisms are in the implementation that are not in the design above. Each exists
because adversarial review found a way for the destructive step to run on a belief that
was no longer true. They are recorded here because they are load-bearing, not incidental.

**A directory that has been retired says so from the inside.** The rename that moves the
environment aside cannot be shown to be durable off Unix, so a power loss can bring it back
under its old name with its contents already deleted, and a node that opened that would
fail to start. A file written inside it after the rename and before any deletion travels
with the directory, so what it is never has to be inferred. A mark beside the environment
was tried first and was wrong: it would have to be cancelled when a retirement is abandoned,
cancellation can fail or be lost, and a stale one authorises deleting an environment that
has since taken a chunk. Deletion removes the mark last, so a failed deletion never leaves a
retired directory looking intact.

**A chunk the node cannot serve is kept but not claimed.** Deleting it, or dropping it from
the index, puts the key in neither the file store's view nor the legacy one, and what
neither view protects is what retirement destroys. Claiming it puts the key in signed
commitments and answers presence probes with a yes for a chunk that cannot be served, which
the commitment-bound audit penalises. So the file stays and the answers stop. Two states,
not one: a chunk that could not be *read* is settled by a later read, and one whose bytes
were *proven wrong* is not, because reading them again says the same thing.

**A verification proof expires.** The pre-retirement pass reads every chunk, and its result
is reused rather than re-read on every tick, because retirement is usually deferred by a
gate that has nothing to do with the files. A kept chunk that stops being servable in that
window is invisible: ordinary requests are still served from the legacy copy. The store
counts the times a chunk stops being servable, a proof records that count, and retirement
refuses a proof the store has outrun.

**A write announces itself before it starts.** The work runs on a blocking thread that
outlives the future waiting for it, so a cancelled write can leave the environment holding a
chunk that nothing recorded. The announcement is deliberately not part of what the node
claims to hold: it vetoes retirement and is reconciled against the disk, but no commitment,
quote or presence answer sees it. A delete drains both halves of any announced write for its
key, so a publish cannot land afterwards and undo it.

**The legacy environment never grows again.** Both stores sit on one disk, each measures
the same free space, and neither knows what the other is about to spend, so a chunk written
to both can be admitted twice against one lot of headroom and enough of them can cross the
reserve together and fill the volume this whole exercise exists to free. From the moment it
is adopted the environment is pinned to what it already occupies: it writes only from pages
it already has, and the file store's accounting becomes the only claim on free disk. The
cost is that the rollback copy is made only when the environment has room of its own, which
on a real node it usually does, because this migration exists precisely because deleting
millions of chunks filled the free list and returned nothing to the filesystem.

The category underneath all five is the same: **a fact established at one moment being acted
on at another.** Copying, verifying and retiring are separated by hours by design, and every
gap between them is somewhere the store can move. The pattern that works is to make the
belief carry its own expiry — the directory carries its mark, the proof carries the count it
saw, the write carries its note — rather than to check again and hope the check is close
enough to the act.

## Consequences

### Positive

- `unlink` returns blocks immediately. No free list, no compaction, no free space required
  to reclaim space. This is the entire point.
- `exists()` and `current_chunks()` become in-memory lookups with no syscall, cheaper than
  the LMDB reads they replace.
- `all_keys()` gains a stable ascending order, which the commitment builder needs and the
  pruning cursor wants.
- A fresh node never opens a memory map at all. `storage.db_size_gb` and ADR-0007's Windows
  map headroom cap die with LMDB.
- The store is self-describing: the filename is the hash, so an operator can verify a chunk
  with `b3sum`, and a scrambled directory layer is recoverable with `find`.

### Negative / Trade-offs

- **There is no rollback once a node has deleted its LMDB.** The staged rollout is the only
  control: a small leading batch, ours, and a wide window.
- **The window between the first and third releases is publicly known, and in it nobody is
  penalised for failing to hold a close-group chunk.** The cheapest way to exploit it is
  precise and worth writing down: a modified peer that never gossips a commitment at all is
  credited as a legacy node, can answer `Present`, and can then return `NotFound` or fail a
  possession check with no trust cost. It pays only for an identity and the traffic. One
  such identity removes one of seven replicas; control of all seven positions removes the
  chunk's availability. The commitment-bound audit is untouched, so this only works for a
  peer that publishes no commitment at all, which is itself visible. The mitigation is not
  a code change, it is not letting the third release slip.
  It is bounded, because the third release evicts afterwards, and audits keep recording so we
  can see it happening, but it is a real invitation for the duration.
- `exists()` is now an index lookup rather than a read of the backing store, so something
  outside the node deleting files is not noticed until the next read of that key. The read
  path self-heals, and a `stat` per call on the node's hottest path is not worth it.
- One inode and one directory entry per chunk. At 4 MiB per object that is 0.05% overhead
  and block rounding for a full chunk is exactly zero, but it is real.
- Windows publishes chunks under their final name rather than by rename, so a crash
  mid-write leaves a partial file that the write, read and pre-retirement paths each have
  to detect rather than trust.
- The paid list is still LMDB. It is a fixed 256 MiB map that contributes nothing to the
  disk problem, but it is why `heed` cannot be dropped yet.
- **Narrowing the commitment cuts the quoted price.** Price is quadratic in the committed
  key count, so a node that has just proved it is short of disk advertises a cheaper quote
  than its close-group peers and then refuses the store on capacity. A wasted round trip
  rather than a mispayment. The fix belongs to the quote path and is a separate decision.
- **A cancelled awaiter drops the per-key lock while its blocking write runs on.** This was
  accepted as bounded and is no longer accepted: review showed both consequences were worse
  than they look. The file store now records what it is writing, per key, cleared by the
  worker rather than the caller, and a delete waits out whatever is already writing its
  key, so a publish cannot land afterwards and undo a prune. A write into the legacy
  environment announces itself before it starts and is reconciled against the disk, so a
  cancelled one cannot leave a chunk that neither view protects.

### Neutral / Operational

- Startup cost is the directory scan: 122 ms warm and 1.55 s cold at 250,000 files across
  256 shards on APFS, of which the index build is 2 to 11 ms. No fast-start snapshot in v1.
  If one is ever added, validate it with the Merkle root of the sorted key set (which
  ADR-0004 already computes) rather than a checksum, because a checksum passes for an
  operator who restores yesterday's data directory and leaves yesterday's snapshot.
- APFS enumeration degrades with churn, not just size: a million files went from about 72
  to about 306 microseconds per entry over twenty cycles of 5% replacement. A long-lived
  macOS node will get slower to start in a way a fresh benchmark never shows.
- NTFS 8.3 short-name generation is worse for us than for most, because a node's filenames
  genuinely share a long prefix. Microsoft advises disabling it above 300,000 files per
  directory.

## Validation

**Already proved, locally:** publish is exactly-once under sixteen concurrent writers of one
address; the index rebuilds from the filesystem across restarts with a stable order; a file
in the wrong shard, an uppercase name, and a non-hex name are all refused; an interrupted
write is swept; a corrupt file is removed and repaired from the legacy copy; a missing file
drops out of the index so replication repairs it; the copier is resumable and cannot
resurrect a pruned chunk; retirement is refused while any gate is unmet and removes the
environment when they are all met; the release switches never round-trip through a config
file.

For the four mechanisms above: an environment carrying no mark is kept however badly it
reads, one carrying its own mark is removed whatever it is named, and the mark survives the
rename it exists to outlive; a chunk that cannot be read is kept on disk, not acknowledged,
not advertised, and answered for again once it can be read; a verification overtaken by a
file that stopped being readable does not authorise a deletion; a write in flight is not
claimed but does stop retirement; a delete outlasts a write nobody waited for; and a key the
environment holds that is in neither view refuses the proof and is put back where the gates
can see it. Each was verified by removing the fix and confirming the test fails.

**Proved in CI, on every commit.** The three harnesses that touch durability run on Linux,
macOS and Windows, and again on ext4, XFS and btrfs loopback volumes. The fourth measures
what one file per chunk costs at scale, which is a fleet question on a fleet that is Linux,
so it runs there:

- *The disk comes back.* Free space is sampled from the filesystem three times: before
  anything is written, at the peak where both stores hold everything, and after the
  environment is gone. Unlinking the environment while holding it open, which makes the
  paths disappear and keeps every block, fails it. This is the claim the whole decision
  rests on and the one the old store could not meet.
- *A crash loses nothing.* A child process is killed at a failpoint inside a publish, not
  after a sleep, so the kill lands where a half-finished chunk exists. What the parent then
  checks is that nothing is claimed that cannot be served, that a leftover is swept, and
  that a chunk caught between the environment write and the file write is named on the
  copier's list rather than lost between them. The same is done to a retirement: a child is
  killed with the environment renamed aside and marked, nothing yet deleted, which is the
  most destructive moment in the migration. The next start must finish that deletion and
  never reopen the directory, because the node has already told the network it serves those
  chunks from the file store. Refusing to believe the mark fails it.
- *Nodes sharing a disk take turns.* Two drivers on one volume, driving `migration::run`
  rather than the copier, with the lock held first by an outsider so neither can be observed
  making progress. Held through retirement as well as through copying, which is the heavier
  half. Removing the lock from either branch of the driver fails these.
- *One file per chunk costs what was claimed.* 100,000 chunks, measured rather than
  asserted: the startup scan takes about 100 ms, the index costs 52 bytes per chunk, opening
  the store reads 125 bytes whatever the chunks contain, and `put` writes exactly one
  directory entry per chunk. The claim underneath the scan's cost, that it reads names and
  does not `stat` behind each one, is checked against the machine rather than against a
  number: the same directory is walked twice in the same process, once reading names and
  once calling `metadata` on every entry, and the scan has to land on the names-only side of
  the two. A flat ceiling cannot settle that, because one `stat` per entry costs about three
  times a bare walk and stays well inside any ceiling loose enough not to flake. Adding that
  `stat` to the scan fails it.

Each of these was checked by mutation: the fix removed, the test confirmed red, the fix
restored.

**Fleet gates, which cannot be closed from a workstation:**

- Forced power loss on ext4, XFS, btrfs, APFS and NTFS showing old-or-new, with antivirus
  and 8.3 generation enabled on the NTFS run. The publish path off Unix does not rename at
  all, precisely because a rename cannot be shown to be durable there: it creates the chunk
  under its final name and flushes the file, which is documented to flush the creation
  metadata with it. What that leaves unproven is directory creation, which has no portable
  flush, so this run is what closes it. `ANT_MIGRATION_RETIRE_LEGACY=0` holds retirement off
  a node until then, per node, without a separate build.

  The loopback jobs above do **not** close this and are not offered as doing so. Killing a
  process and reopening the same mounted filesystem keeps the kernel page cache, so the
  bytes written before the kill are still there to be read; removing every flush from the
  publish path would leave those jobs green. What they do cover is the rest of what a
  filesystem decides: rename behaviour, locking, deletion, and whether the space is actually
  returned, which btrfs in particular accounts for differently from ext4.
- Startup scan, RSS and inode use at 1M and 10M keys, and on each filesystem. CI answers
  100,000 keys on ext4 and prints every number it measures, so drift is visible in the log
  before it trips a gate; `ANT_SCALE_KEYS` raises the count for a deliberate larger run on a
  machine with the disk for it. What CI cannot answer is where the curve stops being linear,
  which is a question about a machine holding ten million files, not about the code.
- The first release gates on no audit-timeout regression on the quiet responsible lane and on
  disk growth
  matching prediction.
- The second gates on a soak of the first, plus a verified retirement returning the
  predicted space.
- The third gates on migration-complete lines across the fleet, refetch backlogs drained, and the
  recorded audit failure rate back to its pre-migration baseline. The first release's
  observability is
  what makes that decidable.
- **How often a short-of-disk node can actually clear the possession gate.** A node whose
  close group is also short of space will not clear it, will not free its disk, and will
  tell its operator to add storage. That is the intended answer, but the fleet needs to
  show how large that population is before the second release, because it decides whether the
  migration
  completes on its own or needs operator action at scale.
- **Chunk size is 4 MiB, confirmed.** This was the open question that gated the whole
  design and it is now answered. Storj and borgbackup both ran one file per object at scale
  and reversed to packing, and both did so for *small* objects: Storj's pieces are *"often
  smaller than a hard drive sector"* and over 60% of borg's chunks are under 8 KiB. Nobody
  has reversed this decision for large objects. The tripwire remains: if the network ever
  starts storing a large share of small records, this ADR should be revisited, and the
  inode exposure below comes with it.

**Review trigger:** if the network ever adopts a declared node capacity, fixed-slot packing
becomes the better store design and this decision should be reopened.

## Implementation slices

This ADR is landed by two pull requests, in this order:

1. **Stop penalising a node for not holding a close-group chunk.** One switch, one helper,
   six call sites. It must ship a release ahead of the migration, because the penalty is
   the auditor's decision and a node cannot stop its peers applying it. The commitment-bound
   subtree audit keeps penalising throughout.
2. **The file store and the migration.** Everything else in this document.

A third release flips the switch from (1) back, gated on fleet evidence rather than a date,
which is why it is a release and not an expiry constant compiled into the first one.

## Notes for AI-assisted work

Drafted with AI assistance. Not to be marked Accepted without human review.
