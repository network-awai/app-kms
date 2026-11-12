# Proposal: append-only KMS policy history

Status: design proposal, 2026-11-13. Tracked by AWAI-2837. No storage or
production change is implied. Owner direction is to make history append-only;
the storage implementation and cutover require qualification. Source baseline:
`ed91648fbe18619d6ace693ef50dc8f0189cba9a`.

## Existing behavior and limits

`worker/src/app.ts` stores one JSON record per `kms-sha256-*` policy ID in KV.
The ID hashes canonical resource pattern, sorted unique recipients, and issuer;
it does **not** hash the JWT, timestamps, links or revocation state. On recipient
change it writes a new record, then overwrites the predecessor's `supersededBy`;
revocation overwrites the requested record. Reads follow at most 64 forward links.
The two writes are not a transaction and concurrent updates can overwrite links.
The current test stub is a single in-memory map and does not establish KV
consistency or concurrency behavior. The repository's AGENTS.md assertion that
old records are never rewritten therefore describes the desired invariant, not
the implementation. No claim is made about the current deployed revision or data.

Existing records cannot prove every historical issuance, previous overwritten
value, ordering, authorization decision, or concurrent update. In particular,
content-derived policy IDs can recur when recipients return to a prior set;
policy ID alone is not a unique issuance or version ID. Do not manufacture
historical events from the surviving KV state or call it a complete audit trail.

## Proposed model

Use an independently durable append-only journal with a **linearizable,
conditional append** per policy lineage. The selected implementation must prove
its atomic commit, fencing and recovery properties; an object store, a CID, or
eventual-consistency KV alone does not supply them. If no qualified journal is
available, the migration stays blocked. A single elected writer is insufficient
without fencing against an expired leader. Do not introduce a new Cloudflare
storage dependency as the replacement.

Each committed event has a versioned deterministic encoding, unique event ID,
lineage ID, sequence, previous event hash, operation ID, kind, actor/authorization
reference, timestamp, policy ID and operation-specific fields. Hash the complete
canonical event bytes, with an explicit codec and domain separator; sign or
otherwise authenticate the committed envelope. Pin the issuer key identity and
preserve signed JWT bytes and verification-key history. Do not store admin tokens,
private keys, or raw authorization credentials in the journal. A hash chain
detects edits within an observed chain but cannot by itself prove completeness,
prevent truncation, or establish who authorized an operation: periodically seal
and independently retain signed checkpoints and replica receipts.

Event kinds: `legacy_snapshot` (only what was observed at migration), `issued`,
`recipients_changed`, and `revoked`. A snapshot records raw legacy record bytes,
their digest, key and capture provenance; it is not a backdated issuance event.
Journal events and policy contents are immutable; any lookup index, head pointer
or cache is a rebuildable projection. Store immutable event bytes and any content
objects before publishing a commit that references them. Verify object digest on
read and fail closed for missing or mismatching objects.

The legacy API accepts a policy ID, not a lineage/version ID. Maintain a
deterministic index from legacy IDs to lineage and current head, preserving observed
behavior where unambiguous. Before migration, detect duplicate IDs, converging or
forked chains, cycles, missing links, >64 links, revoked predecessors and JWT/key
inconsistency. Quarantine ambiguous cases; never silently choose a winner. Returning
to an earlier policy content must create a distinct event/version, without making
the legacy identifier ambiguous; until an explicit compatibility rule is approved,
reject that transition rather than create a loop or silently reassign an ID.

## Concurrency and failure contract

Resolve the requested ID and read a verified head at sequence N. In a single
transaction, validate authorization and current non-revoked state, reserve a
globally unique operation ID and conditional-append against N. A loser must
re-read and recompute its requested operation or return a conflict; never overwrite
a winner. Revocation and recipient changes race under the same fence, so an
append after a committed revoke is rejected. Deduplicate retries by operation ID
and request digest; reuse with different content is an error. A response is sent
only after durable commit; on timeout, query operation ID before retry. A missing
result is unknown until the journal can establish absence. Rebuild projections from
committed events; projection lag must not authorize stale access or lose revocation.
Define read consistency and availability explicitly and fail closed when a fresh
authoritative revocation/head cannot be obtained.

Legacy clients lack operation IDs and expected versions. A compatibility adapter
can retain request/response shapes, but cannot promise exactly-once after an
indeterminate network failure without a stable client-supplied idempotency key.
Add an optional key and document legacy ambiguity; do not infer one from request
body, because identical requests can be intentional distinct operations. Define
authorization, any 409/conflict behavior and API changes before implementation.

## Migration and cutover gates

1. Identify deployed revision, namespace, all writers, key versions and consumers;
   verify access and ownership without exposing secrets. Establish a supported,
   consistent snapshot method and an independently verifiable inventory. KV list
   and repeated reads alone do not prove a point-in-time complete snapshot while
   writers continue. Agree retention, encryption/access controls, and a restore
   location for sensitive policy metadata before exporting anything.
2. Build an offline importer and verifier. Under a separately authorized write
   freeze, drain all writers, fence old writers, enumerate all pages and values,
   capture a signed inventory (key, byte length, digest, count and capture scope),
   repeat and compare, then import observed records as snapshots. Compare counts,
   digests, policy-ID derivations, JWT verification where keys exist, graph links,
   revocations and API results. Keep an explicit exceptions report; absent old
   events and unknown keys remain unknown. Resolve every discrepancy before release.
3. Exercise an isolated journal and projection with synthetic fixtures. Shadow
   reads compare results without affecting authorization. Shadow writes are not a
   safe substitute for fencing unless capture is complete, ordered, durable and
   independently reconciled. Prove recovery after crash at every commit boundary,
   concurrent update/revoke, retries, corruption, stale replica, missing object,
   replay and split-brain attempts. Verify independent replica recovery and audit
   checkpoints. Preserve old data and operational rollback material.
4. Qualify client compatibility, revocation freshness, durability, monitoring,
   ownership and recovery, then seek separate approval for the production route
   cutover. Freeze/fence writers again, reconcile through a known high-water mark,
   atomically switch the authoritative writer, and verify reads and writes. Never
   allow KV and journal writers to operate independently after cutover.
5. Rollback after new journal writes requires an explicitly tested reverse
   projection or replay into a fenced legacy store, including revocations and
   successful writes since cutover. If parity cannot be proven, keep writes paused;
   simply routing to the old snapshot would lose history. Retain backups under the
   approved retention policy; deletion is a separate decision.

## Open decisions and acceptance

Select and qualify the journal/consensus service and replica placement; define
canonical encoding, key rotation and checkpoint retention; decide how legacy IDs
that recur or map to multiple lineages are exposed; define policy-data retention,
operator access and the write-freeze window. The design is ready for review, not
an implementation, proof of existing data completeness, or cutover authorization.
Implementation acceptance requires the migration gates and failure tests above,
plus documented evidence for source, isolated test, deployed candidate and live
cutover as separate milestones.
