# Evidence, provenance, and retention policy

Applies from schema version 2 (Aegis 2.0 Phase 1).

## What is stored

| Table | Contents | Exposed by the API? |
|---|---|---|
| `events` | Canonical, allowlisted event fields (no passwords, keys, or raw messages) | Yes: event explorer, incidents, exports |
| `raw_events` | The original record bytes, their SHA-256, provenance, and hash-chain links | **No.** Only digests and chain status through `/api/v1/evidence/verify` |
| `ingest_errors` | Quarantined lines: source, file identity, byte offset or line number, reason, line SHA-256, and length. **No line content.** | Metadata only, through `/api/v1/sources/<id>/errors` |
| `sources` | Per-source checkpoint (file identity + committed byte offset) and counters | Yes, through `/api/v1/sources` |

Provenance recorded for every raw record: ingestion mode (`synthetic`, `import`, `live`), source ID, source type, file identity (`device:inode` for live files, upload SHA-256 prefix for uploads), record locator (`offset:N`, `line:N`, `demo:N`), ingestion time (UTC), parser version, and schema version. Event time (Cowrie `timestamp`) stays in the canonical event, separate from ingestion time.

## Attempted passwords

Cowrie records the passwords that clients attempt. Aegis keeps them **only** inside `raw_events.raw`, as part of the original evidence. They are never added to canonical events, logs, the UI, reports, or exports. Treat the database file as sensitive: restrict filesystem access, and keep encryption at rest enabled on the host or volume (for example, an encrypted EBS volume).

## The hash chain

Each raw record stores `chain_hash = SHA-256(previous chain_hash + the record's metadata + raw_sha256)`, starting from 64 zeros. `/api/v1/evidence/verify` (also shown under **Lab & validation**) recomputes each record's digest and link, and reports the first invalid record.

What the chain **does** detect: edited raw bytes, edited provenance metadata, and removed or reordered records anywhere except at the end.

What it **does not** detect on its own: someone with write access to the database deleting the newest records, or rebuilding the entire chain. To cover that, periodically copy `head_seq` and `head_hash` from the verify endpoint to a place the Aegis host cannot write to (a ticket, an S3 bucket with Object Lock, or a signed message). Later, confirm that the record at that `seq` still carries that `chain_hash`. Aegis does not do this anchoring automatically yet.

The chain is tamper-evident, not tamper-proof. A blockchain would add nothing for a single writer.

## Retention

`Store.purge_raw(ingested_before)` clears raw bytes older than a UTC timestamp. It keeps digests, provenance, and links, so the chain still verifies; purged records are counted in the verify output. Canonical events and findings are unaffected. No retention schedule runs automatically. Choose a period that fits your legal and research requirements and run a purge on that schedule. A scheduled job and configuration are planned for Phase 7.

Quarantine records are capped at 1,000 per source; the oldest are removed first.

Events stored before schema version 2 have no raw evidence. They remain in their original dataset and are labeled as legacy through the absence of a `raw_events` row.

## Dataset separation

- `demo`: synthetic replay (`ingestion_mode = synthetic`)
- `imported`: analyst uploads (`ingestion_mode = import`). Uploads are atomic: one invalid line rejects the file.
- `live`: the configured Cowrie collector (`ingestion_mode = live`). Invalid lines are quarantined and collection continues.

Datasets never correlate with one another. Before 2.0, the live collector wrote into `imported`; those older rows stay there.
