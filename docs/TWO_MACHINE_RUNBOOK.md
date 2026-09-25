# Two-machine intelligence exchange

The air-gapped machine handles captures and reports. The connected machine handles provider
requests, enrichment, database snapshots, and rule updates. Copy only request JSON plus its
`.sha256` sidecar from air gap to connected. Copy only database snapshots plus their
`.manifest.json` files, or a YARA cache-export directory, in the reverse direction. Do not
copy captured files or staging paths to the connected machine.

Install the root package and all four provider packages from this merged source tree on both
machines, using offline wheels on the air-gapped machine. The three provider CLIs use the
shared request contract from `erecb-triage`; install that package first. Keep both machines
on compatible schema versions. For compiled YARA cache transfer, OS, architecture, libyara,
and yara-python versions must match; import rechecks them.

The air-gap profile keeps its staging index at `data/airgap-staging.sqlite3`. This avoids
reusing a legacy `data/staging.sqlite3` whose recorded input or output roots may belong to a
different checkout. Existing staged captures remain with their original index and roots.

## Air-gapped capture and request export

From the repository root, place archives under `in/` and run:

```bash
erecb-triage --once --config config/airgap.yaml
erecb-triage captures list --config config/airgap.yaml
erecb-triage report --capture 1 --config config/airgap.yaml
erecb-triage requests export --capture 1 --output transfer/requests.json --config config/airgap.yaml
```

The report command reuses a manifest-verified staged capture and refreshes its four reports
and summary. It works after the original archive is removed, but not after the staged copy is
removed. `requests export` defaults to DB misses only and stops if a DB is unavailable or a
lookup is ambiguous. Use `--include all` to request every observed indicator, including
ones with existing records, without requiring working DBs. Every export prints counts,
skipped-file metrics, and IP singularities. Extraction errors abort export rather than
silently transferring an incomplete list. The bundle contains hashes, IPs, normalized GitHub
URLs, and opaque request metadata only; it has no captured paths or bytes.

All four adapters default to `selector: exec-only`. Set a specific adapter's selector to
`all` in a copied YAML profile when IPs or repository URLs may occur in text logs. Adjust
`max_depth_from_staged_root`, hidden-file rules, and byte limits there as needed. The watch
root remains direct-child only; staged search depth is a separate setting.

## Connected provider processing

Before using connected-only provider commands from the repository root, select the connected
role for this shell:

```bash
export ERECB_MODE_PROFILE=config/connected.yaml
```

Transfer `requests.json` **and** `requests.json.sha256`. With each provider's own credentials
and configuration in place, import the same bundle into all three queues:

```bash
erecb-ipintel requests import transfer/requests.json
erecb-fileintel requests import transfer/requests.json
ghintel requests import transfer/requests.json --config path/to/ghintel.toml

erecb-ipintel homework list
erecb-fileintel homework list
ghintel homework list --config path/to/ghintel.toml

erecb-ipintel homework run --limit 20
erecb-fileintel homework run --limit 20
ghintel homework run --limit 20 --config path/to/ghintel.toml
```

Request import validates the checksum and performs no provider calls. Each producer uses a
separate `*-homework.sqlite3` next to its intelligence database; do not return those queue
files to the air gap. Importing the same bundle twice is a no-op. A newer request moves an
item to the front of the LIFO queue; no-result, provider error, and rate-limit outcomes
remain homework with bounded retry delays. A rate limit also pauses that provider's whole
queue until its cooldown expires. A run leases a limited number of eligible items
and records attempts. Run again later for unresolved items. The legacy IPIntel
`enrich FILE --consume` command retains its older extraction-file semantics; use `homework`
for air-gap requests.

After enrichment, create consistent, checksummed snapshots:

```bash
erecb-ipintel db snapshot --source dbs/ipintel.sqlite3 --output transfer/ipintel.sqlite3
erecb-fileintel db snapshot --source dbs/fileintel.sqlite3 --output transfer/fileintel.sqlite3
ghintel db snapshot --output transfer/ghintel.sqlite3 --config path/to/ghintel.toml
```

The producer `db verify` commands can inspect copied snapshots before transport. Never copy
an active SQLite file directly: a WAL sidecar may contain committed data not in that file.
The snapshots use SQLite's backup API and have integrity/checksum manifests.

If rules changed, update and export the active YARA generation:

```bash
yararuler --config path/to/yararuler.toml update-rules
yararuler --config path/to/yararuler.toml cache-export --output transfer/yara-cache
```

Unchanged rule inputs reuse the verified active generation. `--force-rebuild` overrides reuse.

## Air-gapped return and report refresh

For provider-owned merge and cache activation commands, select the air-gap role:

```bash
export ERECB_MODE_PROFILE=config/airgap.yaml
```

Transfer the three `.sqlite3` snapshots and their `.manifest.json` sidecars. Stop the triage
watcher and any process writing the local destination databases. Verify the planned merges:

```bash
erecb-triage db import --fileintel transfer/fileintel.sqlite3 --ipintel transfer/ipintel.sqlite3 --ghintel transfer/ghintel.sqlite3 --dry-run --config config/airgap.yaml
```

If correct, rerun without `--dry-run`. The maintenance command verifies all snapshots,
previews all three producer-owned merges, prepares replacement databases, takes recoverable
SQLite backups under `data/import-backups/<import-set-id>/`, and activates the set while
holding the staging-root lock. It refuses a live triage process or SQLite sidecars. If
activation fails, it restores the already-replaced databases from those backups. Reimporting
the same snapshots is a provider-level no-op. Keep the receipt and backups until reports are
checked.

To activate a copied YARA cache, copy the whole `yara-cache/` directory and run:

```bash
yararuler --config path/to/yararuler.toml cache-import --source transfer/yara-cache
erecb-triage --check --config config/airgap.yaml
erecb-triage report --capture 1 --config config/airgap.yaml
```

Cache import verifies the transfer digests, platform/runtime compatibility, and compiled
artifact loadability before switching the active pointer; older generations remain available
for rollback. Reports show capture generation, policy and database fingerprints, and YARA
generation. A miss, unavailable DB, provider failure, or no YARA match is never a benign
verdict.

## Offline software upgrades

Build one release from the merged repository and create a wheelhouse for the target Python
version and architecture. Record wheel hashes in a release manifest and copy the wheelhouse
and manifest to both machines with the approved removable media.

Upgrade the connected machine first: stop provider workers, back up each intelligence DB and
homework queue, install the root package before the provider packages, then run each
provider's database verification and migration checks. Keep homework queue files on that
machine; they are not part of the return snapshots. After its smoke tests pass, install the
same wheel set on the air-gapped machine, run `erecb-triage --check`, and verify all transferred
DB snapshots before merging them. Do not upgrade only one machine across an exchange boundary.

Request bundle schema v1 is independent of provider DB schema versions. All three connected
provider packages must support a new bundle schema before the air-gap exporter is upgraded.
A producer DB schema must be supported by its air-gap merge implementation before that
snapshot is imported. Preserve the previous wheelhouse, DB backups, and YARA cache generation
until post-upgrade report replay passes. The YARA cache importer rejects OS, architecture,
libyara, or yara-python mismatches.
