# Merged repository layout

The watcher/triage application and its four intelligence producers are developed in one
repository: `https://github.com/aintahydra/ERecB-merged.git`. The former application and
provider GitHub repositories are historical sources. New changes to any of the five components
belong in this repository, in one review and commit history. The provider directories are normal
directories, not submodules or nested Git repositories.

| Component | Source and current design | Output used by triage |
| --- | --- | --- |
| Triage consumer | `src/erecb_triage/`, `design/` | Reports in `output/` |
| FileIntel producer | `providers/ERecB-FileIntel/`, its `design/` | `dbs/fileintel.sqlite3` |
| GHIntel producer | `providers/ERecB-GHIntel/`, its `design/` | `dbs/ghintel.sqlite3` |
| IPIntel producer | `providers/ErecB-IPIntel/`, its `design/` | `dbs/ipintel.sqlite3` |
| YaraRuler producer | `providers/ERecB-YaraRuler/`, its `design/` | Verified YARA cache under `rules/cache/` |

`design/DESIGN_01_SKELETON.md` and DESIGN 02–06 specify the consumer interfaces. Each
producer's own `design/` specifies its database or cache format and update behavior. The copies
under `design/Ref/` preserve the pre-merge reference baseline; they are not the current source
for producer changes. When a producer changes a schema or cache contract, update its design,
the matching consumer design and adapter, and their compatibility tests together. A merged
source tree does not change ownership of runtime data: producers write their outputs; triage
opens databases and cache generations read-only and never runs producer updates during capture
analysis.

The three SQLite files and YARA cache are generated/operator data, not Git content. The root
`.gitignore` excludes `dbs/`, `rules/cache/`, captured inputs, reports, local configuration,
and credentials. A fresh checkout needs these artifacts to be supplied or generated before
running the full profile. Configure each producer to publish to the paths above (from its own
directory, a relative path to the root starts with `../../`), then run
`erecb-triage --config config/watcher_all.yaml --check` from the repository root. Keep producer
updates and consumer capture runs separate so a capture sees a stable database/cache version.

Each component retains its own Python package, CLI, tests, and setup documentation. Work on a
producer from its directory, and work on triage from the repository root. The nested
`providers/ERecB-GHIntel/.github/workflows/ci.yml` is a record of the old repository's CI and
does not run in the merged repository; CI for this repository belongs at the root `.github/`.
