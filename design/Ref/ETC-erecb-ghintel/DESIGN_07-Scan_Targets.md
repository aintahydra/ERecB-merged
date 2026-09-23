# Scan Enrichment Targets

`ghintel scan --enrich` accepts `--enrich-repository` (repeatable) and `--enrich-limit`.

Discovery and GitHub fetching retain their existing all-repository behavior. The new options apply only to the enrichment sub-run, which creates work items solely for the selected canonical repositories. This keeps model-input scope reviewable while retaining the normal discovery and metadata refresh behavior.

Target options require `--enrich`; otherwise the command exits before discovery begins.
