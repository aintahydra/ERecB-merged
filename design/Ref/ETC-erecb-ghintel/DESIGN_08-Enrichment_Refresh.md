# Enrichment Refresh Controls

`ghintel enrich --refresh` bypasses current-finding reuse for a new run. A validated provider-cache entry with the same provider, model, prompt/schema versions, and source set can still be promoted without a new model request.

`ghintel enrich --force-llm` implies `--refresh` and bypasses that validated response cache, subject to all configured request, token, and cost ceilings.

`scan --enrich` provides the corresponding `--enrich-refresh` and `--enrich-force-llm` options. These are ephemeral per-run overrides: the TOML configuration file is never rewritten.
