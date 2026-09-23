# ghintel design package

Status: implementation record for release 0.1.2. For installation and operation, use the current [README](../README.md), [installation guide](../docs/INSTALL.md), and [operations guide](../docs/USAGE.md).

`ghintel` is a local-first Python CLI that inventories Git repositories, resolves GitHub identities, captures bounded documentary evidence, enriches records through GitHub and (optionally) Gemini, and keeps an auditable SQLite history. Its primary read workflow is: an investigator sees a GitHub project link while examining a directory, looks up that link in the local database, and immediately sees the project's purpose plus clearly qualified developer information. It never executes code from a discovered repository.

The design is split into three documents:

- [Architecture](DESIGN_02-Architecture.md) defines boundaries, data flow, discovery and inference rules, safety properties, and external integrations.
- [Data, CLI, and configuration](DESIGN_03-Data_CLI_Config.md) defines persistence invariants, the logical schema, command contracts, configuration behavior, and exit codes.
- [Implementation plan](DESIGN_04-Implementation_Plan.md) decomposes delivery into ordered increments with tests and stage gates.

## Decisions at a glance

1. A canonical repository is the case-insensitive key `github.com/owner/repository`; a local checkout and each configured remote are separate records. `origin`, `upstream`, and other remotes are never silently merged.
2. The input walk discovers repository boundaries first. Source capture then prunes every nested boundary, which prevents a parent from claiming a nested repository's documents.
3. Raw sources, GitHub snapshots, provider responses, findings, and corrections are immutable versions. Small pointer/overlay tables define the effective current view.
4. `reuse` always refreshes local discovery and copy locations but performs no GitHub or Gemini request when a current finding exists. `refresh` uses conditional GitHub requests and only creates a finding when its input fingerprint changes, unless `force_llm_on_unchanged` explicitly requests a new enrichment attempt.
5. Mother-tongue output is an inference about an attributable person, never a verified biography. Organizations, unresolved subjects, conflicting multi-author projects, unsupported languages, and weak evidence resolve to `Unknown`.
6. Gemini output is untrusted until schema, category, source ownership, and exact-quote validation all succeed. Failed responses remain audit records and can never become current findings.
7. Budget checks reserve the worst-case request cost before dispatch. Missing/zero operator pricing disables Gemini enrichment rather than implying that a model is free.
8. Paths below a scan root are stored relative to a logical root. `scan --target-dir PATH` atomically persists a validated absolute input path and scans it as a logical root; moving an existing corpus uses explicit root remapping rather than rewriting evidence history.

9. `lookup GITHUB_URL` is an offline, database-only URL resolver. Its compact project card presents purpose and people separately: GitHub owner/account, documented author or maintainer, and unknown are never conflated; it never silently fetches or enriches a project.

## Workspace evidence used by the plan

The supplied corpus currently contains exactly seven qualifying `.git` directories. It also exercises nested repository boundaries, `.git` URL suffix variants, Chinese and English project prose, a paired `README.md`/`README-en.md`, and sqlmap's large translation set. Those observations are reflected in the Stage 1 and language fixture gates. `askings.md`, `do_not_read/`, `.env`, and the token-looking root file were not read.

## Authoritative interfaces

The implementation should pin tested dependency ranges, but not hard-code mutable service pricing. As of this design, Google's current examples use `google-genai`, support Pydantic/JSON Schema structured output, expose model listing and token counting, and use `gemini-3.8-flash` in examples. The configured model remains operator-controlled and `doctor` must verify account visibility before use:

- [Google Gen AI Python SDK](https://googleapis.github.io/python-genai/)
- [Gemini structured outputs](https://ai.google.dev/gemini-api/docs/structured-output)
- [Gemini token counting and usage](https://ai.google.dev/gemini-api/docs/tokens)
- [Gemini models](https://ai.google.dev/gemini-api/docs/models)
- [GitHub conditional requests and retry guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
- [GitHub REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
