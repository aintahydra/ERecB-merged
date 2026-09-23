# Claude Provider Decision

## Decision

`ghintel` supports one selected enrichment provider per run. The default provider is Anthropic Claude Sonnet 4.6 (`claude-sonnet-4-6`), selected through:

```toml
[enrichment]
provider = "anthropic"
```

Gemini remains available for existing installations by setting `provider = "gemini"`. Local Ollama is supported by setting `provider = "ollama"` and configuring the endpoint and model (for example, `gpt-oss:120b`).

## Configuration and budgets

Claude uses its own `[anthropic]` configuration and `[pricing.anthropic]` rates. `ANTHROPIC_API_KEY` is referenced only by name in configuration; it is never written to the database, emitted by `doctor`, or included in reports. Both pricing values must be supplied by the operator before enrichment can run.

Ollama uses `[ollama]` with a plain HTTP(S) endpoint and does not require an API key. Its local provider charge is zero, but the same request, repository, and token ceilings apply. Because the native API returns token usage after generation, ghintel reserves one input token per UTF-8 byte before sending a request, then reconciles with Ollama's returned counts.

The existing run-wide ceilings remain enforced before every request. The provider performs token counting first, reserves a conservative maximum charge, stores returned usage, and reconciles the reservation after a response.

## Safety and auditability

The Claude adapter supplies the same fixed system instruction and bounded, untrusted source blocks as the Gemini adapter. It does not configure tools, browsing, file access, or function calls. Claude structured JSON output is validated by the existing Pydantic and exact-evidence checks before a finding is promoted. A structurally valid but unattributable or conflicting language claim is normalized to `Unknown`; fabricated evidence still rejects the response.

Provider, model, prompt version, schema version, and source-set hash continue to define the cache key. Claude-backed findings use `anthropic` provenance. Ollama-backed findings use `ollama` provenance. Migrations 005 and 006 add the `claude` and `ollama` language-inference methods so audit records do not mislabel the source provider.

## Operational check

Use `ghintel doctor --check-provider` to verify access to the selected model without uploading repository content. The older `--check-gemini` spelling remains accepted as an alias for this configured-provider check.
