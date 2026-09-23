CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    duplicate_policy TEXT NOT NULL CHECK(duplicate_policy IN ('reuse', 'refresh')),
    status TEXT NOT NULL CHECK(status IN ('running', 'complete', 'interrupted', 'failed')),
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE run_items (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    state TEXT NOT NULL CHECK(state IN ('pending', 'discovered', 'sources_captured', 'fetched', 'deterministic', 'enriched', 'validated', 'promoted', 'complete', 'failed', 'blocked_budget', 'skipped_reuse')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    input_hash TEXT,
    error_code TEXT,
    error_message TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, repository_id)
);
CREATE INDEX run_items_claim_idx ON run_items(run_id, state, lease_expires_at);

CREATE TABLE http_cache_entries (
    request_key TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL,
    body BLOB NOT NULL,
    etag TEXT,
    last_modified TEXT,
    response_headers_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE provider_attempts (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    source_set_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'succeeded', 'failed', 'invalid')),
    raw_response TEXT,
    parsed_json TEXT,
    validation_errors_json TEXT NOT NULL DEFAULT '[]',
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_micro_usd INTEGER,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX provider_attempts_cache_idx ON provider_attempts(provider, model, prompt_version, schema_version, source_set_hash, state);

CREATE TABLE provider_cache (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    source_set_hash TEXT NOT NULL,
    validation_version TEXT NOT NULL,
    attempt_id INTEGER NOT NULL REFERENCES provider_attempts(id),
    PRIMARY KEY(provider, model, prompt_version, schema_version, source_set_hash, validation_version)
);

CREATE TABLE budget_ledger (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    run_item_id INTEGER REFERENCES run_items(id) ON DELETE SET NULL,
    provider_attempt_id INTEGER REFERENCES provider_attempts(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK(kind IN ('reserve', 'commit', 'release')),
    request_count INTEGER NOT NULL DEFAULT 0,
    repository_count INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_micro_usd INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE language_inferences (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    subject_person_id INTEGER REFERENCES people(id),
    category TEXT NOT NULL CHECK(category IN ('Chinese', 'Russian', 'Slavic-other', 'Korean', 'Japanese', 'Arabic', 'Hebrew', 'Hindi', 'English', 'Unknown')),
    method TEXT NOT NULL CHECK(method IN ('explicit-statement', 'unicode-script', 'language-detector', 'gemini', 'combined')),
    confidence TEXT NOT NULL CHECK(confidence IN ('High', 'Medium', 'Low', 'Unknown')),
    detector_language TEXT,
    script_counts_json TEXT NOT NULL,
    rationale TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(finding_id)
);

CREATE TABLE finding_evidence (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    field_path TEXT NOT NULL,
    source_version_id INTEGER NOT NULL REFERENCES source_versions(id),
    quote TEXT NOT NULL,
    start_offset INTEGER,
    occurrence_count INTEGER NOT NULL,
    validation_state TEXT NOT NULL CHECK(validation_state IN ('valid', 'invalid')),
    UNIQUE(finding_id, field_path, source_version_id, quote)
);
