CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE scan_roots (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    absolute_path TEXT NOT NULL,
    path_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE root_mapping_events (
    id INTEGER PRIMARY KEY,
    root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    old_path TEXT,
    new_path TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE repositories (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL CHECK(host = 'github.com'),
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    identity_key TEXT NOT NULL UNIQUE,
    canonical_url TEXT NOT NULL,
    github_node_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX repositories_identity_key_idx ON repositories(identity_key);

CREATE TABLE local_copies (
    id INTEGER PRIMARY KEY,
    root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    relative_path TEXT NOT NULL,
    path_key TEXT NOT NULL,
    git_kind TEXT NOT NULL,
    primary_repository_id INTEGER REFERENCES repositories(id),
    selection_reason TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    missing_at TEXT,
    UNIQUE(root_id, path_key)
);

CREATE TABLE remotes (
    id INTEGER PRIMARY KEY,
    local_copy_id INTEGER NOT NULL REFERENCES local_copies(id) ON DELETE CASCADE,
    remote_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('origin', 'upstream', 'other')),
    direction TEXT NOT NULL CHECK(direction IN ('fetch', 'push')),
    ordinal INTEGER NOT NULL,
    raw_url TEXT NOT NULL,
    repository_id INTEGER REFERENCES repositories(id),
    parse_error TEXT,
    UNIQUE(local_copy_id, remote_name, direction, ordinal)
);

CREATE TABLE discovery_runs (
    id INTEGER PRIMARY KEY,
    root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    status TEXT NOT NULL CHECK(status IN ('running', 'complete', 'failed')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    diagnostics_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE discovery_observations (
    discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    local_copy_id INTEGER NOT NULL REFERENCES local_copies(id),
    diagnostics_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY(discovery_run_id, local_copy_id)
);

CREATE TABLE source_documents (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    local_copy_id INTEGER REFERENCES local_copies(id),
    origin TEXT NOT NULL CHECK(origin IN ('local', 'github')),
    kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    translation INTEGER NOT NULL DEFAULT 0 CHECK(translation IN (0, 1)),
    priority INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX source_documents_lookup_idx ON source_documents(repository_id, local_copy_id, locator);

CREATE TABLE source_versions (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES source_documents(id) ON DELETE CASCADE,
    content_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    encoding TEXT NOT NULL,
    truncated INTEGER NOT NULL CHECK(truncated IN (0, 1)),
    captured_at TEXT NOT NULL,
    UNIQUE(document_id, content_hash)
);

CREATE TABLE github_snapshots (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    owner_login TEXT,
    owner_display_name TEXT,
    owner_type TEXT,
    metadata_json TEXT NOT NULL,
    metadata_hash TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE(repository_id, metadata_hash)
);

CREATE TABLE people (
    id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    github_login TEXT,
    UNIQUE(normalized_name, github_login)
);

CREATE TABLE repository_people (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    person_id INTEGER NOT NULL REFERENCES people(id),
    role TEXT NOT NULL CHECK(role IN ('author', 'maintainer', 'contributor', 'other-documented-role')),
    source_version_id INTEGER REFERENCES source_versions(id),
    quote TEXT,
    confidence TEXT NOT NULL DEFAULT 'Medium',
    UNIQUE(repository_id, person_id, role, source_version_id)
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    version INTEGER NOT NULL,
    input_fingerprint TEXT NOT NULL,
    summary TEXT,
    tool_types_json TEXT NOT NULL DEFAULT '[]',
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    intended_uses_json TEXT NOT NULL DEFAULT '[]',
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(repository_id, version),
    UNIQUE(repository_id, input_fingerprint, provenance)
);

CREATE TABLE repository_current_findings (
    repository_id INTEGER PRIMARY KEY REFERENCES repositories(id),
    finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id)
);

CREATE TABLE corrections (
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    finding_id INTEGER REFERENCES findings(id),
    field_path TEXT NOT NULL,
    replacement_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    supersedes_id INTEGER REFERENCES corrections(id),
    created_at TEXT NOT NULL
);

CREATE VIEW repository_project_cards AS
SELECT
    r.id AS repository_id,
    r.identity_key,
    r.canonical_url,
    r.owner,
    r.name,
    f.id AS finding_id,
    f.version AS finding_version,
    f.summary AS purpose,
    f.tool_types_json AS tool_types_json,
    f.capabilities_json AS capabilities_json,
    f.intended_uses_json AS intended_uses_json,
    f.provenance AS finding_provenance,
    f.created_at AS finding_created_at,
    s.owner_login,
    s.owner_display_name,
    s.owner_type,
    s.captured_at AS github_captured_at,
    COALESCE((
        SELECT json_group_array(json_object('name', p.display_name, 'login', p.github_login, 'role', rp.role, 'quote', rp.quote))
        FROM repository_people rp
        JOIN people p ON p.id = rp.person_id
        WHERE rp.repository_id = r.id
    ), '[]') AS documented_people_json,
    CASE
        WHEN f.id IS NOT NULL THEN 'ready'
        WHEN s.id IS NOT NULL THEN 'deterministic-only'
        ELSE 'not-enriched'
    END AS information_status
FROM repositories r
LEFT JOIN repository_current_findings current ON current.repository_id = r.id
LEFT JOIN findings f ON f.id = current.finding_id
LEFT JOIN github_snapshots s ON s.id = (
    SELECT latest.id FROM github_snapshots latest
    WHERE latest.repository_id = r.id
    ORDER BY latest.captured_at DESC, latest.id DESC LIMIT 1
);
