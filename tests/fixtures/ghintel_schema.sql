CREATE TABLE repositories (
  id INTEGER PRIMARY KEY, host TEXT, owner TEXT, name TEXT, identity_key TEXT UNIQUE,
  canonical_url TEXT, github_node_id TEXT, created_at TEXT, updated_at TEXT
);
CREATE TABLE findings (id INTEGER PRIMARY KEY, repository_id INTEGER, version INTEGER, summary TEXT);
CREATE TABLE repository_current_findings (repository_id INTEGER PRIMARY KEY, finding_id INTEGER);
CREATE TABLE corrections (id INTEGER PRIMARY KEY, repository_id INTEGER, finding_id INTEGER, field_path TEXT);
CREATE TABLE github_snapshots (id INTEGER PRIMARY KEY, repository_id INTEGER, captured_at TEXT);
CREATE TABLE people (id INTEGER PRIMARY KEY, display_name TEXT, github_login TEXT);
CREATE TABLE repository_people (repository_id INTEGER, person_id INTEGER, role TEXT, quote TEXT);
CREATE TABLE language_inferences (id INTEGER PRIMARY KEY, finding_id INTEGER, category TEXT);
CREATE VIEW repository_project_cards AS
SELECT r.id AS repository_id, r.identity_key, r.canonical_url, r.owner, r.name,
       NULL AS finding_id, NULL AS finding_version, NULL AS purpose,
       '[]' AS tool_types_json, '[]' AS capabilities_json, '[]' AS intended_uses_json,
       NULL AS finding_provenance, NULL AS finding_created_at,
       NULL AS owner_login, NULL AS owner_display_name, NULL AS owner_type,
       NULL AS github_captured_at, '[]' AS documented_people_json,
       'not-enriched' AS information_status
FROM repositories r;
