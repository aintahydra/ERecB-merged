CREATE TABLE files (
  id INTEGER PRIMARY KEY, sha256_hash TEXT, md5_hash TEXT, magic TEXT, malicious TEXT,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE file_names (id INTEGER PRIMARY KEY, file_id INTEGER, file_name TEXT, source TEXT, first_seen_at TEXT);
CREATE TABLE tags (id INTEGER PRIMARY KEY, file_id INTEGER, tag TEXT, source TEXT, first_seen_at TEXT);
CREATE TABLE provider_lookups (
  id INTEGER PRIMARY KEY, file_id INTEGER, provider TEXT, query_hash TEXT, query_hash_type TEXT,
  status TEXT, http_status INTEGER, requested_at TEXT, completed_at TEXT, raw_response_path TEXT,
  error_message TEXT
);
CREATE TABLE file_observations (
  id INTEGER PRIMARY KEY, scan_job_id INTEGER, file_id INTEGER, file_path TEXT, file_name TEXT, magic TEXT, observed_at TEXT
);
CREATE TABLE scan_jobs (
  id INTEGER PRIMARY KEY, mode TEXT, root_path TEXT, status TEXT, started_at TEXT, finished_at TEXT,
  files_seen INTEGER, executables_found INTEGER, error_count INTEGER
);
CREATE TABLE scan_errors (
  id INTEGER PRIMARY KEY, scan_job_id INTEGER, file_path TEXT, phase TEXT, error_type TEXT,
  error_message TEXT, occurred_at TEXT
);
