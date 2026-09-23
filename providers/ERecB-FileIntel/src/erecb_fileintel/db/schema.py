SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256_hash TEXT,
  md5_hash TEXT,
  magic TEXT,
  malicious TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (malicious IN ('yes', 'no', 'unknown'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_files_sha256
  ON files(sha256_hash)
  WHERE sha256_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_files_md5
  ON files(md5_hash);

CREATE TABLE IF NOT EXISTS file_names (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  file_name TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  UNIQUE (file_id, file_name, source)
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  tag TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  UNIQUE (file_id, tag, source)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mode TEXT NOT NULL,
  root_path TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  files_seen INTEGER NOT NULL DEFAULT 0,
  executables_found INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  CHECK (mode IN ('watcher', 'manual')),
  CHECK (status IN ('running', 'succeeded', 'partial', 'failed'))
);

CREATE TABLE IF NOT EXISTS scan_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_job_id INTEGER NOT NULL,
  file_path TEXT,
  phase TEXT NOT NULL,
  error_type TEXT NOT NULL,
  error_message TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_job_id INTEGER NOT NULL,
  file_id INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  file_name TEXT NOT NULL,
  magic TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  md5_hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_observations_scan_job
  ON file_observations(scan_job_id);

CREATE INDEX IF NOT EXISTS idx_file_observations_sha256
  ON file_observations(sha256_hash);

CREATE TABLE IF NOT EXISTS provider_lookups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER,
  provider TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  query_hash_type TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  requested_at TEXT NOT NULL,
  completed_at TEXT,
  raw_response_path TEXT,
  error_message TEXT,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_provider_lookups_file_provider
  ON provider_lookups(file_id, provider);

CREATE INDEX IF NOT EXISTS idx_provider_lookups_query_hash
  ON provider_lookups(query_hash);

CREATE TABLE IF NOT EXISTS watch_directories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  input_dir TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  absolute_path TEXT NOT NULL,
  watch_depth INTEGER NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_scan_job_id INTEGER,
  status TEXT NOT NULL,
  FOREIGN KEY (last_scan_job_id) REFERENCES scan_jobs(id) ON DELETE SET NULL,
  UNIQUE (input_dir, relative_path, watch_depth)
);
"""

