CREATE TABLE ip_entities (
  id INTEGER PRIMARY KEY, ip TEXT, ip_version INTEGER, ipv4 TEXT, ipv6 TEXT,
  country_code TEXT, whois TEXT, malicious TEXT, first_seen_local TEXT, last_updated_local TEXT
);
CREATE TABLE ip_observations (
  id INTEGER PRIMARY KEY, ip_entity_id INTEGER, source_path TEXT, extraction_file TEXT, observed_at TEXT
);
CREATE TABLE ip_reverse_dns (ip_entity_id INTEGER, domain TEXT, first_seen_local TEXT);
CREATE TABLE ip_related_iocs (ip_entity_id INTEGER, ioc TEXT, first_seen_local TEXT);
CREATE TABLE ip_related_actors (ip_entity_id INTEGER, actor TEXT, first_seen_local TEXT);
CREATE TABLE provider_ip_results (
  id INTEGER PRIMARY KEY, provider_run_id INTEGER, ip_entity_id INTEGER, provider_name TEXT, provider_status TEXT,
  provider_result_code TEXT, provider_transaction_id TEXT, fetched_at TEXT, error_summary TEXT
);
CREATE TABLE provider_runs (
  id INTEGER PRIMARY KEY, provider_name TEXT, started_at TEXT, finished_at TEXT, status TEXT,
  input_file TEXT, ip_count INTEGER, success_count INTEGER, failure_count INTEGER
);
