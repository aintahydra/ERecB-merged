ALTER TABLE github_snapshots ADD COLUMN stars_count INTEGER;
ALTER TABLE github_snapshots ADD COLUMN license_spdx TEXT;
ALTER TABLE github_snapshots ADD COLUMN is_fork INTEGER NOT NULL DEFAULT 0 CHECK(is_fork IN (0, 1));
ALTER TABLE github_snapshots ADD COLUMN parent_full_name TEXT;
