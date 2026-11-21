-- Rate/budget counter snapshots for restart-safe enforcement.
CREATE TABLE IF NOT EXISTS rate_limit_snapshots (
  id TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
