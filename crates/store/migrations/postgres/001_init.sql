-- ScopeGate store schema placeholder (PostgreSQL)
-- M7/M8: aligned with store domain models; apply via migration tooling later.

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  version BIGINT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  parent_id TEXT NULL,
  token_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  budget BIGINT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revocation_reason TEXT NULL,
  taint_snapshot_id TEXT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT NULL,
  resolver TEXT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq BIGINT PRIMARY KEY,
  ts TEXT NOT NULL,
  task_id TEXT NULL,
  tool TEXT NULL,
  decision TEXT NOT NULL,
  reason TEXT NULL,
  args_digest TEXT NULL,
  result_digest TEXT NULL,
  prev_hash BYTEA NULL,
  hash BYTEA NULL
);

CREATE TABLE IF NOT EXISTS revocations (
  id TEXT PRIMARY KEY,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  reason TEXT NULL,
  revoked_at TEXT NOT NULL,
  revoked_by TEXT NULL
);

CREATE TABLE IF NOT EXISTS taint_snapshots (
  id TEXT PRIMARY KEY,
  task_id TEXT NULL,
  source TEXT NOT NULL,
  labels_json TEXT NOT NULL,
  digest TEXT NULL,
  created_at TEXT NOT NULL
);
