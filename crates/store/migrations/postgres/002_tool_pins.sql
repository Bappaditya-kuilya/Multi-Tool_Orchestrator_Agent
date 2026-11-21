-- Tool manifest pins for MCP tools/list drift detection (rug-pull defense).
CREATE TABLE IF NOT EXISTS tool_pins (
  upstream_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  descriptor_hash TEXT NOT NULL,
  descriptor_json TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  approved BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (upstream_id, tool_name)
);
