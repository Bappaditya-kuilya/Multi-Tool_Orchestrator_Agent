# Store migrations (M7/M8)

Schema placeholders aligned with `crates/store` domain models and the in-memory reference behavior.

## Layout

- `sqlite/001_init.sql` — SQLite/WAL baseline schema
- `postgres/001_init.sql` — PostgreSQL baseline schema

## Apply (planned)

Adapters are stubs today (`SqliteStore`, `PostgresStore`). When wiring `sqlx`:

1. Enable the commented `sqlx` dependency in `crates/store/Cargo.toml` (or workspace).
2. Run migrations at startup before serving traffic:
   - SQLite: `sqlx::migrate!("migrations/sqlite")` (or explicit path) after opening a WAL pool.
   - Postgres: `sqlx::migrate!("migrations/postgres")`.
3. Set SQLite pragmas for WAL + durability (`journal_mode=WAL`, `synchronous=NORMAL|FULL` per policy).
4. Enforce **append-before-return** for `audit_events` inside a transaction: assign/lock sequence, compute `prev_hash`/`hash`, insert, then return the committed event.
5. Fail closed on audit persistence/integrity errors when `StoreConfig::fail_closed_on_audit_error` is true.

## Notes

- `approvals.status` is stored as text (`pending|approved|denied|expired`) matching serde.
- `taint_snapshots.labels_json` stores label arrays as JSON text; adapters should validate/round-trip.
- `audit_events.prev_hash`/`hash` are binary blobs; hash material matches `store::compute_audit_hash`.
- Future migrations should be additive/versioned (`002_*`, etc.) and keep compatibility with in-flight audit chain verification.