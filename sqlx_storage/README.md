# OpenMLS SQLx Storage

A codec-independent storage provider implementing the `StorageProvider` trait
from `openmls_traits` based on the `sqlx` crate.

Two backends are supported, behind cargo features that may be enabled together:

| Feature            | Provider                  | Connection               | Migrations       |
| ------------------ | ------------------------- | ------------------------ | ---------------- |
| `sqlite` (default) | `SqliteStorageProvider`   | `sqlx::SqliteConnection` | `migrations/`    |
| `postgres`         | `PostgresStorageProvider` | `sqlx::PgConnection`     | `migrations_pg/` |

A provider borrows its connection instead of owning a pool, so a host
application can share a single transaction between the provider and its own
tables.
