#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
//! # SQLx Storage Provider
//!
//! This crate implements a storage provider for OpenMLS using SQLx. SQLite and
//! PostgreSQL are both supported, behind the `sqlite` (enabled by default) and
//! `postgres` cargo features. The two are independent: enabling both gives you
//! two provider types, not a runtime switch.
//!
//! * [`SqliteStorageProvider`] wraps a `sqlx::SqliteConnection`.
//! * [`PostgresStorageProvider`] wraps a `sqlx::PgConnection`.
//!
//! Both implement the
//! [`StorageProvider`](openmls_traits::storage::StorageProvider) trait from the
//! `openmls_traits` crate. Both borrow the connection rather than owning a
//! pool, so a host application can share a single transaction between the
//! provider and its own tables.
//!
//! The crate manages its own database migrations in its own migrations table
//! with the name `_openmls_sqlx_migrations`. All tables created by this crate
//! are prefixed with `openmls_` to avoid name clashes.

use std::future::Future;

#[macro_use]
mod wrappers;
#[macro_use]
mod provider;

mod codec;
mod group_data;
mod migrator;
mod source;
mod sql;

pub use crate::codec::Codec;

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!(
    "openmls_sqlx_storage needs at least one backend: enable the `sqlite` and/or `postgres` feature"
);

#[cfg(feature = "sqlite")]
impl_storage_provider! {
    module: sqlite,
    provider: SqliteStorageProvider,
    provider_doc: "A storage provider backed by a borrowed `sqlx::SqliteConnection`.",
    db: sqlx::Sqlite,
    connection: sqlx::SqliteConnection,
    owner: &'a mut sqlx::SqliteConnection,
    exec_fn: crate::source::sqlite_conn_exec,
    migrate_fn: crate::source::sqlite_conn_migrate,
    sql: sqlite,
    migrator: SqliteMigratorWrapper,
    migrations: "./migrations",
}

#[cfg(feature = "sqlite")]
pub use crate::sqlite::SqliteStorageProvider;

#[cfg(feature = "sqlite")]
impl_storage_provider! {
    module: sqlite_pool,
    provider: SqlitePoolStorageProvider,
    provider_doc: "A storage provider backed by an owned `sqlx::SqlitePool`.",
    db: sqlx::Sqlite,
    connection: sqlx::SqliteConnection,
    owner: sqlx::SqlitePool,
    exec_fn: crate::source::sqlite_pool_exec,
    migrate_fn: crate::source::sqlite_pool_migrate,
    sql: sqlite,
    migrator: SqliteMigratorWrapper,
    migrations: "./migrations",
}

#[cfg(feature = "sqlite")]
pub use crate::sqlite_pool::SqlitePoolStorageProvider;

#[cfg(feature = "postgres")]
impl_storage_provider! {
    module: postgres,
    provider: PostgresStorageProvider,
    provider_doc: "A storage provider backed by a borrowed `sqlx::PgConnection`.",
    db: sqlx::Postgres,
    connection: sqlx::PgConnection,
    owner: &'a mut sqlx::PgConnection,
    exec_fn: crate::source::pg_conn_exec,
    migrate_fn: crate::source::pg_conn_migrate,
    sql: postgres,
    migrator: PostgresMigratorWrapper,
    migrations: "./migrations_pg",
}

#[cfg(feature = "postgres")]
pub use crate::postgres::PostgresStorageProvider;

#[cfg(feature = "postgres")]
impl_storage_provider! {
    module: postgres_pool,
    provider: PostgresPoolStorageProvider,
    provider_doc: "A storage provider backed by an owned `sqlx::PgPool`.",
    db: sqlx::Postgres,
    connection: sqlx::PgConnection,
    owner: sqlx::PgPool,
    exec_fn: crate::source::pg_pool_exec,
    migrate_fn: crate::source::pg_pool_migrate,
    sql: postgres,
    migrator: PostgresMigratorWrapper,
    migrations: "./migrations_pg",
}

#[cfg(feature = "postgres")]
pub use crate::postgres_pool::PostgresPoolStorageProvider;

/// Awaits a query future built while the connection lock is still held,
/// keeping the guard and the await in the same statement.
pub(crate) async fn run_task<F>(task: F) -> F::Output
where
    F: Future,
{
    task.await
}
