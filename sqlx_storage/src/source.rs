//! How a provider reaches its executor.
//!
//! With `&mut self` receivers on `StorageProvider`, a provider can hand out a
//! `&mut` borrow of whatever it owns without any interior mutability. The two
//! shapes we care about differ only in how that owned value turns into a sqlx
//! `Executor`, so each is a free function passed into
//! [`impl_storage_provider`](crate::impl_storage_provider) as a macro argument:
//!
//! * a *borrowed connection* (`&mut SqliteConnection`) reborrows through two
//!   levels of `&mut`;
//! * a *pool* (`SqlitePool`) hands out a shared `&Pool`, which sqlx already
//!   implements `Executor` for.
//!
//! Neither needs a `RefCell` or a `Mutex`.

use sqlx::{Executor, migrate::MigrateError, migrate::Migrator};

macro_rules! source_fns {
    (
        db: $db:ty,
        connection: $connection:ty,
        pool: $pool:ty,
        migrator: $migrator:ident,
        conn_exec: $conn_exec:ident,
        pool_exec: $pool_exec:ident,
        conn_migrate: $conn_migrate:ident,
        pool_migrate: $pool_migrate:ident $(,)?
    ) => {
        /// Executor for a provider that borrows a single connection.
        pub(crate) fn $conn_exec<'e>(
            connection: &'e mut &mut $connection,
        ) -> impl Executor<'e, Database = $db> {
            &mut **connection
        }

        /// Executor for a provider that owns a pool.
        pub(crate) fn $pool_exec<'e>(pool: &'e mut $pool) -> impl Executor<'e, Database = $db> {
            &*pool
        }

        pub(crate) async fn $conn_migrate(
            connection: &mut &mut $connection,
            migrator: Migrator,
        ) -> Result<(), MigrateError> {
            migrator
                .run_direct(&mut crate::migrator::$migrator(&mut **connection))
                .await
        }

        pub(crate) async fn $pool_migrate(
            pool: &mut $pool,
            migrator: Migrator,
        ) -> Result<(), MigrateError> {
            let mut conn = pool.acquire().await?;
            migrator
                .run_direct(&mut crate::migrator::$migrator(&mut conn))
                .await
        }
    };
}

#[cfg(feature = "sqlite")]
source_fns! {
    db: sqlx::Sqlite,
    connection: sqlx::SqliteConnection,
    pool: sqlx::SqlitePool,
    migrator: SqliteMigratorWrapper,
    conn_exec: sqlite_conn_exec,
    pool_exec: sqlite_pool_exec,
    conn_migrate: sqlite_conn_migrate,
    pool_migrate: sqlite_pool_migrate,
}

#[cfg(feature = "postgres")]
source_fns! {
    db: sqlx::Postgres,
    connection: sqlx::PgConnection,
    pool: sqlx::PgPool,
    migrator: PostgresMigratorWrapper,
    conn_exec: pg_conn_exec,
    pool_exec: pg_pool_exec,
    conn_migrate: pg_conn_migrate,
    pool_migrate: pg_pool_migrate,
}
