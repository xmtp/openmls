//! Per-backend [`Migrate`] implementations.
//!
//! Each one is copied from the corresponding `sqlx::migrate::Migrate`
//! implementation in sqlx 0.8.6, with the migration table renamed from
//! `_sqlx_migrations` to `_openmls_sqlx_migrations` so that this crate's
//! migrations never collide with the host application's. They are kept as
//! separate verbatim copies rather than unified, because upstream's SQLite and
//! PostgreSQL implementations genuinely differ: SQLite has no cross-process
//! lock and no `no_tx` handling, PostgreSQL takes an advisory lock and honours
//! `no_tx`.

use std::time::{Duration, Instant};

use futures_core::future::BoxFuture;
use sqlx::{
    Connection, Executor,
    migrate::{AppliedMigration, Migrate, MigrateError, Migration},
    query, query_as,
};

#[cfg(feature = "sqlite")]
pub(crate) struct SqliteMigratorWrapper<'a>(pub(crate) &'a mut sqlx::SqliteConnection);

// The following migration is copied exactly from the `sqlx::migrate::Migrate`
// implementation for `SqliteConnection` in sqlx 8.6. The only adaptation is the
// name of the migration table which is `_openmls_sqlx_migrations` instead of
// `_sqlx_migrations`.
#[cfg(feature = "sqlite")]
impl Migrate for SqliteMigratorWrapper<'_> {
    fn ensure_migrations_table(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            self.0
                .execute(
                    r#"
CREATE TABLE IF NOT EXISTS _openmls_sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
                "#,
                )
                .await?;

            Ok(())
        })
    }

    fn dirty_version(&mut self) -> BoxFuture<'_, Result<Option<i64>, MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            let row: Option<(i64,)> = query_as(
                "SELECT version FROM _openmls_sqlx_migrations WHERE success = false ORDER BY version LIMIT 1",
            )
            .fetch_optional(&mut *self.0)
            .await?;

            Ok(row.map(|r| r.0))
        })
    }

    fn list_applied_migrations(
        &mut self,
    ) -> BoxFuture<'_, Result<Vec<AppliedMigration>, MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            let rows: Vec<(i64, Vec<u8>)> =
                query_as("SELECT version, checksum FROM _openmls_sqlx_migrations ORDER BY version")
                    .fetch_all(&mut *self.0)
                    .await?;

            let migrations = rows
                .into_iter()
                .map(|(version, checksum)| AppliedMigration {
                    version,
                    checksum: checksum.into(),
                })
                .collect();

            Ok(migrations)
        })
    }

    fn lock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move { Ok(()) })
    }

    fn unlock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move { Ok(()) })
    }

    fn apply<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            let mut tx = self.0.begin().await?;
            let start = Instant::now();

            // Use a single transaction for the actual migration script and the essential bookeeping so we never
            // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
            // The `execution_time` however can only be measured for the whole transaction. This value _only_ exists for
            // data lineage and debugging reasons, so it is not super important if it is lost. So we initialize it to -1
            // and update it once the actual transaction completed.
            let _ = tx
                .execute(&*migration.sql)
                .await
                .map_err(|e| MigrateError::ExecuteMigration(e, migration.version))?;

            // language=SQL
            let _ = query(
                r#"
    INSERT INTO _openmls_sqlx_migrations ( version, description, success, checksum, execution_time )
    VALUES ( ?1, ?2, TRUE, ?3, -1 )
                "#,
            )
            .bind(migration.version)
            .bind(&*migration.description)
            .bind(&*migration.checksum)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            // Update `elapsed_time`.
            // NOTE: The process may disconnect/die at this point, so the elapsed time value might be lost. We accept
            //       this small risk since this value is not super important.

            let elapsed = start.elapsed();

            // language=SQL
            #[allow(clippy::cast_possible_truncation)]
            let _ = query(
                r#"
    UPDATE _openmls_sqlx_migrations
    SET execution_time = ?1
    WHERE version = ?2
                "#,
            )
            .bind(elapsed.as_nanos() as i64)
            .bind(migration.version)
            .execute(&mut *self.0)
            .await?;

            Ok(elapsed)
        })
    }

    fn revert<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            // Use a single transaction for the actual migration script and the essential bookkeeping so we never
            // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
            let mut tx = self.0.begin().await?;
            let start = Instant::now();

            let _ = tx.execute(&*migration.sql).await?;

            // language=SQL
            let _ = query(r#"DELETE FROM _openmls_sqlx_migrations WHERE version = ?1"#)
                .bind(migration.version)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;

            let elapsed = start.elapsed();

            Ok(elapsed)
        })
    }
}

#[cfg(feature = "postgres")]
pub(crate) struct PostgresMigratorWrapper<'a>(pub(crate) &'a mut sqlx::PgConnection);

/// The advisory lock this crate's migrator holds while it runs.
///
/// Upstream sqlx derives its lock id from a CRC of the database name. That is
/// belt-and-braces — PostgreSQL scopes advisory locks to the current database
/// already — so a fixed id serves the same purpose without pulling in a CRC
/// dependency. The value is the ASCII bytes of `openmls`, which keeps it clear
/// of sqlx's own lock ids.
#[cfg(feature = "postgres")]
const MIGRATION_LOCK_ID: i64 = 0x6f_7065_6e6d_6c73;

// Copied from the `sqlx::migrate::Migrate` implementation for `PgConnection` in
// sqlx 8.6, with the same migration table rename as above and with the advisory
// lock id replaced by `MIGRATION_LOCK_ID`.
#[cfg(feature = "postgres")]
impl Migrate for PostgresMigratorWrapper<'_> {
    fn ensure_migrations_table(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move {
            // language=SQL
            self.0
                .execute(
                    r#"
CREATE TABLE IF NOT EXISTS _openmls_sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
                "#,
                )
                .await?;

            Ok(())
        })
    }

    fn dirty_version(&mut self) -> BoxFuture<'_, Result<Option<i64>, MigrateError>> {
        Box::pin(async move {
            // language=SQL
            let row: Option<(i64,)> = query_as(
                "SELECT version FROM _openmls_sqlx_migrations WHERE success = false ORDER BY version LIMIT 1",
            )
            .fetch_optional(&mut *self.0)
            .await?;

            Ok(row.map(|r| r.0))
        })
    }

    fn list_applied_migrations(
        &mut self,
    ) -> BoxFuture<'_, Result<Vec<AppliedMigration>, MigrateError>> {
        Box::pin(async move {
            // language=SQL
            let rows: Vec<(i64, Vec<u8>)> =
                query_as("SELECT version, checksum FROM _openmls_sqlx_migrations ORDER BY version")
                    .fetch_all(&mut *self.0)
                    .await?;

            let migrations = rows
                .into_iter()
                .map(|(version, checksum)| AppliedMigration {
                    version,
                    checksum: checksum.into(),
                })
                .collect();

            Ok(migrations)
        })
    }

    fn lock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move {
            // Create an application lock over the database. This function will
            // not return until the lock is acquired.
            //
            // https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS
            // language=SQL
            let _ = query("SELECT pg_advisory_lock($1)")
                .bind(MIGRATION_LOCK_ID)
                .execute(&mut *self.0)
                .await?;

            Ok(())
        })
    }

    fn unlock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move {
            // language=SQL
            let _ = query("SELECT pg_advisory_unlock($1)")
                .bind(MIGRATION_LOCK_ID)
                .execute(&mut *self.0)
                .await?;

            Ok(())
        })
    }

    fn apply<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            let start = Instant::now();

            // execute migration queries
            if migration.no_tx {
                execute_migration(self.0, migration).await?;
            } else {
                // Use a single transaction for the actual migration script and the essential bookeeping so we never
                // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
                // The `execution_time` however can only be measured for the whole transaction. This value _only_ exists for
                // data lineage and debugging reasons, so it is not super important if it is lost. So we initialize it to -1
                // and update it once the actual transaction completed.
                let mut tx = self.0.begin().await?;
                execute_migration(&mut tx, migration).await?;
                tx.commit().await?;
            }

            // Update `elapsed_time`.
            // NOTE: The process may disconnect/die at this point, so the elapsed time value might be lost. We accept
            //       this small risk since this value is not super important.
            let elapsed = start.elapsed();

            // language=SQL
            #[allow(clippy::cast_possible_truncation)]
            let _ = query(
                r#"
    UPDATE _openmls_sqlx_migrations
    SET execution_time = $1
    WHERE version = $2
                "#,
            )
            .bind(elapsed.as_nanos() as i64)
            .bind(migration.version)
            .execute(&mut *self.0)
            .await?;

            Ok(elapsed)
        })
    }

    fn revert<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            let start = Instant::now();

            // execute migration queries
            if migration.no_tx {
                revert_migration(self.0, migration).await?;
            } else {
                // Use a single transaction for the actual migration script and the essential bookeeping so we never
                // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
                let mut tx = self.0.begin().await?;
                revert_migration(&mut tx, migration).await?;
                tx.commit().await?;
            }

            let elapsed = start.elapsed();

            Ok(elapsed)
        })
    }
}

#[cfg(feature = "postgres")]
async fn execute_migration(
    conn: &mut sqlx::PgConnection,
    migration: &Migration,
) -> Result<(), MigrateError> {
    let _ = conn
        .execute(&*migration.sql)
        .await
        .map_err(|e| MigrateError::ExecuteMigration(e, migration.version))?;

    // language=SQL
    let _ = query(
        r#"
    INSERT INTO _openmls_sqlx_migrations ( version, description, success, checksum, execution_time )
    VALUES ( $1, $2, TRUE, $3, -1 )
                "#,
    )
    .bind(migration.version)
    .bind(&*migration.description)
    .bind(&*migration.checksum)
    .execute(conn)
    .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn revert_migration(
    conn: &mut sqlx::PgConnection,
    migration: &Migration,
) -> Result<(), MigrateError> {
    let _ = conn
        .execute(&*migration.sql)
        .await
        .map_err(|e| MigrateError::ExecuteMigration(e, migration.version))?;

    // language=SQL
    let _ = query(r#"DELETE FROM _openmls_sqlx_migrations WHERE version = $1"#)
        .bind(migration.version)
        .execute(conn)
        .await?;

    Ok(())
}
