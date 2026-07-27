//! Compile-time evidence for the `&mut self` receiver experiment.
//!
//! Nothing here needs a database: the assertions are all about types.
//!
//! * a *borrowed connection* provider and a *pool* provider both implement
//!   `StorageProvider` with no interior mutability;
//! * the futures those providers return are `Send`, so they can cross a
//!   `tokio::spawn`.

mod common;

use common::*;
use openmls_sqlx_storage::{SqlitePoolStorageProvider, SqliteStorageProvider};
use openmls_traits::storage::StorageProvider;
use sqlx::{SqliteConnection, SqlitePool};

fn assert_send<T: Send>(_: &T) {}

/// The borrowed-connection provider: holds `&mut SqliteConnection` directly.
#[allow(dead_code)]
async fn borrowed_connection_is_send(connection: &mut SqliteConnection) {
    let mut provider = SqliteStorageProvider::<JsonCodec>::new(connection);
    let group_id = TestGroupId(b"g".to_vec());
    let tree = TestBlob(b"t".to_vec());

    let fut = provider.write_tree(&group_id, &tree);
    assert_send(&fut);
    fut.await.unwrap();

    let fut = provider.tree::<_, TestBlob>(&group_id);
    assert_send(&fut);
    fut.await.unwrap();
}

/// The pool provider: owns a `SqlitePool`.
#[allow(dead_code)]
async fn pool_is_send(pool: SqlitePool) {
    let mut provider = SqlitePoolStorageProvider::<JsonCodec>::new(pool);
    let group_id = TestGroupId(b"g".to_vec());
    let tree = TestBlob(b"t".to_vec());

    let fut = provider.write_tree(&group_id, &tree);
    assert_send(&fut);
    fut.await.unwrap();

    let fut = provider.tree::<_, TestBlob>(&group_id);
    assert_send(&fut);
    fut.await.unwrap();
}

/// Whole-provider futures must survive `tokio::spawn`, which is the property
/// the `RefCell` version could not offer.
#[allow(dead_code)]
fn spawnable(pool: SqlitePool) {
    let handle = tokio::spawn(async move {
        let mut provider = SqlitePoolStorageProvider::<JsonCodec>::new(pool);
        let group_id = TestGroupId(b"g".to_vec());
        let tree = TestBlob(b"t".to_vec());
        provider.write_tree(&group_id, &tree).await.unwrap();
    });
    drop(handle);
}

#[test]
fn type_level_assertions_compile() {
    // The real assertions are the signatures above; this keeps the harness happy.
}
