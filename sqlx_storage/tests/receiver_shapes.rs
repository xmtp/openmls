//! Compile-only probes for the by-value `self` receiver shape.
//!
//! Nothing here talks to a database; the point is what the type checker will
//! and will not accept for the two implementor shapes:
//!
//! * `impl StorageProvider for &PostgresPoolProvider` -- shared, `Copy` handle.
//! * `impl StorageProvider for &mut SqliteStorageProvider` -- exclusive handle.

mod common;

use common::*;
use openmls_sqlx_storage::SqliteStorageProvider;
use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};

fn assert_send<T: Send>(_: &T) {}

/// A shared handle is `Copy`, so repeated calls off the same binding need no
/// reborrow and the two futures can be alive at once.
#[allow(dead_code)]
#[cfg(feature = "postgres")]
fn pool_handle_is_copy_and_send(
    provider: &openmls_sqlx_storage::PostgresPoolProvider<'_, JsonCodec>,
    group_id: &TestGroupId,
) {
    let handle = provider;
    let f1 = handle.tree::<TestGroupId, TestBlob>(group_id);
    // `handle` is still live: `&P` is `Copy`.
    let f2 = handle.group_context::<TestGroupId, TestBlob>(group_id);
    assert_send(&f1);
    assert_send(&f2);
}

/// An exclusive handle is not `Copy`, but rustc still inserts a reborrow at
/// *method-call* position, so no explicit `&mut *x` is needed here.
#[allow(dead_code)]
fn conn_handle_auto_reborrows_at_method_calls(
    provider: &mut SqliteStorageProvider<'_, JsonCodec>,
    group_id: &TestGroupId,
) {
    let f1 = provider.tree::<TestGroupId, TestBlob>(group_id);
    assert_send(&f1);
    drop(f1);
    // No `&mut *provider` here -- method resolution reborrows.
    let f2 = provider.group_context::<TestGroupId, TestBlob>(group_id);
    assert_send(&f2);
}

async fn consumes_handle<S: StorageProvider<CURRENT_VERSION>>(
    storage: S,
    group_id: &TestGroupId,
) -> Result<Option<TestBlob>, S::Error> {
    storage.tree::<TestGroupId, TestBlob>(group_id).await
}

/// Forwarding an exclusive handle into a by-value generic parameter is the one
/// place that *does* need the explicit `&mut *x`: without it the first call
/// moves the handle.
#[allow(dead_code)]
fn forwarding_needs_explicit_reborrow(
    provider: &mut SqliteStorageProvider<'_, JsonCodec>,
    group_id: &TestGroupId,
) {
    let f1 = consumes_handle(&mut *provider, group_id);
    assert_send(&f1);
    drop(f1);
    let f2 = consumes_handle(&mut *provider, group_id);
    assert_send(&f2);
}

/// A shared handle forwards into the same by-value generic parameter with no
/// reborrow at all.
#[allow(dead_code)]
#[cfg(feature = "postgres")]
fn shared_forwarding_needs_nothing(
    provider: &openmls_sqlx_storage::PostgresPoolProvider<'_, JsonCodec>,
    group_id: &TestGroupId,
) {
    let f1 = consumes_handle(provider, group_id);
    let f2 = consumes_handle(provider, group_id);
    assert_send(&f1);
    assert_send(&f2);
}
