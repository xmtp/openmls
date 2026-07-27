//! Probe: can a pool-backed provider satisfy the CURRENT `&self` trait with no
//! interior mutability? `&sqlx::Pool` implements `Executor`, so the same
//! Storable helpers the connection provider uses should accept `&self.pool`.
#![cfg(feature = "postgres")]

use std::marker::PhantomData;

use openmls_traits::storage::{CURRENT_VERSION, traits};

use crate::codec::Codec;

pub struct PgPoolStorageProvider<C> {
    pub pool: sqlx::PgPool,
    pub codec: PhantomData<C>,
}

impl<C: Codec> PgPoolStorageProvider<C> {
    /// Mirrors `write_group_state`, but executing against `&self.pool` under a
    /// shared receiver and with no cell of any kind.
    pub async fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), sqlx::Error> {
        crate::postgres::StorableGroupDataRef(group_state)
            .store::<_, C>(
                &self.pool,
                group_id,
                crate::group_data::GroupDataType::GroupState,
            )
            .await
    }
}

#[allow(dead_code)]
fn assert_pool_future_is_send<C: Codec + Send + Sync, G, S>(
    p: &PgPoolStorageProvider<C>,
    gid: &G,
    gs: &S,
) where
    G: traits::GroupId<CURRENT_VERSION> + Sync,
    S: traits::GroupState<CURRENT_VERSION> + Sync,
{
    fn assert_send<T: Send>(_: &T) {}
    let fut = p.write_group_state(gid, gs);
    assert_send(&fut);
}
