//! The storage provider implementation, written once and stamped out per
//! backend by [`impl_storage_provider`].
//!
//! Making a single provider generic over `sqlx::Database` is not practical:
//! every helper would have to repeat `for<'q> <DB as Database>::Arguments<'q>:
//! Encode<...>`-style bounds, and those bounds spread to every caller. Two
//! concrete instantiations of one macro body cost nothing at the type level and
//! keep the call sites readable.
//!
//! Only three things vary between the backends, and all three are macro
//! arguments: the sqlx database type, the connection type, and which module of
//! [`crate::sql`] and which migration tree to use.

macro_rules! impl_storage_provider {
    (
        module: $module:ident,
        provider: $provider:ident,
        provider_doc: $provider_doc:literal,
        db: $db:ty,
        connection: $connection:ty,
        sql: $sql:ident,
        migrator: $migrator:ident,
        migrations: $migrations:tt $(,)?
    ) => {
        pub(crate) mod $module {
            use std::marker::PhantomData;
            use tokio::sync::Mutex;

            use openmls_traits::storage::{
                CURRENT_VERSION, Entity, Key, StorageProvider,
                traits::{
                    self, ProposalRef as ProposalRefTrait,
                    SignaturePublicKey as SignaturePublicKeyTrait,
                },
            };
            use sqlx::{
                Database, Encode, Executor, Row, Type, encode::IsNull, error::BoxDynError, query,
                query_scalar,
            };

            use crate::{
                codec::{Codec, CodecInternal},
                group_data::GroupDataType,
                run_task,
                sql::$sql as sql,
            };

            storable_wrappers!();

            #[doc = $provider_doc]
            ///
            /// It is generic over any codec `C` that implements the
            /// [`Codec`](crate::Codec) trait. The codec is used to serialize and
            /// deserialize the data stored in the underlying database.
            pub struct $provider<'a, C> {
                connection: Mutex<&'a mut $connection>,
                codec: PhantomData<C>,
            }

            impl<'a, C: Codec> $provider<'a, C> {
                #[doc = concat!(
                    "Create a new `", stringify!($provider), "` based on the given `",
                    stringify!($connection), "`."
                )]
                pub fn new(connection: &'a mut $connection) -> Self {
                    Self {
                        connection: Mutex::new(connection),
                        codec: PhantomData,
                    }
                }

                /// Run the migrations for the storage provider using sqlx's built-in
                /// migration support.
                pub async fn run_migrations(&mut self) -> Result<(), sqlx::migrate::MigrateError> {
                    let mut conn = self.connection.lock().await;
                    sqlx::migrate!($migrations)
                        .run_direct(&mut crate::migrator::$migrator(*conn))
                        .await?;
                    Ok(())
                }

                fn wrap_storable_group_id_ref<'b, GroupId: Key<CURRENT_VERSION>>(
                    &self,
                    group_id: &'b GroupId,
                ) -> StorableGroupIdRef<'b, GroupId, C> {
                    StorableGroupIdRef(group_id, PhantomData)
                }
            }

            impl<C: Codec> StorageProvider<CURRENT_VERSION> for $provider<'_, C> {
                type Error = sqlx::Error;

                async fn write_mls_join_config<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    config: &MlsGroupJoinConfig,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(config);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::JoinGroupConfig,
                    );
                    run_task(task).await
                }

                async fn append_own_leaf_node<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    LeafNode: traits::LeafNode<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    leaf_node: &LeafNode,
                ) -> Result<(), Self::Error> {
                    let storable = StorableLeafNodeRef(leaf_node);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, group_id);
                    run_task(task).await
                }

                async fn queue_proposal<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
                    QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    proposal_ref: &ProposalRef,
                    proposal: &QueuedProposal,
                ) -> Result<(), Self::Error> {
                    let storable = StorableProposalRef(proposal_ref, proposal);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, group_id);
                    run_task(task).await
                }

                async fn write_tree<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    TreeSync: traits::TreeSync<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    tree: &TreeSync,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(tree);
                    let mut connection = self.connection.lock().await;
                    let task =
                        storable.store::<_, C>(&mut **connection, group_id, GroupDataType::Tree);
                    run_task(task).await
                }

                async fn write_interim_transcript_hash<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    interim_transcript_hash: &InterimTranscriptHash,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(interim_transcript_hash);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::InterimTranscriptHash,
                    );
                    run_task(task).await
                }

                async fn write_context<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    GroupContext: traits::GroupContext<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    group_context: &GroupContext,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(group_context);
                    let mut connection = self.connection.lock().await;
                    let task =
                        storable.store::<_, C>(&mut **connection, group_id, GroupDataType::Context);
                    run_task(task).await
                }

                async fn write_confirmation_tag<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    confirmation_tag: &ConfirmationTag,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(confirmation_tag);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ConfirmationTag,
                    );
                    run_task(task).await
                }

                async fn write_group_state<
                    GroupState: traits::GroupState<CURRENT_VERSION>,
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    group_state: &GroupState,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(group_state);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::GroupState,
                    );
                    run_task(task).await
                }

                async fn write_message_secrets<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    message_secrets: &MessageSecrets,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(message_secrets);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::MessageSecrets,
                    );
                    run_task(task).await
                }

                async fn write_resumption_psk_store<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    resumption_psk_store: &ResumptionPskStore,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(resumption_psk_store);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ResumptionPskStore,
                    );
                    run_task(task).await
                }

                async fn write_own_leaf_index<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    own_leaf_index: &LeafNodeIndex,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(own_leaf_index);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::OwnLeafIndex,
                    );
                    run_task(task).await
                }

                async fn write_group_epoch_secrets<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    group_epoch_secrets: &GroupEpochSecrets,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(group_epoch_secrets);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::GroupEpochSecrets,
                    );
                    run_task(task).await
                }

                async fn write_signature_key_pair<
                    SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
                    SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &SignaturePublicKey,
                    signature_key_pair: &SignatureKeyPair,
                ) -> Result<(), Self::Error> {
                    let storable = StorableSignatureKeyPairsRef(signature_key_pair);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, public_key);
                    run_task(task).await
                }

                async fn write_encryption_key_pair<
                    EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
                    HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &EncryptionKey,
                    key_pair: &HpkeKeyPair,
                ) -> Result<(), Self::Error> {
                    let storable = StorableEncryptionKeyPairRef(key_pair);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, public_key);
                    run_task(task).await
                }

                async fn write_encryption_epoch_key_pairs<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    EpochKey: traits::EpochKey<CURRENT_VERSION>,
                    HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    epoch: &EpochKey,
                    leaf_index: u32,
                    key_pairs: &[HpkeKeyPair],
                ) -> Result<(), Self::Error> {
                    let storable = StorableEpochKeyPairsRef(key_pairs);
                    let mut connection = self.connection.lock().await;
                    let task =
                        storable.store::<_, _, C>(&mut **connection, group_id, epoch, leaf_index);
                    run_task(task).await
                }

                async fn write_key_package<
                    HashReference: traits::HashReference<CURRENT_VERSION>,
                    KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
                >(
                    &self,
                    hash_ref: &HashReference,
                    key_package: &KeyPackage,
                ) -> Result<(), Self::Error> {
                    let storable = StorableKeyPackageRef(key_package);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, hash_ref);
                    run_task(task).await
                }

                async fn write_psk<
                    PskId: traits::PskId<CURRENT_VERSION>,
                    PskBundle: traits::PskBundle<CURRENT_VERSION>,
                >(
                    &self,
                    psk_id: &PskId,
                    psk: &PskBundle,
                ) -> Result<(), Self::Error> {
                    let storable = StorablePskBundleRef(psk);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(&mut **connection, psk_id);
                    run_task(task).await
                }

                async fn mls_group_join_config<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::JoinGroupConfig,
                    );
                    run_task(task).await
                }

                async fn own_leaf_nodes<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    LeafNode: traits::LeafNode<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Vec<LeafNode>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableLeafNode::load::<_, C>(&mut **connection, group_id);
                    run_task(task).await
                }

                async fn queued_proposal_refs<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Vec<ProposalRef>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableProposal::<u8, ProposalRef>::load_refs::<_, C>(
                        &mut **connection,
                        group_id,
                    );
                    run_task(task).await
                }

                async fn queued_proposals<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
                    QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableProposal::load::<_, C>(&mut **connection, group_id);
                    run_task(task).await
                }

                async fn tree<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    TreeSync: traits::TreeSync<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<TreeSync>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::Tree,
                    );
                    run_task(task).await
                }

                async fn group_context<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    GroupContext: traits::GroupContext<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<GroupContext>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::Context,
                    );
                    run_task(task).await
                }

                async fn interim_transcript_hash<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::InterimTranscriptHash,
                    );
                    run_task(task).await
                }

                async fn confirmation_tag<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<ConfirmationTag>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ConfirmationTag,
                    );
                    run_task(task).await
                }

                async fn group_state<
                    GroupState: traits::GroupState<CURRENT_VERSION>,
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<GroupState>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::GroupState,
                    );
                    run_task(task).await
                }

                async fn message_secrets<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<MessageSecrets>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::MessageSecrets,
                    );
                    run_task(task).await
                }

                async fn resumption_psk_store<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<ResumptionPskStore>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ResumptionPskStore,
                    );
                    run_task(task).await
                }

                async fn own_leaf_index<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<LeafNodeIndex>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::OwnLeafIndex,
                    );
                    run_task(task).await
                }

                async fn group_epoch_secrets<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::GroupEpochSecrets,
                    );
                    run_task(task).await
                }

                async fn signature_key_pair<
                    SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
                    SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &SignaturePublicKey,
                ) -> Result<Option<SignatureKeyPair>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task =
                        StorableSignatureKeyPairs::load::<_, C>(&mut **connection, public_key);
                    run_task(task).await
                }

                async fn encryption_key_pair<
                    HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
                    EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &EncryptionKey,
                ) -> Result<Option<HpkeKeyPair>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableEncryptionKeyPair::load::<_, C>(&mut **connection, public_key);
                    run_task(task).await
                }

                async fn encryption_epoch_key_pairs<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    EpochKey: traits::EpochKey<CURRENT_VERSION>,
                    HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    epoch: &EpochKey,
                    leaf_index: u32,
                ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = load_epoch_key_pairs::<_, _, _, C>(
                        &mut **connection,
                        group_id,
                        epoch,
                        leaf_index,
                    );
                    run_task(task).await
                }

                async fn key_package<
                    KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
                    KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
                >(
                    &self,
                    hash_ref: &KeyPackageRef,
                ) -> Result<Option<KeyPackage>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableKeyPackage::load::<_, C>(&mut **connection, hash_ref);
                    run_task(task).await
                }

                async fn psk<
                    PskBundle: traits::PskBundle<CURRENT_VERSION>,
                    PskId: traits::PskId<CURRENT_VERSION>,
                >(
                    &self,
                    psk_id: &PskId,
                ) -> Result<Option<PskBundle>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = load_psk_bundle::<_, _, C>(&mut **connection, psk_id);
                    run_task(task).await
                }

                async fn remove_proposal<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    proposal_ref: &ProposalRef,
                ) -> Result<(), Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let task = storable.delete_proposal(&mut **connection, proposal_ref);
                    run_task(task).await
                }

                async fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_leaf_nodes(&mut **connection);
                    run_task(task).await
                }

                async fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable
                        .delete_group_data(&mut **connection, GroupDataType::JoinGroupConfig);
                    run_task(task).await
                }

                async fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_group_data(&mut **connection, GroupDataType::Tree);
                    run_task(task).await
                }

                async fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable
                        .delete_group_data(&mut **connection, GroupDataType::ConfirmationTag);
                    run_task(task).await
                }

                async fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task =
                        storable.delete_group_data(&mut **connection, GroupDataType::GroupState);
                    run_task(task).await
                }

                async fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_group_data(&mut **connection, GroupDataType::Context);
                    run_task(task).await
                }

                async fn delete_interim_transcript_hash<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_group_data(
                        &mut **connection,
                        GroupDataType::InterimTranscriptHash,
                    );
                    run_task(task).await
                }

                async fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable
                        .delete_group_data(&mut **connection, GroupDataType::MessageSecrets);
                    run_task(task).await
                }

                async fn delete_all_resumption_psk_secrets<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable
                        .delete_group_data(&mut **connection, GroupDataType::ResumptionPskStore);
                    run_task(task).await
                }

                async fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task =
                        storable.delete_group_data(&mut **connection, GroupDataType::OwnLeafIndex);
                    run_task(task).await
                }

                async fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable
                        .delete_group_data(&mut **connection, GroupDataType::GroupEpochSecrets);
                    run_task(task).await
                }

                async fn clear_proposal_queue<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_all_proposals(&mut **connection);
                    run_task(task).await
                }

                async fn delete_signature_key_pair<
                    SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &SignaturePublicKey,
                ) -> Result<(), Self::Error> {
                    let storable = StorableSignaturePublicKeyRef(public_key);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete::<C>(&mut **connection);
                    run_task(task).await
                }

                async fn delete_encryption_key_pair<
                    EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
                >(
                    &self,
                    public_key: &EncryptionKey,
                ) -> Result<(), Self::Error> {
                    let storable = StorableEncryptionPublicKeyRef(public_key);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete::<C>(&mut **connection);
                    run_task(task).await
                }

                async fn delete_encryption_epoch_key_pairs<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    EpochKey: traits::EpochKey<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    epoch: &EpochKey,
                    leaf_index: u32,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_epoch_key_pair(&mut **connection, epoch, leaf_index);
                    run_task(task).await
                }

                async fn delete_key_package<
                    KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
                >(
                    &self,
                    hash_ref: &KeyPackageRef,
                ) -> Result<(), Self::Error> {
                    let storable = StorableHashRef(hash_ref);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_key_package::<C>(&mut **connection);
                    run_task(task).await
                }

                async fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
                    &self,
                    psk_id: &PskKey,
                ) -> Result<(), Self::Error> {
                    let storable = StorablePskIdRef(psk_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete::<C>(&mut **connection);
                    run_task(task).await
                }

                #[cfg(feature = "extensions-draft")]
                async fn write_application_export_tree<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                    application_export_tree: &ApplicationExportTree,
                ) -> Result<(), Self::Error> {
                    let storable = StorableGroupDataRef(application_export_tree);
                    let mut connection = self.connection.lock().await;
                    let task = storable.store::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ApplicationExportTree,
                    );
                    run_task(task).await
                }

                #[cfg(feature = "extensions-draft")]
                async fn application_export_tree<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<Option<ApplicationExportTree>, Self::Error> {
                    let mut connection = self.connection.lock().await;
                    let task = StorableGroupData::load::<_, C>(
                        &mut **connection,
                        group_id,
                        GroupDataType::ApplicationExportTree,
                    );
                    run_task(task).await
                }

                #[cfg(feature = "extensions-draft")]
                async fn delete_application_export_tree<
                    GroupId: traits::GroupId<CURRENT_VERSION>,
                    ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
                >(
                    &self,
                    group_id: &GroupId,
                ) -> Result<(), Self::Error> {
                    let storable = self.wrap_storable_group_id_ref(group_id);
                    let mut connection = self.connection.lock().await;
                    let task = storable.delete_group_data(
                        &mut **connection,
                        GroupDataType::ApplicationExportTree,
                    );
                    run_task(task).await
                }
            }

            impl<T: Key<CURRENT_VERSION>, C: Codec> Type<$db> for KeyRefWrapper<'_, T, C> {
                fn type_info() -> <$db as Database>::TypeInfo {
                    <Vec<u8> as Type<$db>>::type_info()
                }
            }

            impl<'q, T: Key<CURRENT_VERSION>, C: Codec> Encode<'q, $db> for KeyRefWrapper<'_, T, C> {
                fn encode_by_ref(
                    &self,
                    buf: &mut <$db as Database>::ArgumentBuffer<'q>,
                ) -> Result<IsNull, BoxDynError> {
                    let key_bytes = C::to_vec(self.0)?;
                    Encode::<$db>::encode(key_bytes, buf)
                }
            }

            impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<$db> for EntityRefWrapper<'_, T, C> {
                fn type_info() -> <$db as Database>::TypeInfo {
                    <Vec<u8> as Type<$db>>::type_info()
                }
            }

            impl<T: Entity<CURRENT_VERSION>, C: Codec> Encode<'_, $db> for EntityRefWrapper<'_, T, C> {
                fn encode_by_ref(
                    &self,
                    buf: &mut <$db as Database>::ArgumentBuffer<'_>,
                ) -> Result<IsNull, BoxDynError> {
                    let entity_bytes = C::to_vec(self.0)?;
                    Encode::<$db>::encode(entity_bytes, buf)
                }
            }

            impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<$db> for EntitySliceWrapper<'_, T, C> {
                fn type_info() -> <$db as Database>::TypeInfo {
                    <Vec<u8> as Type<$db>>::type_info()
                }
            }

            impl<T: Entity<CURRENT_VERSION>, C: Codec> Encode<'_, $db> for EntitySliceWrapper<'_, T, C> {
                fn encode_by_ref(
                    &self,
                    buf: &mut <$db as Database>::ArgumentBuffer<'_>,
                ) -> Result<IsNull, BoxDynError> {
                    let entity_bytes = C::to_vec(self.0)?;
                    Encode::<$db>::encode(entity_bytes, buf)
                }
            }

            impl<GroupData: Entity<CURRENT_VERSION>> StorableGroupDataRef<'_, GroupData> {
                async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                    data_type: GroupDataType,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
                    let group_data = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_GROUP_DATA)
                        .bind(group_id)
                        .bind(data_type)
                        .bind(group_data)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<SignatureKeyPairs: Entity<CURRENT_VERSION>>
                StorableSignatureKeyPairsRef<'_, SignatureKeyPairs>
            {
                async fn store<SignaturePublicKey: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    public_key: &SignaturePublicKey,
                ) -> sqlx::Result<()> {
                    let public_key = KeyRefWrapper::<_, C>(public_key, PhantomData);
                    let signature_key = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_SIGNATURE_KEY)
                        .bind(public_key)
                        .bind(signature_key)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<LeafNode: Entity<CURRENT_VERSION>> StorableLeafNodeRef<'_, LeafNode> {
                async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
                    let entity = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_OWN_LEAF_NODE)
                        .bind(group_id)
                        .bind(entity)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackageRef<'_, KeyPackage> {
                async fn store<KeyPackageRef: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    key_package_ref: &KeyPackageRef,
                ) -> sqlx::Result<()> {
                    let key_package_ref = KeyRefWrapper::<_, C>(key_package_ref, PhantomData);
                    let key_package = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_KEY_PACKAGE)
                        .bind(key_package_ref)
                        .bind(key_package)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<EpochKeyPairs: Entity<CURRENT_VERSION>> StorableEpochKeyPairsRef<'_, EpochKeyPairs> {
                async fn store<
                    GroupId: Key<CURRENT_VERSION>,
                    EpochKey: Key<CURRENT_VERSION>,
                    C: Codec,
                >(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                    epoch_id: &EpochKey,
                    leaf_index: u32,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
                    let epoch_id = KeyRefWrapper::<_, C>(epoch_id, PhantomData);
                    let entity = EntitySliceWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_EPOCH_KEY_PAIRS)
                        .bind(group_id)
                        .bind(epoch_id)
                        .bind(i64::from(leaf_index))
                        .bind(entity)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<PskBundle: Entity<CURRENT_VERSION>> StorablePskBundleRef<'_, PskBundle> {
                async fn store<PskId: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    psk_id: &PskId,
                ) -> sqlx::Result<()> {
                    let psk_id = KeyRefWrapper::<_, C>(psk_id, PhantomData);
                    let psk_bundle = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_PSK)
                        .bind(psk_id)
                        .bind(psk_bundle)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<GroupData: Entity<CURRENT_VERSION>> StorableGroupData<GroupData> {
                async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                    data_type: GroupDataType,
                ) -> sqlx::Result<Option<GroupData>> {
                    let key_ref = KeyRefWrapper::<_, C>::new(group_id);
                    let group_data = query_scalar::<$db, Vec<u8>>(sql::LOAD_GROUP_DATA)
                        .bind(key_ref)
                        .bind(data_type)
                        .fetch_optional(executor)
                        .await?
                        .map(C::from_bytes)
                        .transpose()?;
                    Ok(group_data)
                }
            }

            impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
                StorableProposalRef<'_, Proposal, ProposalRef>
            {
                async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>::new(group_id);
                    let proposal_ref = EntityRefWrapper::<_, C>::new(self.0);
                    let proposal = EntityRefWrapper::<_, C>::new(self.1);
                    query::<$db>(sql::STORE_PROPOSAL)
                        .bind(group_id)
                        .bind(proposal_ref)
                        .bind(proposal)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<LeafNode: Entity<CURRENT_VERSION>> StorableLeafNode<LeafNode> {
                async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                ) -> sqlx::Result<Vec<LeafNode>> {
                    let key_ref = KeyRefWrapper::<_, C>::new(group_id);
                    let leaf_nodes = query_scalar::<$db, Vec<u8>>(sql::LOAD_OWN_LEAF_NODES)
                        .bind(key_ref)
                        .fetch_all(executor)
                        .await?
                        .into_iter()
                        .map(C::from_bytes)
                        .collect::<Result<_, _>>()?;

                    Ok(leaf_nodes)
                }
            }

            impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
                StorableProposal<Proposal, ProposalRef>
            {
                async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                ) -> sqlx::Result<Vec<(ProposalRef, Proposal)>> {
                    let key_ref = KeyRefWrapper::<_, C>::new(group_id);
                    query::<$db>(sql::LOAD_PROPOSALS)
                        .bind(key_ref)
                        .fetch_all(executor)
                        .await?
                        .into_iter()
                        .map(|row| {
                            let proposal_ref =
                                C::from_bytes(row.try_get::<Vec<u8>, _>("proposal_ref")?)?;
                            let proposal = C::from_bytes(row.try_get::<Vec<u8>, _>("proposal")?)?;
                            Ok((proposal_ref, proposal))
                        })
                        .collect()
                }

                async fn load_refs<GroupId: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    group_id: &GroupId,
                ) -> sqlx::Result<Vec<ProposalRef>> {
                    let key_ref = KeyRefWrapper::<_, C>::new(group_id);
                    query_scalar::<$db, Vec<u8>>(sql::LOAD_PROPOSAL_REFS)
                        .bind(key_ref)
                        .fetch_all(executor)
                        .await?
                        .into_iter()
                        .map(C::from_bytes)
                        .collect()
                }
            }

            impl<SignatureKeyPairs: Entity<CURRENT_VERSION>>
                StorableSignatureKeyPairs<SignatureKeyPairs>
            {
                async fn load<
                    SignaturePublicKey: SignaturePublicKeyTrait<CURRENT_VERSION>,
                    C: Codec,
                >(
                    executor: impl Executor<'_, Database = $db>,
                    public_key: &SignaturePublicKey,
                ) -> sqlx::Result<Option<SignatureKeyPairs>> {
                    let key_ref = KeyRefWrapper::<_, C>::new(public_key);
                    query_scalar::<$db, Vec<u8>>(sql::LOAD_SIGNATURE_KEY)
                        .bind(key_ref)
                        .fetch_optional(executor)
                        .await?
                        .map(C::from_bytes)
                        .transpose()
                }
            }

            impl<EncryptionKeyPair: Entity<CURRENT_VERSION>>
                StorableEncryptionKeyPair<EncryptionKeyPair>
            {
                async fn load<EncryptionKey: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    public_key: &EncryptionKey,
                ) -> sqlx::Result<Option<EncryptionKeyPair>> {
                    let public_key = KeyRefWrapper::<_, C>::new(public_key);
                    query_scalar::<$db, Vec<u8>>(sql::LOAD_ENCRYPTION_KEY)
                        .bind(public_key)
                        .fetch_optional(executor)
                        .await?
                        .map(C::from_bytes)
                        .transpose()
                }
            }

            impl<EncryptionKeyPair: Entity<CURRENT_VERSION>>
                StorableEncryptionKeyPairRef<'_, EncryptionKeyPair>
            {
                async fn store<EncryptionKey: Key<CURRENT_VERSION>, C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    public_key: &EncryptionKey,
                ) -> sqlx::Result<()> {
                    let public_key = KeyRefWrapper::<_, C>(public_key, PhantomData);
                    let key_pair = EntityRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::STORE_ENCRYPTION_KEY)
                        .bind(public_key)
                        .bind(key_pair)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            async fn load_epoch_key_pairs<
                EpochKeyPairs: Entity<CURRENT_VERSION>,
                GroupId: Key<CURRENT_VERSION>,
                EpochKey: Key<CURRENT_VERSION>,
                C: Codec,
            >(
                executor: impl Executor<'_, Database = $db>,
                group_id: &GroupId,
                epoch_id: &EpochKey,
                leaf_index: u32,
            ) -> sqlx::Result<Vec<EpochKeyPairs>> {
                let group_id = KeyRefWrapper::<_, C>::new(group_id);
                let epoch_id = KeyRefWrapper::<_, C>::new(epoch_id);
                query_scalar::<$db, Vec<u8>>(sql::LOAD_EPOCH_KEY_PAIRS)
                    .bind(group_id)
                    .bind(epoch_id)
                    .bind(i64::from(leaf_index))
                    .fetch_optional(executor)
                    .await?
                    .map(C::from_bytes)
                    .transpose()
                    .map(|opt| opt.unwrap_or_default())
            }

            impl<KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackage<KeyPackage> {
                async fn load<KeyPackageRef: Key<CURRENT_VERSION>, C: Codec>(
                    executor: impl Executor<'_, Database = $db>,
                    key_package_ref: &KeyPackageRef,
                ) -> sqlx::Result<Option<KeyPackage>> {
                    let key_package_ref = KeyRefWrapper::<_, C>::new(key_package_ref);
                    query_scalar::<$db, Vec<u8>>(sql::LOAD_KEY_PACKAGE)
                        .bind(key_package_ref)
                        .fetch_optional(executor)
                        .await?
                        .map(C::from_bytes)
                        .transpose()
                }
            }

            async fn load_psk_bundle<
                PskBundle: Entity<CURRENT_VERSION>,
                PskId: Key<CURRENT_VERSION>,
                C: Codec,
            >(
                executor: impl Executor<'_, Database = $db>,
                psk_id: &PskId,
            ) -> sqlx::Result<Option<PskBundle>> {
                let psk_id = KeyRefWrapper::<_, C>::new(psk_id);
                query_scalar::<$db, Vec<u8>>(sql::LOAD_PSK)
                    .bind(psk_id)
                    .fetch_optional(executor)
                    .await?
                    .map(C::from_bytes)
                    .transpose()
            }

            impl<GroupId: Key<CURRENT_VERSION>, C: Codec> StorableGroupIdRef<'_, GroupId, C> {
                async fn delete_all_proposals(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_ALL_PROPOSALS)
                        .bind(group_id)
                        .execute(executor)
                        .await?;
                    Ok(())
                }

                async fn delete_proposal<ProposalRef: ProposalRefTrait<CURRENT_VERSION>>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    proposal_ref: &ProposalRef,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    let proposal_ref = KeyRefWrapper::<_, C>(proposal_ref, PhantomData);
                    query::<$db>(sql::DELETE_PROPOSAL)
                        .bind(group_id)
                        .bind(proposal_ref)
                        .execute(executor)
                        .await?;
                    Ok(())
                }

                async fn delete_leaf_nodes(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_OWN_LEAF_NODES)
                        .bind(group_id)
                        .execute(executor)
                        .await?;
                    Ok(())
                }

                async fn delete_group_data(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    data_type: GroupDataType,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_GROUP_DATA)
                        .bind(group_id)
                        .bind(data_type)
                        .execute(executor)
                        .await?;
                    Ok(())
                }

                async fn delete_epoch_key_pair<EpochKey: Key<CURRENT_VERSION>>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                    epoch_key: &EpochKey,
                    leaf_index: u32,
                ) -> sqlx::Result<()> {
                    let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    let epoch_key = KeyRefWrapper::<_, C>(epoch_key, PhantomData);
                    query::<$db>(sql::DELETE_EPOCH_KEY_PAIRS)
                        .bind(group_id)
                        .bind(epoch_key)
                        .bind(i64::from(leaf_index))
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<SignaturePublicKey: Key<CURRENT_VERSION>>
                StorableSignaturePublicKeyRef<'_, SignaturePublicKey>
            {
                async fn delete<C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let public_key = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_SIGNATURE_KEY)
                        .bind(public_key)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<EncryptionPublicKey: Key<CURRENT_VERSION>>
                StorableEncryptionPublicKeyRef<'_, EncryptionPublicKey>
            {
                async fn delete<C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let public_key = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_ENCRYPTION_KEY)
                        .bind(public_key)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<KeyPackageRef: Key<CURRENT_VERSION>> StorableHashRef<'_, KeyPackageRef> {
                async fn delete_key_package<C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let hash_ref = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_KEY_PACKAGE)
                        .bind(hash_ref)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }

            impl<PskId: Key<CURRENT_VERSION>> StorablePskIdRef<'_, PskId> {
                async fn delete<C: Codec>(
                    &self,
                    executor: impl Executor<'_, Database = $db>,
                ) -> sqlx::Result<()> {
                    let psks_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
                    query::<$db>(sql::DELETE_PSK)
                        .bind(psks_id)
                        .execute(executor)
                        .await?;
                    Ok(())
                }
            }
        }
    };
}
