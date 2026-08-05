//! The newtypes the storage provider hangs its SQL on.
//!
//! Every one of these carries at least one inherent method that takes an
//! executor, and those methods differ per dialect. Inherent impls are
//! crate-global, so a single shared set of types could only ever have one
//! backend's methods on it. Instead the definitions live in a macro and each
//! backend module stamps out its own private copy; the types are internal, so
//! nothing about that is observable from outside the crate.

macro_rules! storable_wrappers {
    () => {
        #[derive(Debug, serde::Serialize)]
        pub(super) struct KeyRefWrapper<'a, T: Key<CURRENT_VERSION>, C: Codec>(
            pub &'a T,
            pub PhantomData<C>,
        );

        impl<'a, T: Key<CURRENT_VERSION>, C: Codec> KeyRefWrapper<'a, T, C> {
            fn new(value: &'a T) -> Self {
                Self(value, PhantomData)
            }
        }

        pub(super) struct EntityRefWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(
            pub &'a T,
            pub PhantomData<C>,
        );

        impl<'a, T: Entity<CURRENT_VERSION>, C: Codec> EntityRefWrapper<'a, T, C> {
            fn new(value: &'a T) -> Self {
                Self(value, PhantomData)
            }
        }

        pub(super) struct EntitySliceWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(
            pub &'a [T],
            pub PhantomData<C>,
        );

        pub(super) struct StorableGroupIdRef<'a, GroupId: Key<CURRENT_VERSION>, C: Codec>(
            pub &'a GroupId,
            pub PhantomData<C>,
        );

        pub(super) struct StorableGroupData<GroupData: Entity<CURRENT_VERSION>>(pub GroupData);

        pub(super) struct StorableGroupDataRef<'a, GroupData: Entity<CURRENT_VERSION>>(
            pub &'a GroupData,
        );

        pub(super) struct StorableEncryptionKeyPair<EncryptionKeyPair: Entity<CURRENT_VERSION>>(
            pub EncryptionKeyPair,
        );

        pub(super) struct StorableEncryptionKeyPairRef<
            'a,
            EncryptionKeyPair: Entity<CURRENT_VERSION>,
        >(pub &'a EncryptionKeyPair);

        pub(super) struct StorableEncryptionPublicKeyRef<
            'a,
            EncryptionPublicKey: Key<CURRENT_VERSION>,
        >(pub &'a EncryptionPublicKey);

        pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<CURRENT_VERSION>>(
            pub &'a [EpochKeyPairs],
        );

        pub(super) struct StorableKeyPackage<KeyPackage: Entity<CURRENT_VERSION>>(pub KeyPackage);

        pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<CURRENT_VERSION>>(
            pub &'a KeyPackage,
        );

        pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<CURRENT_VERSION>>(
            pub &'a KeyPackageRef,
        );

        pub(super) struct StorableLeafNode<LeafNode: Entity<CURRENT_VERSION>>(pub LeafNode);

        pub(super) struct StorableLeafNodeRef<'a, LeafNode: Entity<CURRENT_VERSION>>(
            pub &'a LeafNode,
        );

        pub(super) struct StorableProposal<
            Proposal: Entity<CURRENT_VERSION>,
            ProposalRef: Entity<CURRENT_VERSION>,
        >(pub ProposalRef, pub Proposal);

        pub(super) struct StorableProposalRef<
            'a,
            Proposal: Entity<CURRENT_VERSION>,
            ProposalRef: Entity<CURRENT_VERSION>,
        >(pub &'a ProposalRef, pub &'a Proposal);

        pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<CURRENT_VERSION>>(
            pub &'a PskBundle,
        );

        pub(super) struct StorablePskIdRef<'a, PskId: Key<CURRENT_VERSION>>(pub &'a PskId);

        pub(super) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<CURRENT_VERSION>>(
            pub SignatureKeyPairs,
        );

        pub(super) struct StorableSignatureKeyPairsRef<
            'a,
            SignatureKeyPairs: Entity<CURRENT_VERSION>,
        >(pub &'a SignatureKeyPairs);

        pub(super) struct StorableSignaturePublicKeyRef<
            'a,
            SignaturePublicKey: Key<CURRENT_VERSION>,
        >(pub &'a SignaturePublicKey);
    };
}
