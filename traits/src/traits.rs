//! # OpenMLS Traits
//!
//! This module defines a number of traits that are used by the public
//! API of OpenMLS.

pub mod crypto;
pub mod grease;
pub mod public_storage;
pub mod random;
pub mod signatures;
pub mod storage;
pub mod types;

/// A prelude to include to get all traits in scope and expose `openmls_types`.
pub mod prelude {
    pub use super::crypto::OpenMlsCrypto as _;
    pub use super::random::OpenMlsRand as _;
    pub use super::signatures::Signer as _;
    pub use super::storage::StorageProvider as _;
    pub use super::types as openmls_types;
    pub use super::OpenMlsProvider as _;
}

/// The OpenMLS Crypto Provider Trait
///
/// An implementation of this trait must be passed in to the public OpenMLS API
/// to perform randomness generation, cryptographic operations, and key storage.
// ANCHOR: openmls_provider
pub trait OpenMlsProvider {
    type CryptoProvider: crypto::OpenMlsCrypto;
    type RandProvider: random::OpenMlsRand;

    /// The error type produced by this provider's storage. Hoisted out of the
    /// storage GAT so callers can name it without picking a lifetime.
    type StorageError: core::fmt::Debug + std::error::Error;

    /// The storage handle handed out by [`Self::storage`].
    ///
    /// Expected to be a reference type -- `&P` for providers that only need
    /// shared access, `&mut P` for providers that own an exclusive resource
    /// such as a bare database connection.
    type StorageProvider<'a>: storage::StorageProvider<
        { storage::CURRENT_VERSION },
        Error = Self::StorageError,
    >
    where
        Self: 'a;

    // Get the storage provider.
    fn storage(&mut self) -> Self::StorageProvider<'_>;

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider;

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider;
}
// ANCHOR_END: openmls_provider
