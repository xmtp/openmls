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

/// Conditional `Send`/`Sync` for the async `StorageProvider` bounds. Off-wasm
/// these are real `Send`/`Sync` (herald's native spawned workers move storage
/// futures across threads); on wasm they are a no-op bound, because storage
/// handles there (e.g. `sqlite-wasm`) are `!Send + !Sync` and the executor is
/// single-threaded. This lets a wasm SQLite-backed provider implement the trait.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

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
    type StorageProvider: storage::StorageProvider<{ storage::CURRENT_VERSION }>;

    // Get the storage provider.
    fn storage(&self) -> &Self::StorageProvider;

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider;

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider;
}
// ANCHOR_END: openmls_provider
