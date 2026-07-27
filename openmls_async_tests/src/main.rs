use openmls::prelude::tls_codec::Deserialize;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    prelude::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_sqlx_storage::{Codec, SqliteStorageProvider};
use serde::Serialize;
use sqlx::{Connection, SqliteConnection};

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

struct SqlxTestProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<'static, JsonCodec>,
}

impl OpenMlsProvider for SqlxTestProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageError = sqlx::Error;
    // The connection-backed provider is exclusive: the handle is `&mut`.
    type StorageProvider<'b>
        = &'b mut SqliteStorageProvider<'static, JsonCodec>
    where
        Self: 'b;

    fn storage(&mut self) -> Self::StorageProvider<'_> {
        &mut self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

async fn new_credential<P: OpenMlsProvider>(
    provider: &mut P,
    identity: &[u8],
    signature_scheme: SignatureScheme,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity.to_vec());
    let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
    signature_keys
        .store(provider.storage())
        .await
        .expect("store signature key");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

async fn async_group_flow_works(
    alice_provider: &mut SqlxTestProvider,
    bob_provider: &mut SqlxTestProvider,
) {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"async-group");

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm()).await;
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm()).await;

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .await
        .expect("key package build failed")
        .key_package()
        .to_owned();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential.clone(),
    )
    .await
    .expect("group creation failed");

    let (_, welcome, _) = alice_group
        .add_members_without_update(alice_provider, &alice_signer, &[bob_key_package])
        .await
        .expect("add members failed");

    alice_group
        .merge_pending_commit(alice_provider)
        .await
        .expect("merge pending commit failed");

    let welcome_bytes = welcome.to_bytes().expect("welcome serialization failed");
    let welcome_in =
        MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice()).expect("welcome deserialize");
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected welcome"),
    };

    let staged = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("staged welcome failed");

    let mut bob_group = staged
        .into_group(bob_provider)
        .await
        .expect("group from welcome failed");

    let message = b"hello from alice";
    let queued_message = alice_group
        .create_message(alice_provider, &alice_signer, message)
        .await
        .expect("create message failed");

    let queued_message_bytes = queued_message
        .to_bytes()
        .expect("queued message serialization failed");
    let queued_message_in = MlsMessageIn::tls_deserialize(&mut queued_message_bytes.as_slice())
        .expect("queued message deserialize");
    let protocol_message = queued_message_in
        .try_into_protocol_message()
        .expect("protocol message expected");

    let processed_message = bob_group
        .process_message(bob_provider, protocol_message)
        .await
        .expect("process message failed");

    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            assert_eq!(application_message.into_bytes(), message);
        }
        _ => panic!("unexpected message type"),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let alice_connection: &'static mut SqliteConnection = Box::leak(Box::new(
        SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("connect alice storage"),
    ));
    let mut alice_storage = SqliteStorageProvider::<JsonCodec>::new(alice_connection);
    alice_storage
        .run_migrations()
        .await
        .expect("migrate alice storage");

    let bob_connection: &'static mut SqliteConnection = Box::leak(Box::new(
        SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("connect bob storage"),
    ));
    let mut bob_storage = SqliteStorageProvider::<JsonCodec>::new(bob_connection);
    bob_storage
        .run_migrations()
        .await
        .expect("migrate bob storage");

    let mut alice_provider = SqlxTestProvider {
        crypto: RustCrypto::default(),
        storage: alice_storage,
    };
    let mut bob_provider = SqlxTestProvider {
        crypto: RustCrypto::default(),
        storage: bob_storage,
    };

    async_group_flow_works(&mut alice_provider, &mut bob_provider).await;
}

/// A single storage call off the `&mut`-backed sqlx provider must produce a
/// `Send` future -- there is no cell anywhere in the provider now.
#[allow(dead_code)]
fn assert_storage_call_future_is_send(p: &mut SqlxTestProvider, id: &GroupId) {
    fn assert_send<T: Send>(_: &T) {}
    let fut = MlsGroup::load(p, id);
    assert_send(&fut);
}

// Herald spawns one task per account stream, so a full storage-backed MLS flow
// must produce a Send future. This is a compile-time guard against the
// provider reintroducing a !Send cell around its connection.
#[allow(dead_code)]
fn assert_group_flow_future_is_send(
    a: &mut SqlxTestProvider,
    b: &mut SqlxTestProvider,
) {
    fn assert_send<T: Send>(_: &T) {}
    let fut = async_group_flow_works(a, b);
    assert_send(&fut);
}

// Control: the same Send assertion against a provider that is *not* itself
// lifetime-parametric.
#[allow(dead_code)]
fn assert_memory_storage_future_is_send(p: &mut OpenMlsRustCrypto, id: &GroupId) {
    fn assert_send<T: Send>(_: &T) {}
    let fut = MlsGroup::load(p, id);
    assert_send(&fut);
}
