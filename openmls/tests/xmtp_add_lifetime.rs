//! XMTP patch on v0.9.1: the lifetime of a key package in an Add proposal is
//! not checked against the system clock when a commit is built or processed.
//! A member that processes the commit after the key package expired must reach
//! the same epoch as the committer. The committer skips the check too, on
//! purpose: a queued Add, or one built from a key package fetched earlier, must
//! not make the commit impossible to build once the key package expires.
//! `KeyPackageIn::validate`, used when a key package is fetched, still checks
//! the lifetime.
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openmls::credentials::test_utils::new_credential;
use openmls::prelude::{tls_codec::*, *};
use openmls::treesync::errors::LifetimeError;
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

/// How long a short-lived key package stays valid, in seconds. The setup
/// before the sleep must finish within this time.
const VALIDITY: u64 = 3;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key_package_with_lifetime<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    lifetime: Lifetime,
) -> KeyPackage {
    let (credential, signer) = new_credential(provider, b"Dave", ciphersuite.signature_algorithm());
    KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .build(ciphersuite, provider, &signer, credential)
        .unwrap()
        .key_package()
        .clone()
}

/// A key package that expired 2 seconds after the Unix epoch.
fn expired_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) -> KeyPackage {
    key_package_with_lifetime(ciphersuite, provider, Lifetime::init(1, 2))
}

/// A key package that expires `VALIDITY` seconds from now.
fn short_lived_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) -> KeyPackage {
    let now = now();
    key_package_with_lifetime(
        ciphersuite,
        provider,
        Lifetime::init(now - 60, now + VALIDITY),
    )
}

/// Waits until a key package from [`short_lived_key_package`] has expired.
fn wait_for_expiry() {
    thread::sleep(Duration::from_secs(VALIDITY));
}

fn config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Alice creates a group and adds Charlie, who joins from the Welcome.
fn alice_and_charlie<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_provider: &Provider,
    charlie_provider: &Provider,
) -> (MlsGroup, SignatureKeyPair, MlsGroup, SignatureKeyPair) {
    let config = config(ciphersuite);
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        MlsGroup::new(alice_provider, &alice_signer, &config, alice_credential).unwrap();

    let (charlie_credential, charlie_signer) = new_credential(
        charlie_provider,
        b"Charlie",
        ciphersuite.signature_algorithm(),
    );
    let charlie_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            charlie_provider,
            &charlie_signer,
            charlie_credential,
        )
        .unwrap()
        .key_package()
        .clone();
    let (_, welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[charlie_key_package])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    let welcome = match MlsMessageIn::from(welcome).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome"),
    };
    let charlie_group =
        StagedWelcome::new_from_welcome(charlie_provider, config.join_config(), welcome, None)
            .unwrap()
            .into_group(charlie_provider)
            .unwrap();
    (alice_group, alice_signer, charlie_group, charlie_signer)
}

/// Decodes `message` from bytes, as a receiver gets it over the wire.
fn receive(message: MlsMessageOut) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

/// Processes and merges a received commit.
fn process_commit<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    commit: MlsMessageOut,
) {
    let processed = group
        .process_message(provider, receive(commit))
        .expect("a receiver must not check the lifetime of an Add");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group.merge_staged_commit(provider, *staged).unwrap();
        }
        other => panic!("expected a staged commit, got {other:?}"),
    }
}

#[openmls_test]
fn member_accepts_commit_that_adds_an_expired_key_package() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group, _) =
        alice_and_charlie(ciphersuite, alice_provider, charlie_provider);

    // Alice adds Dave, whose key package is expired by the clock of every
    // member. The committer skips the lifetime check on purpose, so a commit
    // with an Add that was valid when it was queued or fetched can still be
    // built. Receivers skip it too, so the group cannot split over it.
    let dave_provider = &Provider::default();
    let dave_key_package = expired_key_package(ciphersuite, dave_provider);
    let (commit, _welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[dave_key_package])
        .expect("the committer must not check the lifetime of an Add");
    alice_group.merge_pending_commit(alice_provider).unwrap();

    process_commit(&mut charlie_group, charlie_provider, commit);
    assert_eq!(alice_group.epoch(), charlie_group.epoch());
    assert_eq!(alice_group.members().count(), 3);
    assert_eq!(charlie_group.members().count(), 3);
}

/// The case the patch is for: the commit is built while the key package is
/// valid, and a member processes it after the key package expired.
#[openmls_test]
fn member_accepts_add_by_value_after_the_key_package_expired() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group, _) =
        alice_and_charlie(ciphersuite, alice_provider, charlie_provider);

    let dave_provider = &Provider::default();
    let dave_key_package = short_lived_key_package(ciphersuite, dave_provider);
    let (commit, _welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[dave_key_package])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    wait_for_expiry();

    process_commit(&mut charlie_group, charlie_provider, commit);
    assert_eq!(alice_group.epoch(), charlie_group.epoch());
    assert_eq!(charlie_group.members().count(), 3);
}

/// An Add is proposed while the key package is valid, and committed by
/// reference after it expired. The committer and the receiver both skip the
/// lifetime check.
#[openmls_test]
fn member_accepts_add_by_reference_after_the_key_package_expired() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group, charlie_signer) =
        alice_and_charlie(ciphersuite, alice_provider, charlie_provider);

    let dave_provider = &Provider::default();
    let dave_key_package = short_lived_key_package(ciphersuite, dave_provider);
    let (proposal, _) = alice_group
        .propose_add_member(alice_provider, &alice_signer, &dave_key_package)
        .unwrap();
    let processed = charlie_group
        .process_message(charlie_provider, receive(proposal))
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            charlie_group
                .store_pending_proposal(charlie_provider.storage(), *proposal)
                .unwrap();
        }
        other => panic!("expected a proposal, got {other:?}"),
    }

    wait_for_expiry();

    let (commit, _welcome, _) = charlie_group
        .commit_to_pending_proposals(charlie_provider, &charlie_signer)
        .expect("the committer must not check the lifetime of a queued Add");
    charlie_group
        .merge_pending_commit(charlie_provider)
        .unwrap();

    process_commit(&mut alice_group, alice_provider, commit);
    assert_eq!(alice_group.epoch(), charlie_group.epoch());
    assert_eq!(alice_group.members().count(), 3);
}

/// `KeyPackageIn::validate`, used when a key package is fetched, still
/// rejects a key package outside its lifetime.
#[openmls_test]
fn key_package_validation_still_checks_the_lifetime() {
    let provider = &Provider::default();
    let validate = |key_package: KeyPackage| {
        KeyPackageIn::from(key_package).validate(provider.crypto(), ProtocolVersion::Mls10)
    };

    let expired = expired_key_package(ciphersuite, provider);
    assert!(matches!(
        validate(expired),
        Err(KeyPackageVerifyError::LifetimeError(
            LifetimeError::Expired { .. }
        ))
    ));

    let now = now();
    let not_valid_yet =
        key_package_with_lifetime(ciphersuite, provider, Lifetime::init(now + 600, now + 1200));
    assert!(matches!(
        validate(not_valid_yet),
        Err(KeyPackageVerifyError::LifetimeError(
            LifetimeError::NotValidYet { .. }
        ))
    ));

    let valid = short_lived_key_package(ciphersuite, provider);
    assert!(validate(valid).is_ok());
}
