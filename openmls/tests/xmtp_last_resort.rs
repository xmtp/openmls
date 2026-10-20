//! XMTP backport of the validation check of upstream be2368a21 (#2133) on
//! v0.9.1. With `extensions-draft`, the `last_resort_key_package` component
//! (0x0004) in a key package's `app_data_dictionary` must have empty data.
//! Later OpenMLS releases reject a key package that breaks this rule, so this
//! branch must reject it too, or the two disagree on a commit that adds it.
//!
//! The encoding change of #2133 (`mark_as_last_resort` writing the component)
//! is not backported, but a key package in that encoding must be accepted.
#![cfg(feature = "extensions-draft")]

use openmls::component::ComponentType;
use openmls::credentials::test_utils::new_credential;
use openmls::extensions::AppDataDictionary;
use openmls::group::ProposalStore;
use openmls::prelude::{tls_codec::*, *};
use openmls_test::openmls_test;

/// A key package for Dave. The capabilities hold the leaf's ciphersuite and
/// credential type plus `extension_types`. With `[AppDataDictionary]`, these
/// are the capabilities upstream's builder sets for a last-resort key package
/// when the caller sets none.
fn key_package_with<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    extension_types: &[ExtensionType],
    key_package_extensions: Extensions<KeyPackage>,
    leaf_node_extensions: Option<Extensions<LeafNode>>,
) -> KeyPackageBundle {
    let (credential, signer) = new_credential(provider, b"Dave", ciphersuite.signature_algorithm());
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[ciphersuite]),
        Some(extension_types),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let mut builder = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .key_package_extensions(key_package_extensions);
    if let Some(leaf_node_extensions) = leaf_node_extensions {
        builder = builder.leaf_node_extensions(leaf_node_extensions);
    }
    builder
        .build(ciphersuite, provider, &signer, credential)
        .unwrap()
}

/// An `app_data_dictionary` extension with the given components.
fn dictionary(entries: &[(u16, Vec<u8>)]) -> AppDataDictionaryExtension {
    let mut dictionary = AppDataDictionary::new();
    for (component_id, data) in entries {
        dictionary.insert(*component_id, data.clone());
    }
    AppDataDictionaryExtension::new(dictionary)
}

/// A key package whose `app_data_dictionary` holds only the last-resort
/// component, with `data`. With empty data, this is upstream's new
/// last-resort encoding.
fn last_resort_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    data: Vec<u8>,
) -> KeyPackageBundle {
    key_package_with(
        ciphersuite,
        provider,
        &[ExtensionType::AppDataDictionary],
        Extensions::single(Extension::AppDataDictionary(dictionary(&[(
            ComponentType::LastResortKeyPackage.into(),
            data,
        )])))
        .unwrap(),
        None,
    )
}

fn validate<Provider: OpenMlsProvider>(
    provider: &Provider,
    key_package: &KeyPackage,
) -> Result<KeyPackage, KeyPackageVerifyError> {
    KeyPackageIn::from(key_package.clone()).validate(provider.crypto(), ProtocolVersion::Mls10)
}

fn config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build()
}

/// A configuration whose messages a `PublicGroup` can read.
fn public_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// Alice creates a group and adds Charlie, who joins from the Welcome.
fn alice_and_charlie<Provider: OpenMlsProvider>(
    config: &MlsGroupCreateConfig,
    ciphersuite: Ciphersuite,
    alice_provider: &Provider,
    charlie_provider: &Provider,
) -> (
    MlsGroup,
    openmls_basic_credential::SignatureKeyPair,
    MlsGroup,
) {
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        MlsGroup::new(alice_provider, &alice_signer, config, alice_credential).unwrap();
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
    let charlie_group = join(charlie_provider, config, welcome);
    (alice_group, alice_signer, charlie_group)
}

fn join<Provider: OpenMlsProvider>(
    provider: &Provider,
    config: &MlsGroupCreateConfig,
    welcome: MlsMessageOut,
) -> MlsGroup {
    let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::from(welcome).extract() else {
        panic!("expected a Welcome");
    };
    StagedWelcome::new_from_welcome(provider, config.join_config(), welcome, None)
        .unwrap()
        .into_group(provider)
        .unwrap()
}

/// Decodes `message` from bytes, as a receiver gets it over the wire.
fn receive(message: &MlsMessageOut) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

/// Processes and merges a received commit.
fn process_commit<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    commit: &MlsMessageOut,
) {
    let processed = group
        .process_message(provider, receive(commit))
        .expect("the receiver must accept the commit");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    group.merge_staged_commit(provider, *staged).unwrap();
}

fn malformed<E>() -> ProcessMessageError<E> {
    ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
        KeyPackageVerifyError::MalformedLastResortComponent,
    ))
}

#[openmls_test]
fn key_package_validation_rejects_last_resort_component_with_data() {
    let provider = &Provider::default();
    let key_package = last_resort_key_package(ciphersuite, provider, vec![1]);
    assert_eq!(
        validate(provider, key_package.key_package()).unwrap_err(),
        KeyPackageVerifyError::MalformedLastResortComponent
    );
}

/// The check uses the wire value 0x0004, the value upstream checks.
#[openmls_test]
fn key_package_validation_checks_component_id_4() {
    let provider = &Provider::default();
    let key_package = key_package_with(
        ciphersuite,
        provider,
        &[ExtensionType::AppDataDictionary],
        Extensions::single(Extension::AppDataDictionary(dictionary(&[(
            0x0004,
            vec![1],
        )])))
        .unwrap(),
        None,
    );
    assert_eq!(
        validate(provider, key_package.key_package()).unwrap_err(),
        KeyPackageVerifyError::MalformedLastResortComponent
    );
}

/// Component 4 with data in the leaf node's own dictionary is not a
/// key-package marker. Upstream does not check it, so neither may this branch.
#[openmls_test]
fn key_package_validation_ignores_component_4_in_the_leaf_node() {
    let provider = &Provider::default();
    let key_package = key_package_with(
        ciphersuite,
        provider,
        &[ExtensionType::AppDataDictionary],
        Extensions::empty(),
        Some(
            Extensions::single(Extension::AppDataDictionary(dictionary(&[(
                ComponentType::LastResortKeyPackage.into(),
                vec![1],
            )])))
            .unwrap(),
        ),
    );
    validate(provider, key_package.key_package())
        .expect("a leaf-node dictionary entry must not trigger the check");
}

/// A committer that adds the key package without decoding it, as
/// `add_members` does with a `KeyPackage`, builds the commit, as upstream does.
/// A receiver decodes the Add and must reject it.
#[openmls_test]
fn receiver_rejects_add_of_last_resort_component_with_data() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );

    let dave_provider = &Provider::default();
    let dave_key_package = last_resort_key_package(ciphersuite, dave_provider, vec![1]);
    let (commit, _, _) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[dave_key_package.key_package().clone()],
        )
        .unwrap();

    let error = charlie_group
        .process_message(charlie_provider, receive(&commit))
        .unwrap_err();
    assert_eq!(error, malformed());
}

/// A standalone Add proposal with the malformed component is rejected when it
/// arrives, by a member and by a `PublicGroup` observer.
#[openmls_test]
fn receivers_reject_standalone_add_proposal_of_last_resort_component_with_data() {
    let config = public_config(ciphersuite);
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) =
        alice_and_charlie(&config, ciphersuite, alice_provider, charlie_provider);

    let observer_provider = &Provider::default();
    let group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let (observer, _) = PublicGroup::from_external(
        observer_provider.crypto(),
        observer_provider.storage(),
        alice_group.export_ratchet_tree().into(),
        group_info,
        ProposalStore::new(),
    )
    .unwrap();

    let dave_provider = &Provider::default();
    let dave_key_package = last_resort_key_package(ciphersuite, dave_provider, vec![1]);
    let (proposal, _) = alice_group
        .propose_add_member(
            alice_provider,
            &alice_signer,
            dave_key_package.key_package(),
        )
        .unwrap();

    let error = charlie_group
        .process_message(charlie_provider, receive(&proposal))
        .unwrap_err();
    assert_eq!(error, malformed());

    let error = observer
        .process_message(observer_provider.crypto(), receive(&proposal))
        .unwrap_err();
    assert_eq!(
        error,
        PublicProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::MalformedLastResortComponent
        ))
    );
}

/// Forward compatibility: a key package in upstream's new last-resort
/// encoding (the component with empty data) passes validation, can be added
/// by a commit, and the receiver and the new member accept the commit.
#[openmls_test]
fn member_accepts_add_of_key_package_in_upstream_last_resort_encoding() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );

    let dave_provider = &Provider::default();
    let dave_key_package = last_resort_key_package(ciphersuite, dave_provider, vec![]);
    let validated = validate(dave_provider, dave_key_package.key_package())
        .expect("a key package in the upstream last-resort encoding must pass");

    let (commit, welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[validated])
        .expect("the committer must accept the upstream last-resort encoding");
    alice_group.merge_pending_commit(alice_provider).unwrap();

    process_commit(&mut charlie_group, charlie_provider, &commit);
    assert_eq!(charlie_group.epoch(), alice_group.epoch());
    assert_eq!(charlie_group.members().count(), 3);

    let dave_group = join(dave_provider, &config(ciphersuite), welcome);
    assert_eq!(dave_group.epoch(), alice_group.epoch());
}

/// The same encoding in a standalone Add proposal: the receiver stores it, and
/// the commit that references it is accepted.
#[openmls_test]
fn member_accepts_add_by_reference_of_key_package_in_upstream_last_resort_encoding() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );

    let dave_provider = &Provider::default();
    let dave_key_package = last_resort_key_package(ciphersuite, dave_provider, vec![]);
    let (proposal, _) = alice_group
        .propose_add_member(
            alice_provider,
            &alice_signer,
            dave_key_package.key_package(),
        )
        .unwrap();
    let processed = charlie_group
        .process_message(charlie_provider, receive(&proposal))
        .expect("the receiver must accept the proposal");
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        panic!("expected a proposal");
    };
    charlie_group
        .store_pending_proposal(charlie_provider.storage(), *queued)
        .unwrap();

    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    process_commit(&mut charlie_group, charlie_provider, &commit);
    assert_eq!(charlie_group.epoch(), alice_group.epoch());
    assert_eq!(charlie_group.members().count(), 3);
}

/// Upstream's transition shape: a caller-set legacy `last_resort` extension
/// next to a dictionary that holds another component with data and the
/// last-resort component with empty data. Only component 4 is checked.
#[openmls_test]
fn member_accepts_add_of_key_package_in_upstream_transition_shape() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );

    let dave_provider = &Provider::default();
    let mut extensions =
        Extensions::single(Extension::LastResort(LastResortExtension::default())).unwrap();
    extensions
        .add(Extension::AppDataDictionary(dictionary(&[
            (0x8001, vec![1, 2, 3]),
            (ComponentType::LastResortKeyPackage.into(), vec![]),
        ])))
        .unwrap();
    let dave_key_package = key_package_with(
        ciphersuite,
        dave_provider,
        &[ExtensionType::AppDataDictionary, ExtensionType::LastResort],
        extensions,
        None,
    );
    let validated = validate(dave_provider, dave_key_package.key_package())
        .expect("the transition shape must pass");

    let (commit, _, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[validated])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    process_commit(&mut charlie_group, charlie_provider, &commit);
    assert_eq!(charlie_group.epoch(), alice_group.epoch());
}
