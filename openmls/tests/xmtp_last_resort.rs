//! XMTP backport of upstream be2368a21 (#2133) on v0.9.1. With
//! `extensions-draft`, the `last_resort_key_package` component (0x0004) in a
//! key package's `app_data_dictionary` must have empty data. Later OpenMLS
//! releases reject a key package that breaks this rule, so this branch must
//! reject it too, or the two disagree on a commit that adds it.
//!
//! `mark_as_last_resort` writes the component, and `KeyPackage::last_resort`
//! recognizes it, so a Welcome does not consume such a key package.
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

/// Dave joins two groups from Welcomes to the same `key_package`. In the
/// first, Alice adds him and Charlie processes the commit from bytes. In the
/// second, Eve adds him. A Welcome that consumes the key package makes the
/// second join fail with `NoMatchingKeyPackage`.
fn join_two_groups<Provider: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
    dave_provider: &Provider,
    key_package: KeyPackage,
) {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );
    let (commit, welcome, _) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            std::slice::from_ref(&key_package),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    process_commit(&mut charlie_group, charlie_provider, &commit);
    assert_eq!(charlie_group.members().count(), 3);
    let dave_in_alice_group = join(dave_provider, &config(ciphersuite), welcome);
    assert_eq!(dave_in_alice_group.epoch(), alice_group.epoch());

    let eve_provider = &Provider::default();
    let (eve_credential, eve_signer) =
        new_credential(eve_provider, b"Eve", ciphersuite.signature_algorithm());
    let mut eve_group = MlsGroup::new(
        eve_provider,
        &eve_signer,
        &config(ciphersuite),
        eve_credential,
    )
    .unwrap();
    let (_, welcome, _) = eve_group
        .add_members(eve_provider, &eve_signer, &[key_package])
        .unwrap();
    eve_group.merge_pending_commit(eve_provider).unwrap();
    let dave_in_eve_group = join(dave_provider, &config(ciphersuite), welcome);
    assert_eq!(dave_in_eve_group.epoch(), eve_group.epoch());
}

/// Asserts that `key_package`'s `app_data_dictionary` holds the last-resort
/// component with empty data.
fn assert_last_resort_component(key_package: &KeyPackage) {
    assert_eq!(
        key_package
            .extensions()
            .app_data_dictionary()
            .expect("the marker must be in the app_data_dictionary")
            .dictionary()
            .get(&ComponentType::LastResortKeyPackage.into()),
        Some(&[][..])
    );
}

/// A key package built with `mark_as_last_resort` and no capabilities carries
/// only the new marker. It passes validation, a receiver accepts the commit
/// that adds it, and it survives a Welcome: Dave joins two groups from the
/// same key package.
#[openmls_test]
fn marked_key_package_survives_two_welcomes() {
    let dave_provider = &Provider::default();
    let (dave_credential, dave_signer) =
        new_credential(dave_provider, b"Dave", ciphersuite.signature_algorithm());
    let dave_key_package = KeyPackage::builder()
        .mark_as_last_resort()
        .build(ciphersuite, dave_provider, &dave_signer, dave_credential)
        .unwrap()
        .key_package()
        .clone();
    assert!(dave_key_package.last_resort());
    assert!(!dave_key_package
        .extensions()
        .contains(ExtensionType::LastResort));
    assert_last_resort_component(&dave_key_package);
    let validated = validate(dave_provider, &dave_key_package)
        .expect("a key package marked as last resort must pass");

    join_two_groups(ciphersuite, dave_provider, validated);
}

/// libxmtp's key packages carry only the legacy `last_resort` extension. With
/// `extensions-draft`, a Welcome must still keep such a key package.
#[openmls_test]
fn legacy_marked_key_package_survives_two_welcomes() {
    let dave_provider = &Provider::default();
    let dave_key_package = key_package_with(
        ciphersuite,
        dave_provider,
        &[ExtensionType::LastResort],
        Extensions::single(Extension::LastResort(LastResortExtension::default())).unwrap(),
        None,
    )
    .key_package()
    .clone();
    assert!(dave_key_package
        .extensions()
        .app_data_dictionary()
        .is_none());
    let validated = validate(dave_provider, &dave_key_package)
        .expect("a key package with the legacy marker must pass");

    join_two_groups(ciphersuite, dave_provider, validated);
}

/// An `app_data_dictionary` without component 4 is not a last-resort marker,
/// so a Welcome deletes the bundle.
#[openmls_test]
fn key_package_with_other_component_only_is_consumed() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let (mut alice_group, alice_signer, _charlie_group) = alice_and_charlie(
        &config(ciphersuite),
        ciphersuite,
        alice_provider,
        charlie_provider,
    );
    let dave_provider = &Provider::default();
    let key_package = key_package_with(
        ciphersuite,
        dave_provider,
        &[ExtensionType::AppDataDictionary],
        Extensions::single(Extension::AppDataDictionary(dictionary(&[(
            0x8001,
            vec![1],
        )])))
        .unwrap(),
        None,
    )
    .key_package()
    .clone();
    assert!(!key_package.last_resort());

    let hash_ref = key_package.hash_ref(dave_provider.crypto()).unwrap();
    let (_, welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[key_package])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    join(dave_provider, &config(ciphersuite), welcome);
    let stored: Option<KeyPackageBundle> = dave_provider.storage().key_package(&hash_ref).unwrap();
    assert!(stored.is_none(), "a Welcome must delete the bundle");
}

/// `mark_as_last_resort` also marks key packages that the virtual-client batch
/// builder creates, and they pass validation.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test]
fn virtual_client_batch_marks_key_packages_as_last_resort() {
    use openmls::components::vc_derivation_info::VC_COMPONENT_ID;

    let provider = &Provider::default();
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build();
    // The leaf lists VC_COMPONENT_ID in its AppComponents entry (component 1).
    let leaf_node_extensions = {
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(1, vec![VC_COMPONENT_ID].tls_serialize_detached().unwrap());
        Extensions::single(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap()
    };

    let (emulator_credential, emulator_signer) =
        new_credential(provider, b"Emulator", ciphersuite.signature_algorithm());
    let emulator_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .with_leaf_node_extensions(leaf_node_extensions.clone())
        .unwrap()
        .build();
    let mut emulator = MlsGroup::new(
        provider,
        &emulator_signer,
        &emulator_config,
        emulator_credential,
    )
    .unwrap();
    let epoch_id = emulator
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .unwrap();

    let (vc_credential, vc_signer) = new_credential(
        provider,
        b"VirtualClient",
        ciphersuite.signature_algorithm(),
    );
    let batch = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(leaf_node_extensions)
        .mark_as_last_resort()
        .build_vc_batch(
            ciphersuite,
            provider,
            &vc_signer,
            vc_credential,
            epoch_id,
            1,
        )
        .unwrap();

    let key_package = batch.key_packages[0].0.key_package();
    assert!(key_package.last_resort());
    assert_last_resort_component(key_package);
    validate(provider, key_package).expect("a marked virtual-client key package must pass");
}
