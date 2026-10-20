//! XMTP backport of upstream #2127 on v0.9.1: a GREASE-valued leaf node
//! extension reports `ExtensionType::Grease`, the same type that its
//! capabilities decode to. A member must accept a received Add whose key
//! package's leaf node carries a GREASE extension that its capabilities
//! declare. Otherwise this member and members on later OpenMLS releases
//! disagree on the commit.
use openmls::credentials::test_utils::new_credential;
use openmls::prelude::{tls_codec::*, *};
use openmls::treesync::errors::LeafNodeValidationError;
use openmls_test::openmls_test;

const GREASE: u16 = 0x5A5A;

/// A key package whose leaf node carries a GREASE extension. Its capabilities
/// declare that extension type when `declare` is true.
fn grease_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    declare: bool,
) -> KeyPackage {
    let (credential, signer) = new_credential(provider, b"Dave", ciphersuite.signature_algorithm());
    let declared = if declare {
        vec![ExtensionType::Grease(GREASE)]
    } else {
        vec![]
    };
    let capabilities = Capabilities::builder().extensions(declared).build();
    let leaf_node_extensions =
        Extensions::single(Extension::Unknown(GREASE, UnknownExtension(vec![1, 2, 3]))).unwrap();
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(leaf_node_extensions)
        .build(ciphersuite, provider, &signer, credential)
        .unwrap()
        .key_package()
        .clone()
}

#[openmls_test]
fn member_accepts_add_of_leaf_node_with_declared_grease_extension() {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let alice_provider = &Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        MlsGroup::new(alice_provider, &alice_signer, &config, alice_credential).unwrap();

    // Charlie joins with a plain key package.
    let charlie_provider = &Provider::default();
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
    let mut charlie_group =
        StagedWelcome::new_from_welcome(charlie_provider, config.join_config(), welcome, None)
            .unwrap()
            .into_group(charlie_provider)
            .unwrap();

    // Alice adds Dave, whose leaf node carries a declared GREASE extension.
    let dave_provider = &Provider::default();
    let dave_key_package = grease_key_package(ciphersuite, dave_provider, true);
    let (commit, dave_welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[dave_key_package])
        .expect("the committer must accept a declared GREASE extension");
    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Charlie receives the commit over the wire.
    let commit = MlsMessageIn::tls_deserialize_exact(commit.tls_serialize_detached().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let processed = charlie_group
        .process_message(charlie_provider, commit)
        .expect("a receiver must accept a declared GREASE extension");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            charlie_group
                .merge_staged_commit(charlie_provider, *staged)
                .unwrap();
        }
        other => panic!("expected a staged commit, got {other:?}"),
    }
    assert_eq!(alice_group.epoch(), charlie_group.epoch());
    assert_eq!(alice_group.members().count(), 3);
    assert_eq!(charlie_group.members().count(), 3);

    // Dave joins from the Welcome and validates a tree that holds his leaf.
    let dave_welcome = match MlsMessageIn::from(dave_welcome).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome"),
    };
    let dave_group =
        StagedWelcome::new_from_welcome(dave_provider, config.join_config(), dave_welcome, None)
            .expect("a joiner must accept a declared GREASE extension")
            .into_group(dave_provider)
            .unwrap();
    assert_eq!(dave_group.epoch(), alice_group.epoch());
}

/// GREASE does not exempt an extension from the capability check. A leaf node
/// with a GREASE extension that its capabilities do not declare is rejected.
/// In-process, the committer runs the same check as a receiver, so the
/// rejection shows at the committer.
#[openmls_test]
fn committer_rejects_add_of_leaf_node_with_undeclared_grease_extension() {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let alice_provider = &Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        MlsGroup::new(alice_provider, &alice_signer, &config, alice_credential).unwrap();

    let dave_provider = &Provider::default();
    let dave_key_package = grease_key_package(ciphersuite, dave_provider, false);
    let Err(error) = alice_group.add_members(alice_provider, &alice_signer, &[dave_key_package])
    else {
        panic!("an undeclared GREASE extension must be rejected");
    };
    assert!(
        matches!(
            error,
            AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                ProposalValidationError::LeafNodeValidation(
                    LeafNodeValidationError::UnsupportedExtensions
                )
            ))
        ),
        "unexpected error: {error:?}"
    );
}
