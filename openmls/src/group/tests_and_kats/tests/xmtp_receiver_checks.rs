//! XMTP: receiver-side checks that a test cannot reach through the public
//! API, because the committer runs the same check first. Each test builds a
//! valid commit, changes it, and re-signs it, so only the receiver's check
//! decides the outcome.

use openmls_traits::{signatures::Signer, types::Ciphersuite};
use tls_codec::{Deserialize, Serialize};

use crate::{
    credentials::{test_utils::new_credential, NewSignerBundle},
    extensions::{Extension, ExtensionType, Extensions, UnknownExtension},
    framing::*,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, resign_message},
        *,
    },
    key_packages::KeyPackage,
    messages::proposals::*,
    treesync::{
        errors::{ApplyUpdatePathError, LeafNodeValidationError},
        node::leaf_node::Capabilities,
    },
};

const GREASE: u16 = 0x5A5A;

struct Setup {
    alice_group: MlsGroup,
    alice_signer: openmls_basic_credential::SignatureKeyPair,
    bob_group: MlsGroup,
    bob_signer: openmls_basic_credential::SignatureKeyPair,
    bob_credential_with_key: crate::credentials::CredentialWithKey,
    charlie_group: MlsGroup,
}

/// Alice, Bob and Charlie in a group that sends public messages, so that a
/// test can change and re-sign a commit.
fn setup(
    ciphersuite: Ciphersuite,
    alice_provider: &impl crate::storage::OpenMlsProvider,
    bob_provider: &impl crate::storage::OpenMlsProvider,
    charlie_provider: &impl crate::storage::OpenMlsProvider,
) -> Setup {
    let alice = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let charlie = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let bob_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            bob_provider,
            &bob.signer,
            bob.credential_with_key.clone(),
        )
        .unwrap()
        .key_package()
        .clone();
    let charlie_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            charlie_provider,
            &charlie.signer,
            charlie.credential_with_key.clone(),
        )
        .unwrap()
        .key_package()
        .clone();

    let config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .build();
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice.signer,
        &config,
        alice.credential_with_key.clone(),
    )
    .unwrap();
    let (_, welcome, _) = alice_group
        .add_members(
            alice_provider,
            &alice.signer,
            &[bob_key_package, charlie_key_package],
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome = MlsMessageIn::from(welcome).into_welcome().unwrap();
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        config.join_config(),
        welcome.clone(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(bob_provider)
    .unwrap();
    let charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(charlie_provider)
    .unwrap();

    Setup {
        alice_group,
        alice_signer: alice.signer,
        bob_group,
        bob_signer: bob.signer,
        bob_credential_with_key: bob.credential_with_key,
        charlie_group,
    }
}

/// Decodes a commit as a receiver gets it.
fn public_message(commit: &MlsMessageOut) -> PublicMessage {
    let bytes = commit.tls_serialize_detached().unwrap();
    MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .unwrap()
        .into_plaintext()
        .unwrap()
}

/// Replaces the proposals of `original` with the result of `change` and
/// re-signs it as Alice, the committer, in her current epoch.
fn change_proposals(
    original: &PublicMessage,
    alice_group: &MlsGroup,
    alice_signer: &impl Signer,
    provider: &impl crate::storage::OpenMlsProvider,
    ciphersuite: Ciphersuite,
    change: impl FnOnce(&mut Vec<ProposalOrRef>),
) -> ProtocolMessage {
    let FramedContentBody::Commit(mut commit) = original.content().clone() else {
        panic!("expected a commit");
    };
    change(&mut commit.proposals);
    let mut changed = original.clone();
    changed.set_content(FramedContentBody::Commit(commit));
    resign_message(
        alice_group,
        changed,
        original,
        provider,
        alice_signer,
        ciphersuite,
    )
    .into()
}

/// #2207 on the receiver side for a member commit: the path leaf of a commit
/// from a member must not reuse the signature key of another member who stays
/// in the group.
///
/// Alice commits `Remove(Bob)` and moves her own leaf to Bob's signature key.
/// The committer accepts that, because Bob's leaf is removed. The test then
/// drops the Remove and re-signs, so Bob stays and the path leaf duplicates
/// his key. Charlie must reject the commit.
#[openmls_test::openmls_test]
fn receiver_rejects_member_commit_whose_path_leaf_reuses_a_member_signature_key() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let Setup {
        mut alice_group,
        alice_signer,
        bob_group,
        bob_signer,
        bob_credential_with_key,
        mut charlie_group,
    } = setup(ciphersuite, alice_provider, bob_provider, charlie_provider);

    let commit = alice_group
        .commit_builder()
        .propose_removals([bob_group.own_leaf_index()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build_with_new_signer(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            NewSignerBundle {
                signer: &bob_signer,
                credential_with_key: bob_credential_with_key,
            },
            |_| true,
        )
        .expect("the committer accepts the key of a removed member")
        .stage_commit(alice_provider)
        .unwrap()
        .commit()
        .clone();
    let original = public_message(&commit);

    let without_remove = change_proposals(
        &original,
        &alice_group,
        &alice_signer,
        alice_provider,
        ciphersuite,
        |proposals| {
            let count = proposals.len();
            proposals.retain(|proposal| !proposal.as_proposal().is_some_and(Proposal::is_remove));
            assert_eq!(proposals.len(), count - 1);
        },
    );
    let error = charlie_group
        .process_message(charlie_provider, without_remove)
        .expect_err("the path leaf reuses Bob's signature key");
    assert!(
        matches!(
            error,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::DuplicateSignatureKey
            ))
        ),
        "unexpected error: {error:?}"
    );

    // The unchanged commit is accepted, so the rejection above comes from the
    // duplicate key, not from the re-signing.
    charlie_group
        .process_message(charlie_provider, ProtocolMessage::from(original))
        .unwrap();
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
}

/// A key package for Dave whose leaf node carries a GREASE extension. Its
/// capabilities declare that extension type when `declare` is true.
fn dave_grease_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
    declare: bool,
) -> KeyPackage {
    let (credential, signer) = new_credential(provider, b"Dave", ciphersuite.signature_algorithm());
    let declared = if declare {
        vec![ExtensionType::Grease(GREASE)]
    } else {
        vec![]
    };
    KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::builder().extensions(declared).build())
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(GREASE, UnknownExtension(vec![1, 2, 3])))
                .unwrap(),
        )
        .build(ciphersuite, provider, &signer, credential)
        .unwrap()
        .key_package()
        .clone()
}

/// Replaces the key package of the single Add proposal in `proposals`.
fn swap_added_key_package(proposals: &mut [ProposalOrRef], key_package: KeyPackage) {
    let mut swapped = 0;
    for proposal in proposals.iter_mut() {
        if matches!(proposal.as_proposal(), Some(Proposal::Add(_))) {
            *proposal = ProposalOrRef::proposal(Proposal::Add(Box::new(AddProposal {
                key_package: key_package.clone(),
            })));
            swapped += 1;
        }
    }
    assert_eq!(swapped, 1);
}

/// The GREASE mapping on the receiver side. Alice commits an Add, and the
/// test swaps in Dave's key package and re-signs. The swap changes the tree,
/// so the commit cannot be applied in the end; what matters is whether the
/// receiver's capability check on the added leaf passes.
#[openmls_test::openmls_test]
fn receiver_capability_check_on_added_leaf_with_grease_extension() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let dave_provider = &Provider::default();
    let Setup {
        mut alice_group,
        alice_signer,
        mut charlie_group,
        ..
    } = setup(ciphersuite, alice_provider, bob_provider, charlie_provider);

    // Alice commits an Add of a key package without GREASE.
    let (plain_credential, plain_signer) =
        new_credential(dave_provider, b"Dave", ciphersuite.signature_algorithm());
    let plain_key_package = KeyPackage::builder()
        .build(ciphersuite, dave_provider, &plain_signer, plain_credential)
        .unwrap()
        .key_package()
        .clone();
    let (commit, _, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[plain_key_package])
        .unwrap();
    let original = public_message(&commit);

    let process = |charlie_group: &mut MlsGroup, declare: bool| {
        let key_package = dave_grease_key_package(ciphersuite, dave_provider, declare);
        let changed = change_proposals(
            &original,
            &alice_group,
            &alice_signer,
            alice_provider,
            ciphersuite,
            |proposals| swap_added_key_package(proposals, key_package),
        );
        charlie_group
            .process_message(charlie_provider, changed)
            .expect_err("the swapped commit no longer matches its confirmation tag")
    };

    // Undeclared: the receiver rejects the added leaf.
    let error = process(&mut charlie_group, false);
    assert!(
        matches!(
            error,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::LeafNodeValidation(
                    LeafNodeValidationError::UnsupportedExtensions
                )
            ))
        ),
        "unexpected error: {error:?}"
    );

    // Declared: the receiver's proposal checks pass. The commit fails only
    // when its path, built for the original tree, is applied to the tree that
    // holds the swapped leaf.
    let error = process(&mut charlie_group, true);
    assert!(
        matches!(
            error,
            ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
                ApplyUpdatePathError::ParentHashMismatch
            ))
        ),
        "the receiver rejected a declared GREASE extension: {error:?}"
    );

    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
}
