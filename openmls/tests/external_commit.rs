use openmls::{
    credentials::test_utils::new_credential,
    messages::group_info::VerifiableGroupInfo,
    prelude::{tls_codec::*, *},
    treesync::LeafNodeParameters,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

fn create_alice_group(
    ciphersuite: Ciphersuite,
    provider: &impl openmls::storage::OpenMlsProvider,
    use_ratchet_tree_extension: bool,
) -> (MlsGroup, CredentialWithKey, SignatureKeyPair) {
    let group_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .ciphersuite(ciphersuite)
        .build();

    let (credential_with_key, signature_keys) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    let group = MlsGroup::new(
        provider,
        &signature_keys,
        &group_config,
        credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    (group, credential_with_key, signature_keys)
}

#[openmls_test]
fn test_external_commit() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    // Alice creates a new group ...
    let (alice_group, _, alice_signer) = create_alice_group(ciphersuite, alice_provider, false);

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group
            .export_group_info(alice_provider.crypto(), &alice_signer, true)
            .unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    let verifiable_group_info_broken = {
        let group_info = alice_group
            .export_group_info(alice_provider.crypto(), &alice_signer, true)
            .unwrap();

        let serialized_group_info = {
            let mut tmp = group_info.tls_serialize_detached().unwrap();

            // Simulate a bit-flip in the signature.
            let last = tmp.len().checked_sub(1).unwrap();
            tmp[last] ^= 1;

            tmp
        };

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    // ---------------------------------------------------------------------------------------------

    // Now, Bob wants to join Alice' group by an external commit. (Positive case.)
    {
        let (bob_credential, bob_signature_keys) =
            new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

        let (_bob_group, _) = MlsGroup::external_commit_builder()
            .build_group(bob_provider, verifiable_group_info, bob_credential)
            .unwrap()
            .load_psks(bob_provider.storage())
            .unwrap()
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                &bob_signature_keys,
                |_| true,
            )
            .unwrap()
            .finalize(bob_provider)
            .unwrap();
    }

    // Now, Bob wants to join Alice' group by an external commit. (Negative case, broken signature.)
    {
        let (bob_credential, _bob_signature_keys) =
            new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

        let got_error = MlsGroup::external_commit_builder()
            .build_group(bob_provider, verifiable_group_info_broken, bob_credential)
            .unwrap_err();

        assert!(matches!(
            got_error,
            ExternalCommitBuilderError::PublicGroupError(
                CreationFromExternalError::InvalidGroupInfoSignature
            )
        ));
    }
}

#[openmls_test]
fn test_group_info() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, alice_provider, true);

    // Self update Alice's to get a group info from a commit
    let group_info = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob wants to join
    let (bob_credential, bob_signature_keys) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, bundle) = MlsGroup::external_commit_builder()
        .with_config(
            MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .build_group(bob_provider, verifiable_group_info, bob_credential)
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signature_keys,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();
    let (msg, _, group_info) = bundle.into_contents();
    let msg = MlsMessageIn::from(msg);

    // let alice process bob's new client
    let msg = alice_group
        .process_message(alice_provider, msg.try_into_protocol_message().unwrap())
        .unwrap()
        .into_content();
    match msg {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group
                .merge_staged_commit(alice_provider, *commit)
                .unwrap();
        }
        _ => panic!("Unexpected message type"),
    }

    // bob sends a message to alice
    let message: MlsMessageIn = bob_group
        .create_message(bob_provider, &bob_signature_keys, b"Hello Alice")
        .unwrap()
        .into();

    let msg = alice_group
        .process_message(alice_provider, message.try_into_protocol_message().unwrap())
        .unwrap();
    let decrypted = match msg.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => msg.into_bytes(),
        _ => panic!("Not an ApplicationMessage"),
    };
    assert_eq!(decrypted, b"Hello Alice");

    // check that the returned group info from the external join is valid
    // Bob wants to join with another client
    let (bob_credential, bob_signature_keys) =
        new_credential(bob_provider, b"Bob 2", ciphersuite.signature_algorithm());
    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let _ = MlsGroup::external_commit_builder()
        .build_group(bob_provider, verifiable_group_info, bob_credential)
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signature_keys,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();
}

#[openmls_test]
fn test_not_present_group_info() {
    let provider = &Provider::default();
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, provider, false);

    // Self update Alice's to get a group info from a commit
    let group_info = alice_group
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info();
    alice_group.merge_pending_commit(provider).unwrap();

    assert!(group_info.is_none());
}

/// External commit carrying a by-value `Add` proposal alongside the implicit
/// `ExternalInit` and the joiner's path leaf. This is the building block for
/// atomic multi-leaf joins (e.g. a single device joining via external commit
/// while introducing a co-resident sibling device).
///
/// Verifies:
///   - The resulting [`CommitMessageBundle`] contains a Welcome (because an
///     invitation list was produced).
///   - The existing member (Alice) accepts and processes the external commit
///     including the by-value Add.
///   - The invitee from the by-value Add (Bob2) can join via the Welcome.
///   - All three parties converge to the same epoch and tree.
#[openmls_test]
fn test_external_commit_with_inline_add() {
    let alice_provider = &Provider::default();
    let bob1_provider = &Provider::default();
    let bob2_provider = &Provider::default();

    // Alice creates a group with ratchet tree extension so we can export a
    // self-contained GroupInfo for the external commit.
    let (mut alice_group, _alice_credential, alice_signer) =
        create_alice_group(ciphersuite, alice_provider, true);

    // Self-update so that the exported GroupInfo carries an external_pub
    // extension.
    let group_info = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info()
        .expect("self-update should produce a GroupInfo");
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let verifiable_group_info = {
        let serialized = group_info.tls_serialize_detached().unwrap();
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice()).unwrap()
    };

    // Bob1 (primary joiner) and Bob2 (co-resident sibling) generate
    // credentials. Bob2 also generates a KeyPackage that Bob1 will include as
    // an inline Add proposal in the external commit.
    let (bob1_credential, bob1_signer) =
        new_credential(bob1_provider, b"Bob1", ciphersuite.signature_algorithm());
    let (bob2_credential, bob2_signer) =
        new_credential(bob2_provider, b"Bob2", ciphersuite.signature_algorithm());

    let bob2_key_package = KeyPackage::builder()
        .build(ciphersuite, bob2_provider, &bob2_signer, bob2_credential)
        .unwrap()
        .key_package()
        .clone();

    // Bob1 builds an external commit that adds Bob2 by value.
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let (bob1_group, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config.clone())
        .build_group(bob1_provider, verifiable_group_info, bob1_credential)
        .unwrap()
        .propose_adds([bob2_key_package])
        .load_psks(bob1_provider.storage())
        .unwrap()
        .build(
            bob1_provider.rand(),
            bob1_provider.crypto(),
            &bob1_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob1_provider)
        .unwrap();

    // The bundle MUST carry a Welcome for Bob2.
    assert!(
        bundle.welcome().is_some(),
        "external commit with by-value Add must produce a Welcome"
    );
    let welcome = bundle.welcome().unwrap().clone();
    let commit_msg: MlsMessageIn = bundle.commit().clone().into();

    // Alice processes Bob1's external commit.
    let processed = alice_group
        .process_message(
            alice_provider,
            commit_msg.try_into_protocol_message().unwrap(),
        )
        .expect("Alice should accept external commit with inline Add");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            alice_group
                .merge_staged_commit(alice_provider, *staged)
                .unwrap();
        }
        _ => panic!("Expected StagedCommitMessage"),
    }

    // Bob2 joins via the Welcome.
    let bob2_group = StagedWelcome::new_from_welcome(
        bob2_provider,
        &join_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Bob2 should accept the Welcome")
    .into_group(bob2_provider)
    .expect("Bob2 should be able to build the group");

    // All three converge to the same epoch and group context.
    assert_eq!(alice_group.epoch(), bob1_group.epoch());
    assert_eq!(alice_group.epoch(), bob2_group.epoch());
    assert_eq!(
        alice_group.export_group_context(),
        bob1_group.export_group_context(),
    );
    assert_eq!(
        alice_group.export_group_context(),
        bob2_group.export_group_context(),
    );

    // The group has three members: Alice, Bob1, Bob2.
    assert_eq!(alice_group.members().count(), 3);
    assert_eq!(bob1_group.members().count(), 3);
    assert_eq!(bob2_group.members().count(), 3);

    // Sanity: silence unused warnings in case `bob2_signer` is not otherwise
    // referenced (it is captured by the closure during KeyPackage build above).
    let _ = bob2_signer;
}

/// External commit carrying a by-value `AppDataUpdate` proposal. This exercises
/// the `extensions-draft-08` code path: a non-member joining via external
/// commit applies an update to the AppDataDictionary atomically with the
/// join.
#[cfg(feature = "extensions-draft-08")]
#[openmls_test]
fn test_external_commit_with_inline_app_data_update() {
    use openmls::component::*;
    use openmls::extensions::*;
    use openmls::messages::proposals::AppDataUpdateProposal;

    const COMPONENT_ID: ComponentId = 16;

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Alice configures the group to require the AppDataUpdate proposal type
    // and the AppDataDictionary extension. Her own leaf must advertise the
    // matching capabilities.
    let capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        None,
    );
    let required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        ));

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities.clone())
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(Extensions::single(required_capabilities).unwrap())
        .build();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &group_config,
        alice_credential.clone(),
    )
    .unwrap();

    // Self-update Alice so the exported GroupInfo includes an external_pub.
    let group_info = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info()
        .expect("self-update should produce a GroupInfo");
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let verifiable_group_info = {
        let serialized = group_info.tls_serialize_detached().unwrap();
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice()).unwrap()
    };

    // Bob joins via external commit and includes an AppDataUpdate proposal.
    // His new leaf node must advertise the AppDataUpdate capability.
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(bob_credential.clone())
        .with_capabilities(capabilities)
        .build();

    let app_data_update = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
        COMPONENT_ID,
        b"hello-from-external-commit",
    )));

    let mut bob_commit_stage = MlsGroup::external_commit_builder()
        .with_config(group_config.join_config().clone())
        .build_group(bob_provider, verifiable_group_info, bob_credential)
        .unwrap()
        .leaf_node_parameters(bob_leaf_node_parameters)
        .add_proposal(app_data_update)
        .load_psks(bob_provider.storage())
        .unwrap();

    // Stage the AppDataUpdate so the dictionary diff is included in the
    // commit's GroupContext.
    let mut app_data_updater = bob_commit_stage.app_data_dictionary_updater();
    for proposal in bob_commit_stage.app_data_update_proposals() {
        let component_id = proposal.component_id();
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            app_data_updater
                .set(ComponentData::from_parts(component_id, data.clone()));
        }
    }
    let changes = app_data_updater.changes();
    assert!(
        changes.as_ref().is_some_and(|c| !c.is_empty()),
        "expected AppDataUpdate to produce dictionary changes"
    );
    bob_commit_stage.with_app_data_dictionary_updates(changes);

    let (bob_group, bundle) = bob_commit_stage
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    // Alice processes Bob's external commit. She must compute the same
    // dictionary updates to validate the commit successfully.
    let commit_msg: MlsMessageIn = bundle.commit().clone().into();
    let unverified = alice_group
        .unprotect_message(alice_provider, commit_msg.into_protocol_message().unwrap())
        .unwrap();
    let mut alice_updater = alice_group.app_data_dictionary_updater();
    for proposal in unverified.committed_proposals().unwrap().iter() {
        let validated = proposal
            .clone()
            .validate(alice_provider.crypto(), ciphersuite, ProtocolVersion::Mls10)
            .unwrap();
        let proposal = match validated {
            ProposalOrRef::Proposal(p) => *p,
            ProposalOrRef::Reference(_) => continue,
        };
        if let Proposal::AppDataUpdate(p) = proposal {
            let component_id = p.component_id();
            if let AppDataUpdateOperation::Update(data) = p.operation() {
                alice_updater.set(ComponentData::from_parts(component_id, data.clone()));
            }
        }
    }
    let processed = alice_group
        .process_unverified_message_with_app_data_updates(
            alice_provider,
            unverified,
            alice_updater.changes(),
        )
        .expect("Alice should accept external commit with AppDataUpdate");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            alice_group
                .merge_staged_commit(alice_provider, *staged)
                .unwrap();
        }
        _ => panic!("Expected StagedCommitMessage"),
    }

    // Both parties should now agree on the AppDataDictionary contents.
    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(
        alice_group.extensions().app_data_dictionary(),
        bob_group.extensions().app_data_dictionary(),
    );
    let alice_dict = alice_group
        .extensions()
        .app_data_dictionary()
        .expect("AppDataDictionary must be present");
    assert_eq!(
        alice_dict.dictionary().get(&COMPONENT_ID),
        Some(b"hello-from-external-commit".as_ref()),
    );
}
