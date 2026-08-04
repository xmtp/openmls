//! Round-trip tests for the PostgreSQL backend.
//!
//! These need a real server, so they are opt-in: set
//! `OPENMLS_SQLX_POSTGRES_URL` to a connection string and they run, otherwise
//! each one skips. Every test works in a schema of its own so they neither see
//! each other's rows nor each other's migration table.
#![cfg(feature = "postgres")]

mod common;

use common::*;
use openmls_sqlx_storage::PostgresStorageProvider;
use openmls_traits::storage::StorageProvider;
use sqlx::{Connection as _, Executor as _, PgConnection};

const URL_ENV: &str = "OPENMLS_SQLX_POSTGRES_URL";

/// Set this in CI. It turns "no server configured" from a silent skip into a
/// failure, so a misconfigured job cannot report green having tested nothing --
/// the skip path costs 0.00s and still prints `ok`, which is indistinguishable
/// from a real run at a glance.
const REQUIRE_ENV: &str = "OPENMLS_SQLX_REQUIRE_POSTGRES";

/// Connects and hands back a session pinned to a freshly created, empty schema.
/// Returns `None` when no server is configured, so the caller can skip.
async fn connect(schema: &str) -> Option<PgConnection> {
    let Ok(url) = std::env::var(URL_ENV) else {
        assert!(
            std::env::var(REQUIRE_ENV).is_err(),
            "{REQUIRE_ENV} is set but {URL_ENV} is not -- refusing to skip the \
             PostgreSQL tests and report success"
        );
        eprintln!("skipping: {URL_ENV} is not set");
        return None;
    };

    let mut connection = PgConnection::connect(&url).await.unwrap();
    for statement in [
        format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
        format!("CREATE SCHEMA {schema}"),
        format!("SET search_path TO {schema}"),
    ] {
        connection.execute(statement.as_str()).await.unwrap();
    }

    Some(connection)
}

async fn teardown(mut connection: PgConnection, schema: &str) {
    connection
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn proposals() {
    const SCHEMA: &str = "openmls_test_proposals";
    let Some(mut connection) = connect(SCHEMA).await else {
        return;
    };

    {
        let mut storage = PostgresStorageProvider::<JsonCodec>::new(&mut connection);
        storage.run_migrations().await.unwrap();

        let group_id = TestGroupId(b"TestGroupId".to_vec());
        let proposals = (0..10)
            .map(|i| TestProposal(format!("TestProposal{i}").as_bytes().to_vec()))
            .collect::<Vec<_>>();

        for (i, proposal) in proposals.iter().enumerate() {
            storage
                .queue_proposal(&group_id, &TestProposalRef(i), proposal)
                .await
                .unwrap();
        }

        let proposals_read: Vec<(TestProposalRef, TestProposal)> =
            storage.queued_proposals(&group_id).await.unwrap();
        let proposals_expected: Vec<(TestProposalRef, TestProposal)> = (0..10)
            .map(TestProposalRef)
            .zip(proposals.clone())
            .collect();
        assert_eq!(proposals_expected, proposals_read);

        // Re-queueing an existing ref must overwrite rather than conflict; this
        // is the `ON CONFLICT ... DO UPDATE` tail doing the work that
        // `INSERT OR REPLACE` does on SQLite.
        let replacement = TestProposal(b"replacement".to_vec());
        storage
            .queue_proposal(&group_id, &TestProposalRef(3), &replacement)
            .await
            .unwrap();
        let proposals_read: Vec<(TestProposalRef, TestProposal)> =
            storage.queued_proposals(&group_id).await.unwrap();
        assert_eq!(10, proposals_read.len());
        assert_eq!(
            replacement,
            proposals_read
                .iter()
                .find(|(r, _)| *r == TestProposalRef(3))
                .unwrap()
                .1
        );

        storage
            .remove_proposal(&group_id, &TestProposalRef(5))
            .await
            .unwrap();
        let proposal_refs_read: Vec<TestProposalRef> =
            storage.queued_proposal_refs(&group_id).await.unwrap();
        let mut expected = (0..10).map(TestProposalRef).collect::<Vec<_>>();
        expected.remove(5);
        assert_eq!(expected, proposal_refs_read);

        storage
            .clear_proposal_queue::<TestGroupId, TestProposalRef>(&group_id)
            .await
            .unwrap();
        let proposal_refs_read: Vec<TestProposalRef> =
            storage.queued_proposal_refs(&group_id).await.unwrap();
        assert!(proposal_refs_read.is_empty());
    }

    teardown(connection, SCHEMA).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn group_data_roundtrip() {
    const SCHEMA: &str = "openmls_test_group_data";
    let Some(mut connection) = connect(SCHEMA).await else {
        return;
    };

    {
        let mut storage = PostgresStorageProvider::<JsonCodec>::new(&mut connection);
        storage.run_migrations().await.unwrap();

        let group_id = TestGroupId(b"group-data".to_vec());
        let tree = TestBlob(b"tree".to_vec());
        let context = TestBlob(b"context".to_vec());
        let leaf_index = TestLeafIndex(7);

        storage.write_tree(&group_id, &tree).await.unwrap();
        storage.write_context(&group_id, &context).await.unwrap();
        storage
            .write_own_leaf_index(&group_id, &leaf_index)
            .await
            .unwrap();

        assert_eq!(Some(tree), storage.tree(&group_id).await.unwrap());
        assert_eq!(
            Some(context.clone()),
            storage.group_context(&group_id).await.unwrap()
        );
        assert_eq!(
            Some(leaf_index),
            storage.own_leaf_index(&group_id).await.unwrap()
        );

        // Two writes of the same (group_id, data_type) must collapse onto one row.
        let new_tree = TestBlob(b"new-tree".to_vec());
        storage.write_tree(&group_id, &new_tree).await.unwrap();
        assert_eq!(Some(new_tree), storage.tree(&group_id).await.unwrap());

        storage.delete_tree(&group_id).await.unwrap();
        assert_eq!(
            None::<TestBlob>,
            storage.tree::<_, TestBlob>(&group_id).await.unwrap()
        );
        // Deleting one data type must leave the others alone.
        assert_eq!(
            Some(context),
            storage.group_context(&group_id).await.unwrap()
        );

        // `append_own_leaf_node` shares the group id as its primary key, so the
        // most recent write wins here too.
        let leaf_node = TestBlob(b"leaf-node".to_vec());
        storage
            .append_own_leaf_node(&group_id, &leaf_node)
            .await
            .unwrap();
        assert_eq!(
            vec![leaf_node],
            storage
                .own_leaf_nodes::<_, TestBlob>(&group_id)
                .await
                .unwrap()
        );

        storage.delete_own_leaf_nodes(&group_id).await.unwrap();
        assert!(
            storage
                .own_leaf_nodes::<_, TestBlob>(&group_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    teardown(connection, SCHEMA).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_material_roundtrip() {
    const SCHEMA: &str = "openmls_test_key_material";
    let Some(mut connection) = connect(SCHEMA).await else {
        return;
    };

    {
        let mut storage = PostgresStorageProvider::<JsonCodec>::new(&mut connection);
        storage.run_migrations().await.unwrap();

        let signature_public_key = TestSignaturePublicKey(b"signature-public".to_vec());
        let signature_key_pair = TestSignatureKeyPair(b"signature-pair".to_vec());
        let encryption_key = TestEncryptionKey(b"encryption-public".to_vec());
        let encryption_key_pair = TestHpkeKeyPair(b"encryption-pair".to_vec());
        let group_id = TestGroupId(b"key-material".to_vec());
        let epoch = TestEpochKey(b"epoch".to_vec());
        let epoch_key_pairs = vec![
            TestHpkeKeyPair(b"epoch-pair-0".to_vec()),
            TestHpkeKeyPair(b"epoch-pair-1".to_vec()),
        ];
        let hash_ref = TestHashRef(b"hash-ref".to_vec());
        let key_package = TestKeyPackage(b"key-package".to_vec());
        let psk_id = TestPskId(b"psk-id".to_vec());
        let psk_bundle = TestPskBundle(b"psk-bundle".to_vec());

        storage
            .write_signature_key_pair(&signature_public_key, &signature_key_pair)
            .await
            .unwrap();
        storage
            .write_encryption_key_pair(&encryption_key, &encryption_key_pair)
            .await
            .unwrap();
        storage
            .write_encryption_epoch_key_pairs(&group_id, &epoch, 3, &epoch_key_pairs)
            .await
            .unwrap();
        storage
            .write_key_package(&hash_ref, &key_package)
            .await
            .unwrap();
        storage.write_psk(&psk_id, &psk_bundle).await.unwrap();

        assert_eq!(
            Some(signature_key_pair),
            storage
                .signature_key_pair(&signature_public_key)
                .await
                .unwrap()
        );
        assert_eq!(
            Some(encryption_key_pair),
            storage.encryption_key_pair(&encryption_key).await.unwrap()
        );
        assert_eq!(
            epoch_key_pairs,
            storage
                .encryption_epoch_key_pairs::<_, _, TestHpkeKeyPair>(&group_id, &epoch, 3)
                .await
                .unwrap()
        );
        // A different leaf index is a different row, even for the same epoch.
        assert!(
            storage
                .encryption_epoch_key_pairs::<_, _, TestHpkeKeyPair>(&group_id, &epoch, 4)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            Some(key_package),
            storage.key_package(&hash_ref).await.unwrap()
        );
        assert_eq!(Some(psk_bundle), storage.psk(&psk_id).await.unwrap());

        storage
            .delete_signature_key_pair::<TestSignaturePublicKey>(&signature_public_key)
            .await
            .unwrap();
        storage
            .delete_encryption_key_pair::<TestEncryptionKey>(&encryption_key)
            .await
            .unwrap();
        storage
            .delete_encryption_epoch_key_pairs::<TestGroupId, TestEpochKey>(&group_id, &epoch, 3)
            .await
            .unwrap();
        storage
            .delete_key_package::<TestHashRef>(&hash_ref)
            .await
            .unwrap();
        storage.delete_psk::<TestPskId>(&psk_id).await.unwrap();

        assert_eq!(
            None::<TestSignatureKeyPair>,
            storage
                .signature_key_pair(&signature_public_key)
                .await
                .unwrap()
        );
        assert_eq!(
            None::<TestHpkeKeyPair>,
            storage.encryption_key_pair(&encryption_key).await.unwrap()
        );
        assert!(
            storage
                .encryption_epoch_key_pairs::<_, _, TestHpkeKeyPair>(&group_id, &epoch, 3)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            None::<TestKeyPackage>,
            storage.key_package(&hash_ref).await.unwrap()
        );
        assert_eq!(None::<TestPskBundle>, storage.psk(&psk_id).await.unwrap());
    }

    teardown(connection, SCHEMA).await;
}
