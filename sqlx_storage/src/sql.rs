//! The SQL statements used by the storage provider, rendered once per
//! supported dialect.
//!
//! The statements are written down a single time, in [`statement_set`], and the
//! places where the dialects diverge are passed in as arguments. There are only
//! two such places:
//!
//! * Bind placeholders. SQLite spells them `?1`, PostgreSQL spells them `$1`.
//! * Upserts. SQLite has the non-standard `INSERT OR REPLACE INTO`, while
//!   PostgreSQL needs an explicit `ON CONFLICT (<primary key>) DO UPDATE SET
//!   <non-key columns>` tail. The tails are per-table because they name that
//!   table's primary key, so they are passed in one by one.
//!
//! Everything else is shared, which is the point: a fix to a statement lands in
//! both backends at once.

macro_rules! statement_set {
    (
        placeholders: [$p1:literal, $p2:literal, $p3:literal, $p4:literal],
        insert: $insert:literal,
        on_conflict_group_data: $oc_group_data:literal,
        on_conflict_proposal: $oc_proposal:literal,
        on_conflict_own_leaf_node: $oc_own_leaf_node:literal,
        on_conflict_signature_key: $oc_signature_key:literal,
        on_conflict_encryption_key: $oc_encryption_key:literal,
        on_conflict_epoch_key_pairs: $oc_epoch_key_pairs:literal,
        on_conflict_key_package: $oc_key_package:literal,
        on_conflict_psk: $oc_psk:literal $(,)?
    ) => {
        pub(crate) const STORE_GROUP_DATA: &str = concat!(
            $insert,
            "openmls_group_data (group_id, data_type, group_data) VALUES (",
            $p1,
            ", ",
            $p2,
            ", ",
            $p3,
            ")",
            $oc_group_data,
        );

        pub(crate) const LOAD_GROUP_DATA: &str = concat!(
            "SELECT group_data FROM openmls_group_data WHERE group_id = ",
            $p1,
            " AND data_type = ",
            $p2,
        );

        pub(crate) const DELETE_GROUP_DATA: &str = concat!(
            "DELETE FROM openmls_group_data WHERE group_id = ",
            $p1,
            " AND data_type = ",
            $p2,
        );

        pub(crate) const STORE_PROPOSAL: &str = concat!(
            $insert,
            "openmls_proposal (group_id, proposal_ref, proposal) VALUES (",
            $p1,
            ", ",
            $p2,
            ", ",
            $p3,
            ")",
            $oc_proposal,
        );

        pub(crate) const LOAD_PROPOSALS: &str = concat!(
            "SELECT proposal_ref, proposal FROM openmls_proposal WHERE group_id = ",
            $p1,
        );

        pub(crate) const LOAD_PROPOSAL_REFS: &str = concat!(
            "SELECT proposal_ref FROM openmls_proposal WHERE group_id = ",
            $p1,
        );

        pub(crate) const DELETE_PROPOSAL: &str = concat!(
            "DELETE FROM openmls_proposal WHERE group_id = ",
            $p1,
            " AND proposal_ref = ",
            $p2,
        );

        pub(crate) const DELETE_ALL_PROPOSALS: &str =
            concat!("DELETE FROM openmls_proposal WHERE group_id = ", $p1,);

        pub(crate) const STORE_OWN_LEAF_NODE: &str = concat!(
            $insert,
            "openmls_own_leaf_node (group_id, leaf_node) VALUES (",
            $p1,
            ", ",
            $p2,
            ")",
            $oc_own_leaf_node,
        );

        pub(crate) const LOAD_OWN_LEAF_NODES: &str = concat!(
            "SELECT leaf_node FROM openmls_own_leaf_node WHERE group_id = ",
            $p1,
        );

        pub(crate) const DELETE_OWN_LEAF_NODES: &str =
            concat!("DELETE FROM openmls_own_leaf_node WHERE group_id = ", $p1,);

        pub(crate) const STORE_SIGNATURE_KEY: &str = concat!(
            $insert,
            "openmls_signature_key (public_key, signature_key) VALUES (",
            $p1,
            ", ",
            $p2,
            ")",
            $oc_signature_key,
        );

        pub(crate) const LOAD_SIGNATURE_KEY: &str = concat!(
            "SELECT signature_key FROM openmls_signature_key WHERE public_key = ",
            $p1,
        );

        pub(crate) const DELETE_SIGNATURE_KEY: &str =
            concat!("DELETE FROM openmls_signature_key WHERE public_key = ", $p1,);

        pub(crate) const STORE_ENCRYPTION_KEY: &str = concat!(
            $insert,
            "openmls_encryption_key (public_key, key_pair) VALUES (",
            $p1,
            ", ",
            $p2,
            ")",
            $oc_encryption_key,
        );

        pub(crate) const LOAD_ENCRYPTION_KEY: &str = concat!(
            "SELECT key_pair FROM openmls_encryption_key WHERE public_key = ",
            $p1,
        );

        pub(crate) const DELETE_ENCRYPTION_KEY: &str = concat!(
            "DELETE FROM openmls_encryption_key WHERE public_key = ",
            $p1,
        );

        pub(crate) const STORE_EPOCH_KEY_PAIRS: &str = concat!(
            $insert,
            "openmls_epoch_key_pairs (group_id, epoch_id, leaf_index, key_pairs) VALUES (",
            $p1,
            ", ",
            $p2,
            ", ",
            $p3,
            ", ",
            $p4,
            ")",
            $oc_epoch_key_pairs,
        );

        pub(crate) const LOAD_EPOCH_KEY_PAIRS: &str = concat!(
            "SELECT key_pairs FROM openmls_epoch_key_pairs WHERE group_id = ",
            $p1,
            " AND epoch_id = ",
            $p2,
            " AND leaf_index = ",
            $p3,
        );

        pub(crate) const DELETE_EPOCH_KEY_PAIRS: &str = concat!(
            "DELETE FROM openmls_epoch_key_pairs WHERE group_id = ",
            $p1,
            " AND epoch_id = ",
            $p2,
            " AND leaf_index = ",
            $p3,
        );

        pub(crate) const STORE_KEY_PACKAGE: &str = concat!(
            $insert,
            "openmls_key_package (key_package_ref, key_package) VALUES (",
            $p1,
            ", ",
            $p2,
            ")",
            $oc_key_package,
        );

        pub(crate) const LOAD_KEY_PACKAGE: &str = concat!(
            "SELECT key_package FROM openmls_key_package WHERE key_package_ref = ",
            $p1,
        );

        pub(crate) const DELETE_KEY_PACKAGE: &str = concat!(
            "DELETE FROM openmls_key_package WHERE key_package_ref = ",
            $p1,
        );

        pub(crate) const STORE_PSK: &str = concat!(
            $insert,
            "openmls_psk (psk_id, psk_bundle) VALUES (",
            $p1,
            ", ",
            $p2,
            ")",
            $oc_psk,
        );

        pub(crate) const LOAD_PSK: &str =
            concat!("SELECT psk_bundle FROM openmls_psk WHERE psk_id = ", $p1,);

        pub(crate) const DELETE_PSK: &str =
            concat!("DELETE FROM openmls_psk WHERE psk_id = ", $p1,);
    };
}

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite {
    statement_set! {
        placeholders: ["?1", "?2", "?3", "?4"],
        insert: "INSERT OR REPLACE INTO ",
        // `INSERT OR REPLACE` already resolves every primary key conflict, so
        // none of the tables need a conflict tail.
        on_conflict_group_data: "",
        on_conflict_proposal: "",
        on_conflict_own_leaf_node: "",
        on_conflict_signature_key: "",
        on_conflict_encryption_key: "",
        on_conflict_epoch_key_pairs: "",
        on_conflict_key_package: "",
        on_conflict_psk: "",
    }
}

#[cfg(feature = "postgres")]
pub(crate) mod postgres {
    statement_set! {
        placeholders: ["$1", "$2", "$3", "$4"],
        insert: "INSERT INTO ",
        // PostgreSQL has no `INSERT OR REPLACE`, so every upsert spells out its
        // table's primary key as the conflict target and re-assigns the
        // remaining columns from the rejected row.
        on_conflict_group_data:
            " ON CONFLICT (group_id, data_type) DO UPDATE SET group_data = EXCLUDED.group_data",
        on_conflict_proposal:
            " ON CONFLICT (group_id, proposal_ref) DO UPDATE SET proposal = EXCLUDED.proposal",
        on_conflict_own_leaf_node:
            " ON CONFLICT (group_id) DO UPDATE SET leaf_node = EXCLUDED.leaf_node",
        on_conflict_signature_key:
            " ON CONFLICT (public_key) DO UPDATE SET signature_key = EXCLUDED.signature_key",
        on_conflict_encryption_key:
            " ON CONFLICT (public_key) DO UPDATE SET key_pair = EXCLUDED.key_pair",
        on_conflict_epoch_key_pairs:
            " ON CONFLICT (group_id, epoch_id, leaf_index) DO UPDATE SET key_pairs = EXCLUDED.key_pairs",
        on_conflict_key_package:
            " ON CONFLICT (key_package_ref) DO UPDATE SET key_package = EXCLUDED.key_package",
        on_conflict_psk:
            " ON CONFLICT (psk_id) DO UPDATE SET psk_bundle = EXCLUDED.psk_bundle",
    }
}
