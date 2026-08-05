-- Migration: Add application_export_tree to openmls_group_data
--
-- The SQLite twin of this migration has to rename, recreate and repopulate the
-- table, because SQLite cannot alter a CHECK constraint. PostgreSQL can drop
-- and re-add the named constraint in place, so the data never moves.
ALTER TABLE openmls_group_data
    DROP CONSTRAINT openmls_group_data_data_type_check;

ALTER TABLE openmls_group_data
    ADD CONSTRAINT openmls_group_data_data_type_check CHECK (
        data_type IN (
            'join_group_config',
            'tree',
            'interim_transcript_hash',
            'context',
            'confirmation_tag',
            'group_state',
            'message_secrets',
            'resumption_psk_store',
            'own_leaf_index',
            'use_ratchet_tree_extension',
            'group_epoch_secrets',
            'application_export_tree'
        )
    );
