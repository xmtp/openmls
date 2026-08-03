#[derive(Debug, Clone, Copy)]
pub(crate) enum GroupDataType {
    JoinGroupConfig,
    Tree,
    InterimTranscriptHash,
    Context,
    ConfirmationTag,
    GroupState,
    MessageSecrets,
    ResumptionPskStore,
    OwnLeafIndex,
    UseRatchetTreeExtension,
    GroupEpochSecrets,
    #[cfg(feature = "extensions-draft")]
    ApplicationExportTree,
}

impl GroupDataType {
    fn to_str(self) -> &'static str {
        match self {
            GroupDataType::JoinGroupConfig => "join_group_config",
            GroupDataType::Tree => "tree",
            GroupDataType::InterimTranscriptHash => "interim_transcript_hash",
            GroupDataType::Context => "context",
            GroupDataType::ConfirmationTag => "confirmation_tag",
            GroupDataType::GroupState => "group_state",
            GroupDataType::MessageSecrets => "message_secrets",
            GroupDataType::ResumptionPskStore => "resumption_psk_store",
            GroupDataType::OwnLeafIndex => "own_leaf_index",
            GroupDataType::UseRatchetTreeExtension => "use_ratchet_tree_extension",
            GroupDataType::GroupEpochSecrets => "group_epoch_secrets",
            #[cfg(feature = "extensions-draft")]
            GroupDataType::ApplicationExportTree => "application_export_tree",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "join_group_config" => Some(GroupDataType::JoinGroupConfig),
            "tree" => Some(GroupDataType::Tree),
            "interim_transcript_hash" => Some(GroupDataType::InterimTranscriptHash),
            "context" => Some(GroupDataType::Context),
            "confirmation_tag" => Some(GroupDataType::ConfirmationTag),
            "group_state" => Some(GroupDataType::GroupState),
            "message_secrets" => Some(GroupDataType::MessageSecrets),
            "resumption_psk_store" => Some(GroupDataType::ResumptionPskStore),
            "own_leaf_index" => Some(GroupDataType::OwnLeafIndex),
            "use_ratchet_tree_extension" => Some(GroupDataType::UseRatchetTreeExtension),
            "group_epoch_secrets" => Some(GroupDataType::GroupEpochSecrets),
            #[cfg(feature = "extensions-draft")]
            "application_export_tree" => Some(GroupDataType::ApplicationExportTree),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid group data type: {value}")]
struct InvalidGroupDataTypeError {
    value: String,
}

/// Binds [`GroupDataType`] to the `TEXT` column it is stored in. The
/// implementations are identical across dialects, but the traits are
/// parameterised by the database, so one set is needed per backend.
macro_rules! impl_group_data_type_codec {
    ($db:ty) => {
        impl sqlx::Type<$db> for GroupDataType {
            fn type_info() -> <$db as sqlx::Database>::TypeInfo {
                <String as sqlx::Type<$db>>::type_info()
            }
        }

        impl<'q> sqlx::Encode<'q, $db> for GroupDataType {
            fn encode_by_ref(
                &self,
                buf: &mut <$db as sqlx::Database>::ArgumentBuffer<'q>,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                sqlx::Encode::<$db>::encode(self.to_str(), buf)
            }
        }

        impl<'r> sqlx::Decode<'r, $db> for GroupDataType {
            fn decode(
                value: <$db as sqlx::Database>::ValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                let value: &str = sqlx::Decode::<$db>::decode(value)?;
                Self::from_str(value).ok_or_else(|| {
                    InvalidGroupDataTypeError {
                        value: value.to_string(),
                    }
                    .into()
                })
            }
        }
    };
}

#[cfg(feature = "sqlite")]
impl_group_data_type_codec!(sqlx::Sqlite);

#[cfg(feature = "postgres")]
impl_group_data_type_codec!(sqlx::Postgres);
