use std::collections::{HashMap, VecDeque};

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

impl EpochTree {
    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.message_secrets.timestamp()
    }
}

// Internal helper struct
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
    leaves: Vec<Member>,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
///
/// Persisted on-disk format. The bincode/postcard positional wire layout is:
///
/// ```text
///   max_epochs:          usize
///   past_epoch_trees:    VecDeque<EpochTree>
///   message_secrets:     MessageSecrets            (five upstream-0.7.x fields)
///   added_at:            Option<SystemTime>        <- fork-only trailing field
///   past_epoch_added_at: Vec<Option<SystemTime>>   <- fork-only trailing field
/// ```
///
/// The two fork-only fields are hand-serialized here rather than as an inline
/// `MessageSecrets.added_at`, because `MessageSecrets` is not the last field of
/// `EpochTree`, so an inline trailing field would corrupt the byte stream. They
/// are read *tolerantly*: EOF (or any deserialize error) past the upstream shape
/// is treated as "absent -> `None`", so data written by openmls-0.7.x — which
/// lacks them — still loads. On deserialize the timestamps are re-hydrated onto
/// the corresponding `MessageSecrets.added_at` fields. Both are at the end of
/// the struct, so a tolerant misread cannot consume a sibling's bytes.
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    pub(crate) max_epochs: usize,
    // Past message secrets.
    // NOTE: these are in order of addition (latest at end).
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecrets,
}

impl Serialize for MessageSecretsStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("MessageSecretsStore", 5)?;
        s.serialize_field("max_epochs", &self.max_epochs)?;
        s.serialize_field("past_epoch_trees", &self.past_epoch_trees)?;
        s.serialize_field("message_secrets", &self.message_secrets)?;
        s.serialize_field("added_at", &self.message_secrets.added_at)?;
        let past_added_at: Vec<Option<SystemTime>> = self
            .past_epoch_trees
            .iter()
            .map(|t| t.message_secrets.added_at)
            .collect();
        s.serialize_field("past_epoch_added_at", &past_added_at)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for MessageSecretsStore {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &[
            "max_epochs",
            "past_epoch_trees",
            "message_secrets",
            "added_at",
            "past_epoch_added_at",
        ];
        deserializer.deserialize_struct("MessageSecretsStore", FIELDS, MessageSecretsStoreVisitor)
    }
}

struct MessageSecretsStoreVisitor;

impl<'de> serde::de::Visitor<'de> for MessageSecretsStoreVisitor {
    type Value = MessageSecretsStore;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("struct MessageSecretsStore")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<MessageSecretsStore, A::Error> {
        use serde::de::Error;
        let max_epochs = seq
            .next_element::<usize>()?
            .ok_or_else(|| Error::missing_field("max_epochs"))?;
        let mut past_epoch_trees = seq
            .next_element::<VecDeque<EpochTree>>()?
            .ok_or_else(|| Error::missing_field("past_epoch_trees"))?;
        let mut message_secrets = seq
            .next_element::<MessageSecrets>()?
            .ok_or_else(|| Error::missing_field("message_secrets"))?;
        // Tolerant tail #1: `added_at` for the current `message_secrets`.
        let added_at = seq
            .next_element::<Option<SystemTime>>()
            .unwrap_or(None)
            .flatten();
        message_secrets.added_at = added_at;
        // Tolerant tail #2: per-past-epoch timestamps, re-hydrated by index.
        let past_added_at: Vec<Option<SystemTime>> = seq
            .next_element::<Vec<Option<SystemTime>>>()
            .unwrap_or(None)
            .unwrap_or_default();
        for (i, tree) in past_epoch_trees.iter_mut().enumerate() {
            tree.message_secrets.added_at = past_added_at.get(i).copied().unwrap_or(None);
        }
        Ok(MessageSecretsStore {
            max_epochs,
            past_epoch_trees,
            message_secrets,
        })
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<MessageSecretsStore, A::Error> {
        use serde::de::Error;
        let mut max_epochs: Option<usize> = None;
        let mut past_epoch_trees: Option<VecDeque<EpochTree>> = None;
        let mut message_secrets: Option<MessageSecrets> = None;
        let mut added_at: Option<Option<SystemTime>> = None;
        let mut past_epoch_added_at: Option<Vec<Option<SystemTime>>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "max_epochs" => max_epochs = Some(map.next_value()?),
                "past_epoch_trees" => past_epoch_trees = Some(map.next_value()?),
                "message_secrets" => message_secrets = Some(map.next_value()?),
                "added_at" => added_at = Some(map.next_value()?),
                "past_epoch_added_at" => past_epoch_added_at = Some(map.next_value()?),
                _ => {
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }

        let mut message_secrets =
            message_secrets.ok_or_else(|| Error::missing_field("message_secrets"))?;
        message_secrets.added_at = added_at.unwrap_or(None);
        let mut past_epoch_trees =
            past_epoch_trees.ok_or_else(|| Error::missing_field("past_epoch_trees"))?;
        if let Some(past_added_at) = past_epoch_added_at {
            for (i, tree) in past_epoch_trees.iter_mut().enumerate() {
                tree.message_secrets.added_at = past_added_at.get(i).copied().unwrap_or(None);
            }
        }
        Ok(MessageSecretsStore {
            max_epochs: max_epochs.ok_or_else(|| Error::missing_field("max_epochs"))?,
            past_epoch_trees,
            message_secrets,
        })
    }
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for MessageSecretsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecretsStore")
            .field("max_epochs", &"***")
            .field("past_epoch_trees", &"***")
            .field("message_secrets", &"***")
            .finish()
    }
}

const VECDEQUE_MAX_CAPACITY: usize = isize::MAX as usize;

// XXX: the VecDeque capacity is not checked elsewhere in this module.
/// Helper function to map a policy to a maximum number of past epochs
fn max_epochs(policy: &PastEpochDeletionPolicy) -> usize {
    // get the `max_epochs`, or the maximum capacity of a `VecDeque`
    let max_epochs = policy.max_epochs().unwrap_or(VECDEQUE_MAX_CAPACITY);

    // cap at max capacity
    max_epochs.min(VECDEQUE_MAX_CAPACITY)
}

impl MessageSecretsStore {
    /// Create a new store that can hold up to `max_past_epochs` message secrets.
    /// If `max_past_epochs` is 0, only the current epoch is being stored.
    pub(crate) fn new_with_secret(
        policy: &PastEpochDeletionPolicy,
        message_secrets: MessageSecrets,
    ) -> Self {
        // max or the limit of the storage size
        let max_epochs = max_epochs(policy);

        Self {
            max_epochs,
            past_epoch_trees: VecDeque::new(),
            message_secrets: message_secrets.with_timestamp(SystemTime::now()),
        }
    }

    /// Resize the store.
    pub(crate) fn resize(&mut self, policy: &PastEpochDeletionPolicy) {
        // max or the limit of the storage size
        let max_past_epochs = max_epochs(policy);

        let old_size = self.max_epochs;
        self.max_epochs = max_past_epochs;
        if old_size > max_past_epochs {
            let num_epochs_out = old_size - max_past_epochs;
            self.past_epoch_trees
                .rotate_left(num_epochs_out.min(self.past_epoch_trees.len()));
            self.past_epoch_trees.truncate(max_past_epochs);
        }
    }

    /// Set the `message_secrets` to a provided `MessageSecrets`, and return
    /// the previous one.
    pub(crate) fn replace_current_message_secrets(
        &mut self,
        message_secrets: MessageSecrets,
    ) -> MessageSecrets {
        let mut message_secrets = message_secrets.with_timestamp(SystemTime::now());
        std::mem::swap(&mut self.message_secrets, &mut message_secrets);

        message_secrets
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    /// Note that this does not take the epoch into account and pops out the
    /// oldest element.
    pub(crate) fn add_past_epoch_tree(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
        message_secrets: MessageSecrets,
        leaves: Vec<Member>,
    ) {
        // Don't store the tree if it's not intended
        if self.max_epochs == 0 {
            return;
        }
        if self.past_epoch_trees.len() >= self.max_epochs {
            self.past_epoch_trees.rotate_left(1);
            self.past_epoch_trees.truncate(self.max_epochs - 1);
        }

        self.past_epoch_trees.push_back(EpochTree {
            epoch: group_epoch.into().as_u64(),
            message_secrets,
            leaves,
        });
        debug_assert!(
            self.max_epochs >= self.past_epoch_trees.len(),
            "Only {} past secrets must be stored but we found {}",
            self.max_epochs,
            self.past_epoch_trees.len()
        );
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch_mut(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&mut MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some(&epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// Return a mutable reference to the [`MessageSecrets`] and a slice to the
    /// [`Member`]s of the epoch.
    pub(crate) fn secrets_and_leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<(&MessageSecrets, &[Member])> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some((&epoch_tree.message_secrets, &epoch_tree.leaves));
            }
        }
        None
    }

    /// Returns a `HashMap` that maps a `LeafNodeIndex` to the correct
    /// [`Member`] in the given `group_epoch`.
    pub(crate) fn leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> HashMap<LeafNodeIndex, &Member> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return epoch_tree
                    .leaves
                    .iter()
                    .map(|m| (m.index, m))
                    .collect::<HashMap<LeafNodeIndex, &Member>>();
            }
        }
        HashMap::new()
    }

    /// Check if the provided epoch contains a leaf index.
    pub(crate) fn epoch_has_leaf(
        &self,
        group_epoch: GroupEpoch,
        leaf_index: LeafNodeIndex,
    ) -> bool {
        self.past_epoch_trees.iter().any(|t| {
            t.epoch == group_epoch.0
                && t.leaves
                    .iter()
                    .any(|Member { index, .. }| *index == leaf_index)
        })
    }

    /// Get a mutable reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets_mut(&mut self) -> &mut MessageSecrets {
        &mut self.message_secrets
    }

    /// Get a reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets
    }

    fn delete_past_epoch_secrets_older_than_duration(&mut self, duration: std::time::Duration) {
        // first, compare to the timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if let Ok(elapsed) = SystemTime::now().duration_since(added_at) {
                if elapsed > duration {
                    // delete all
                    self.past_epoch_trees.clear();
                    return;
                }
            }
        }

        // find the first past epoch tree with a timestamp past the duration
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                let Ok(elapsed) = SystemTime::now().duration_since(added_at) else {
                    return false;
                };

                elapsed > duration
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {

            // keep all
        }
    }

    fn delete_past_epoch_secrets_before_timestamp(&mut self, cutoff: SystemTime) {
        // first, compare to timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if added_at < cutoff {
                // delete all
                self.past_epoch_trees.clear();
                return;
            }
        }

        // find the first past epoch tree with an earlier non-None timestamp
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                added_at < cutoff
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {
            // keep all
        }
    }

    pub(crate) fn delete_past_epoch_secrets(&mut self, policy: PastEpochDeletion) {
        // handle different types of past epoch deletion
        if let Some(config) = policy.config {
            match config {
                PastEpochDeletionTimeConfig::DeleteAllWithoutTimestamp => {
                    self.past_epoch_trees
                        .retain(|tree| tree.message_secrets.timestamp().is_some());
                }
                PastEpochDeletionTimeConfig::BeforeTimestamp(timestamp) => {
                    self.delete_past_epoch_secrets_before_timestamp(timestamp)
                }
                PastEpochDeletionTimeConfig::OlderThanDuration(duration) => {
                    self.delete_past_epoch_secrets_older_than_duration(duration)
                }
            };
            // ensure at most `max_past_epochs` entries are included
            if let Some(max_past_epochs) = policy.max_past_epochs {
                if let Some(i) = self.past_epoch_trees.len().checked_sub(max_past_epochs) {
                    self.past_epoch_trees.drain(0..i);
                }
            }
        } else {
            // delete all
            self.past_epoch_trees.clear();
        }
    }

    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    /// Helper function for testing, to iterate over all past epoch secrets
    pub(crate) fn iter_past_epoch_trees(&self) -> impl Iterator<Item = &EpochTree> {
        self.past_epoch_trees.iter()
    }

    #[cfg(test)]
    /// Helper function for testing, to get the number of past epoch trees
    pub(crate) fn num_past_epoch_trees(&self) -> usize {
        self.past_epoch_trees.len()
    }
}

// Storage-compatibility tests for the fork-only `added_at` tail, exercised
// through *bincode* — the non-self-describing codec libxmtp actually persists
// with. The existing `past_secrets_storage_compatibility` KAT uses `serde_json`
// (self-describing), so it only covers the `visit_map` path; these cover the
// `visit_seq` / EOF-tolerant path that motivates the hand-written impl.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod bincode_storage_compat_tests {
    use super::{EpochTree, MessageSecretsStore};
    use crate::binary_tree::array_representation::LeafNodeIndex;
    use crate::group::mls_group::config::PastEpochDeletionPolicy;
    use crate::schedule::message_secrets::MessageSecrets;
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::types::Ciphersuite;
    use serde::Serialize;
    use std::collections::VecDeque;
    use std::time::SystemTime;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    fn secrets(rng: &RustCrypto, added_at: Option<SystemTime>) -> MessageSecrets {
        MessageSecrets::random(CIPHERSUITE, rng, LeafNodeIndex::new(0)).with_timestamp(added_at)
    }

    /// A new-format `MessageSecretsStore` round-trips through bincode, preserving
    /// the fork-only `added_at` timestamps carried on the trailing tail fields —
    /// both the current secrets and each past epoch.
    #[test]
    fn bincode_roundtrip_preserves_added_at() {
        let rng = RustCrypto::default();
        let mut store = MessageSecretsStore::new_with_secret(
            &PastEpochDeletionPolicy::KeepAll,
            secrets(&rng, None),
        );
        store.add_past_epoch_tree(0u64, secrets(&rng, None), Vec::new());
        store.add_past_epoch_tree(1u64, secrets(&rng, None), Vec::new());

        // Set known timestamps directly, bypassing the `SystemTime::now()` the
        // constructors stamp. Mix in a `None` so the parallel
        // `past_epoch_added_at` array is exercised on both a present and an
        // absent entry.
        let current = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let past0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000);
        store.message_secrets.added_at = Some(current);
        store.past_epoch_trees[0].message_secrets.added_at = Some(past0);
        store.past_epoch_trees[1].message_secrets.added_at = None;

        let bytes = bincode::serialize(&store).expect("serialize");
        let back: MessageSecretsStore = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(back.message_secrets.added_at, Some(current));
        assert_eq!(
            back.past_epoch_trees[0].message_secrets.added_at,
            Some(past0)
        );
        assert_eq!(back.past_epoch_trees[1].message_secrets.added_at, None);
    }

    /// Data written before `added_at` existed (openmls-0.7.x, as shipped in
    /// libxmtp 1.9/1.10) has only the three base fields under bincode. The
    /// trailing tail fields must read tolerantly — EOF -> `None`, not an error.
    #[test]
    fn bincode_tolerates_pre_added_at_layout() {
        let rng = RustCrypto::default();
        let store = MessageSecretsStore::new_with_secret(
            &PastEpochDeletionPolicy::KeepAll,
            secrets(&rng, Some(SystemTime::now())),
        );

        // The openmls-0.7.x on-disk shape: the three base fields only, no
        // trailing `added_at` / `past_epoch_added_at`. bincode is positional, so
        // this is byte-identical to what an older openmls wrote.
        #[derive(Serialize)]
        struct PreAddedAtLayout<'a> {
            max_epochs: usize,
            past_epoch_trees: &'a VecDeque<EpochTree>,
            message_secrets: &'a MessageSecrets,
        }
        let old_bytes = bincode::serialize(&PreAddedAtLayout {
            max_epochs: store.max_epochs,
            past_epoch_trees: &store.past_epoch_trees,
            message_secrets: &store.message_secrets,
        })
        .expect("serialize old layout");

        let back: MessageSecretsStore =
            bincode::deserialize(&old_bytes).expect("deserialize old layout");
        assert!(back.message_secrets.added_at.is_none());
    }
}
