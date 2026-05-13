use std::collections::{HashMap, VecDeque};

#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;
#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

impl EpochTree {
    #[cfg(test)]
    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.message_secrets.timestamp()
    }
}

// Internal helper struct.
//
// Wire layout (bincode/postcard positional) — IDENTICAL to upstream
// openmls 0.7.x/0.8.x:
//
//   epoch:           u64
//   message_secrets: MessageSecrets   (five upstream fields)
//   leaves:          Vec<Member>
//
// IMPORTANT: do not add fields here. `EpochTree` is stored inside a
// `VecDeque<EpochTree>` in `MessageSecretsStore`, so it is NOT at the tail of
// the byte stream — a tolerantly-read trailing field would consume bytes from
// the next `EpochTree` (or from a sibling field of the outer struct). Any
// fork-only per-epoch metadata is carried in a parallel array on
// `MessageSecretsStore` instead (see `past_epoch_added_at`).
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
/// Persisted on-disk format. Wire layout (bincode/postcard positional):
///
///   max_epochs:           usize        (upstream — bincode native usize)
///   past_epoch_trees:     VecDeque<EpochTree>
///   message_secrets:      MessageSecrets   (five upstream fields)
///   added_at:             Option<SystemTime>           ← fork-only tail
///   past_epoch_added_at:  Vec<Option<SystemTime>>      ← fork-only tail
///
/// Both fork-only trailing fields are read tolerantly: missing-at-EOF or any
/// deserialize error is treated as "absent" and replaced with `None`/empty.
/// This is safe because they are at the END of the struct, so misreads cannot
/// consume bytes belonging to siblings. On deserialize, `added_at` is
/// re-hydrated onto `message_secrets.added_at` and `past_epoch_added_at`
/// entries onto each `past_epoch_trees[i].message_secrets.added_at` so the
/// rest of the codebase sees timestamps on `MessageSecrets` as before.
///
/// On serialize, `past_epoch_added_at` length always matches
/// `past_epoch_trees.len()` (padded with `None` if a tree was added before
/// any timestamp logic touched it).
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    pub(crate) max_epochs: usize,
    past_epoch_trees: VecDeque<EpochTree>,
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
        // Tolerant tail #1: `added_at` for current message_secrets.
        let added_at = seq
            .next_element::<Option<SystemTime>>()
            .unwrap_or(None)
            .flatten();
        message_secrets.added_at = added_at;
        // Tolerant tail #2: per-past-epoch timestamps.
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

    #[cfg(test)]
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
