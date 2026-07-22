//! Fork-owned storage-tag baseline.
//!
//! Upstream's `test_storage_tag_stability` pins our enums against *published*
//! openmls releases. The XMTP fork intentionally diverges on the persisted
//! `storage_tag` numbering of `ExtensionType` / `Extension`: `ImmutableMetadata`
//! occupies tag 6, which shifts `Unknown` / `Grease` / `AppDataDictionary` up by
//! one, so the fork keeps reading groups persisted by older fork releases. That
//! layout can never match a published crate, so rather than comparing against
//! one we pin the fork's numbering positively here.
//!
//! Only meaningful on the `storage_tag` path — the format libxmtp actually
//! persists. `compat_0_7_1` and `fork-baseline` build our `openmls` without
//! `0-8-1-storage-format`, so they exercise the `storage_tag` derive; the
//! `compat_0_8_1*` features build it positionally, which the upstream suite
//! already covers. (`0-8-1-storage-format` is an `openmls` feature, not one of
//! ours, so it cannot be named in a `cfg` here — we gate on our own features
//! that select the path instead.)
#![cfg(any(feature = "compat_0_7_1", feature = "fork-baseline"))]

use openmls::extensions::{Extension, ExtensionType, Metadata, UnknownExtension};
use openmls_compat_tests::storage_tag_check::StorageTags;

/// The `(variant_index, variant_name)` a value serializes to. `variant_index`
/// is the bincode/postcard wire tag; `variant_name` is the JSON/CBOR tag.
#[track_caller]
fn tag<T: serde::Serialize>(value: &T) -> (u32, &'static str) {
    let t = StorageTags::for_enum_variant(value).expect("value is an enum variant");
    (t.non_self_describing, t.self_describing)
}

#[test]
fn extension_type_fork_storage_tags() {
    // Tags 0-5 are shared with upstream and unchanged by the fork.
    assert_eq!(tag(&ExtensionType::ApplicationId), (0, "ApplicationId"));
    assert_eq!(tag(&ExtensionType::RatchetTree), (1, "RatchetTree"));
    assert_eq!(
        tag(&ExtensionType::RequiredCapabilities),
        (2, "RequiredCapabilities")
    );
    assert_eq!(tag(&ExtensionType::ExternalPub), (3, "ExternalPub"));
    assert_eq!(tag(&ExtensionType::ExternalSenders), (4, "ExternalSenders"));
    assert_eq!(tag(&ExtensionType::LastResort), (5, "LastResort"));
    // Fork divergence: ImmutableMetadata claims 6, pushing the rest up one.
    assert_eq!(
        tag(&ExtensionType::ImmutableMetadata),
        (6, "ImmutableMetadata")
    );
    assert_eq!(tag(&ExtensionType::Unknown(20)), (7, "Unknown"));
    assert_eq!(tag(&ExtensionType::Grease(0)), (8, "Grease"));
    #[cfg(feature = "fork-baseline")]
    assert_eq!(
        tag(&ExtensionType::AppDataDictionary),
        (9, "AppDataDictionary")
    );
}

#[test]
fn extension_fork_storage_tags() {
    // Same divergence on the payload-carrying `Extension` enum. Payload contents
    // are irrelevant to the tag probe; use the cheapest value for each variant.
    assert_eq!(
        tag(&Extension::ImmutableMetadata(Metadata::new(Vec::new()))),
        (6, "ImmutableMetadata")
    );
    assert_eq!(
        tag(&Extension::Unknown(20, UnknownExtension(Vec::new()))),
        (7, "Unknown")
    );
}
