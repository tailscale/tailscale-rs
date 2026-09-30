use crate::{FilterStorage, filter::FilterStorageExt};

/// Update `storage` with new rules on the basis of a `MapResponse`-style update.
///
/// `packet_filter` is the old-style `packet_filter` field, and `packet_filters` is the
/// `MapResponse::packet_filters` field as an iterator. `clear_storage` is
/// whether `storage` should be cleared after processing the `packet_filter` but
/// before processing `packet_filters`.
///
/// You most likely want the version of this function from `packetfilter_state`, which
/// is specialized to load the rules from a `MapResponse` (it calls this function
/// internally).
pub fn apply_update(
    storage: &mut dyn FilterStorage,
    packet_filter: Option<crate::Ruleset>,
    clear_storage: bool,
    packet_filters: &mut dyn Iterator<Item = (&str, Option<crate::Ruleset>)>,
) {
    // This implementation follows the instructions in the godoc in
    // `tailcfg.go:MapResponse`. If you are wondering why this does something a
    // certain way, check those docs first.

    if clear_storage {
        storage.clear();
    } else if let Some(ruleset) = packet_filter {
        // These would be processed _before_ the clear according to the go docs, so
        // don't even bother in that case.
        storage.insert(crate::DEFAULT_RULESET_NAME, ruleset);
    }

    let packet_filters = packet_filters.filter(|(k, v)| {
        let is_clear_rule = *k == crate::CLEAR_MAP_KEY && v.is_none();

        !is_clear_rule
    });

    for (ruleset_name, ruleset) in packet_filters {
        match ruleset {
            // "rule" => nil
            None => {
                storage.remove(ruleset_name);
            }
            // The empty ruleset acts like the key isn't even present (since filters are
            // grant-only, never deny), just remove the value
            Some(ruleset) if ruleset.is_empty() => {
                storage.remove(ruleset_name);
            }
            Some(ruleset) => {
                storage.insert(ruleset_name, ruleset);
            }
        }
    }
}
