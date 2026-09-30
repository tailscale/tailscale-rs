use alloc::vec::Vec;

use crate::{Filter, FilterStorage, PacketInfo, Rule, filter::CapIter};

/// A [`Filter`] that uses `Primary` to enforce filter rules, but checks the output of
/// `Checked` against `Primary`'s results.
///
/// Intended to be used as a tool for validation of a new filter in a live system.
#[derive(Debug, Copy, Clone, Default)]
pub struct CheckingFilter<Primary, Checked>(pub Primary, pub Checked);

impl<Primary, Checked> Filter for CheckingFilter<Primary, Checked>
where
    Primary: Filter,
    Checked: Filter,
{
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        let caps = caps.collect::<Vec<_>>();

        let result = self.0.match_for(info, &mut caps.iter().copied());
        let checked_result = self.1.match_for(info, &mut caps.iter().copied());

        if result != checked_result {
            tracing::warn!(
                ?result, ?checked_result,
                ?info, ?caps,
                primary_filter = %core::any::type_name::<Primary>(),
                checked_filter = %core::any::type_name::<Checked>()
            );
        }

        result
    }

    fn matches(&self, info: &PacketInfo, caps: CapIter) -> bool {
        let caps = caps.collect::<Vec<_>>();

        let result = self.0.matches(info, &mut caps.iter().copied());
        let checked_result = self.1.matches(info, &mut caps.iter().copied());

        if result != checked_result {
            tracing::warn!(
                ?result, ?checked_result,
                ?info, ?caps,
                primary_filter = %core::any::type_name::<Primary>(),
                checked_filter = %core::any::type_name::<Checked>()
            );
        }

        result
    }
}

impl<Primary, Checked> FilterStorage for CheckingFilter<Primary, Checked>
where
    Primary: FilterStorage,
    Checked: FilterStorage,
{
    fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>) {
        let v = ruleset.collect::<Vec<_>>();

        self.0.insert_dyn(name, &mut v.iter().cloned());
        self.1.insert_dyn(name, &mut v.into_iter());
    }

    fn remove(&mut self, name: &str) {
        self.0.remove(name);
        self.1.remove(name);
    }

    fn clear(&mut self) {
        self.0.clear();
        self.1.clear();
    }
}
