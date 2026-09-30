use serde::Deserialize;

/// Encodes the control plane's view of Tailnet Key Authority (TKA) state. Transmitted as part of
/// a [`MapResponse`][crate::MapResponse] to a Tailscale node.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TkaInfo<'a> {
    /// Describes the hash of the latest Authority Update Message (AUM) applied to the authority.
    /// If this field differs from the locally-known value, the node should perform synchronization
    /// via a separate RPC.
    ///
    /// Encoded as a standard Base32 string with no padding; see `tka.AUMHash.MarshalText` in the
    /// Go codebase.
    #[serde(borrow)]
    pub head: &'a str,

    /// If `true`, indicates the control plane believes TKA should be disabled, and the node should
    /// fetch a disablement secret. If the disablement secret verifies, then the node should
    /// disable TKA locally.
    ///
    /// This field exists so a value of `None` in a
    /// [`MapResponse::tka_info`][crate::MapResponse::tka_info] in a delta update can
    /// mean "no change from previous value" rather than "disable TKA on this node".
    pub disabled: bool,
}
