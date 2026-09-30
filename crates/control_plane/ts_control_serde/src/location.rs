/// Represents geographical location data about a Tailscale node. Location is optional and only set
/// if explicitly declared by a node.
#[serde_with::apply(
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
     _ => #[serde(default)],
)]
#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Location<'a> {
    /// User friendly country name, with proper capitalization (e.g. "Canada").
    pub country: &'a str,
    /// ISO 3166-1 alpha-2 in upper case (e.g. "CA").
    pub country_code: &'a str,
    /// User friendly city name, with proper capitalization (e.g. "Squamish").
    pub city: &'a str,
    /// A short code representing the city in upper case. Used to disambiguate a city from
    /// another location with the same city name. It uniquely identifies a particular
    /// geographical location within the same Tailnet.
    ///
    /// IATA, ICAO or ISO 3166-2 codes (e.g. "YSE") are recommended.
    pub city_code: &'a str,
    /// The optional geographical latitude coordinate of the node, in degrees. No particular
    /// accuracy level is promised; the coordinates may simply be the center of the city or
    /// country.
    pub latitude: Option<f64>,
    /// The optional geographical longitude coordinate of the node, in degrees. No particular
    /// accuracy level is promised; the coordinates may simply be the center of the city or
    /// country.
    pub longitude: Option<f64>,
    /// Determines the order of use of an exit node when a location-based preference matches
    /// more than one exit node. The exit node with the highest-priority location wins. Nodes of
    /// equal probability may be selected arbitrarily.
    ///
    /// A value of 0 means the exit node does not have a priority preference.
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub priority: usize,
}
