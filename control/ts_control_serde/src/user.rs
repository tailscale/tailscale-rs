use chrono::{DateTime, Utc};
use serde::Deserialize;
use url::Url;

/// A unique integer ID for a [`Login`]. This is not used by Tailscale node software, but is used
/// in the control plane.
pub type LoginId = i64;

/// A unique integer ID for a [`User`].
pub type UserId = i64;

/// Represents a [`User`] from a specific identity provider (IdP), not associated with any
/// particular Tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Login<'a> {
    /// The unique integer ID of this login. Unused on the Tailscale node-side, but used by the
    /// control plane.
    #[serde(rename = "ID")]
    pub id: LoginId,
    /// A string representation of the IdP itself, e.g. "google", "github", "okta_foo", etc.
    #[serde(borrow)]
    pub provider: &'a str,
    /// An email address or "email-ish" string (e.g. "alice@github") associated with this Tailscale
    /// user, according to the IdP.
    #[serde(borrow)]
    pub login_name: &'a str,
    /// If populated, the display name of this Tailscale user, according to the IdP. Can be
    /// overridden by a value in the [`User::display_name`] field.
    #[serde(borrow, default)]
    pub display_name: Option<&'a str>,
    /// If populated, a URL to a profile picture representing this Tailscale user, according to the
    /// IdP. Can be overridden by a value in the [`User::profile_pic_url`] field.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
}

/// A Tailscale user.
///
/// A [`User`] can have multiple [`Login`]s associated with it (e.g. gmail and github oauth),
/// although as of 2019, none of the UIs support this.
///
/// Some fields are inherited from the [`Login`]s and can be overridden, such as
/// [`User::display_name`] and [`User::profile_pic_url`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User<'a> {
    /// The unique integer ID of this Tailscale user.
    #[serde(rename = "ID")]
    pub id: UserId,
    /// If populated, the display name of this Tailscale user. Overrides the value in any IdP-
    /// provided [`Login::display_name`] field.
    #[serde(borrow, default)]
    pub display_name: Option<&'a str>,
    /// If populated, a URL to a profile picture representing this Tailscale user. Overrides the
    /// IdP-provided value in any [`Login::profile_pic_url`] field.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
    /// The date and time that this Tailscale user was created, in the UTC timezone.
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
}

/// Display-friendly data for a [`User`]. Includes the [`Login::login_name`] for display purposes.
/// but *not* the [`Login::provider`]. Also includes derived data from one of the [`Login`]s
/// associated with a [`User`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile<'a> {
    /// The unique integer ID of this Tailscale user this [`UserProfile`] is associated with.
    #[serde(rename = "ID")]
    pub id: UserId,
    /// An email address or "email-ish" string (e.g. "alice@github") associated with this Tailscale
    /// user's [`UserProfile`], according to the IdP. For display purposes only.
    #[serde(borrow, default)]
    pub login_name: &'a str,
    /// If populated, the display name of this Tailscale user (e.g. "Alice Smith"), according to
    /// the IdP.
    #[serde(borrow, default)]
    pub display_name: Option<&'a str>,
    /// If populated, a URL to a profile picture representing this Tailscale user.
    #[serde(
        rename = "ProfilePicURL",
        deserialize_with = "crate::util::deserialize_string_option",
        default
    )]
    pub profile_pic_url: Option<Url>,
}
