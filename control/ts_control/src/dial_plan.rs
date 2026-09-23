use core::{net::IpAddr, time::Duration};

use ts_control_serde::{ControlDialPlan, ControlIpCandidate};

/// A plan to connect to the control plane, supplied as part of a netmap update.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DialPlan {
    /// Use system DNS to resolve the control plane's IP address.
    #[default]
    UseDns,

    /// Use the contained plan to connect to the control plane.
    Plan(Vec<DialCandidate>),
}

/// A candidate endpoint for a control plane connection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DialCandidate {
    // NOTE(npry): field order in this struct is load-bearing for the PartialOrd derive.
    // The relevant initial tuple is (priority, start_delay_sec).
    /// The priority of this candidate.
    ///
    /// Higher priorities are preferred over lower ones.
    pub priority: usize,

    /// How long to delay before attempting to use this candidate.
    pub start_delay_sec: Duration,
    /// Timeout before giving up on this candidate.
    pub timeout: Duration,

    /// The mode with which to connect.
    pub mode: DialMode,
}

/// The mode with which to connect to the control plane.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DialMode {
    /// Connect directly via the indicated IP address (do not resolve using DNS).
    Ip(IpAddr),

    /// Connect to control over HTTPS using the proxy CONNECT method via the selected host.
    Ace {
        /// The hostname to connect to.
        ///
        /// This is always set as the HTTP request's `Host`.
        host: String,

        /// If present, the resolved address of the host to connect to.
        ip: Option<IpAddr>,
    },
}

impl From<ControlDialPlan<'_>> for DialPlan {
    fn from(value: ControlDialPlan<'_>) -> Self {
        (&value).into()
    }
}

impl TryFrom<ControlIpCandidate<'_>> for DialCandidate {
    type Error = ();

    fn try_from(value: ControlIpCandidate<'_>) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&ControlDialPlan<'_>> for DialPlan {
    fn from(value: &ControlDialPlan<'_>) -> Self {
        let mut plan_candidates = value
            .candidates
            .iter()
            .filter_map(|x| x.try_into().ok())
            .collect::<Vec<DialCandidate>>();

        // sort in decreasing priority order
        plan_candidates.sort_by(|a, b| a.cmp(b).reverse());

        if plan_candidates.is_empty() {
            DialPlan::UseDns
        } else {
            DialPlan::Plan(plan_candidates)
        }
    }
}

impl TryFrom<&ControlIpCandidate<'_>> for DialCandidate {
    type Error = ();

    fn try_from(value: &ControlIpCandidate<'_>) -> Result<Self, Self::Error> {
        let mode = if let Some(ace_host) = value.ace_host {
            DialMode::Ace {
                host: ace_host.to_string(),
                ip: value.ip,
            }
        } else if let Some(ip) = value.ip {
            DialMode::Ip(ip)
        } else {
            return Err(());
        };

        Ok(Self {
            mode,
            timeout: value.dial_timeout_sec,
            start_delay_sec: value.dial_start_delay_sec,
            priority: value.priority.clamp(0, 256) as _,
        })
    }
}
