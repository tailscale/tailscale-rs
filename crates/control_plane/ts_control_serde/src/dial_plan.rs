use alloc::vec::Vec;
use core::{net::IpAddr, time::Duration};

use serde::Deserialize;

/// Instructions from the control server to a Tailscale node on how to connect to the control
/// server. Used to maintain connection if the node's network state changes after the initial
/// connection, or if the control server pushes other changes to the node (such as DNS config
/// updates) that break connectivity.
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ControlDialPlan<'a> {
    /// The list of candidate IP addresses this Tailscale node should use to reach the control
    /// server. An empty list means the node should use any DNS resolver available to discover the
    /// control server's IP address.
    #[serde(borrow)]
    pub candidates: Vec<ControlIpCandidate<'a>>,
}

/// Represents a single candidate IP address to attempt a connection to the control server.
#[serde_with::serde_as]
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename = "ControlIPCandidate", rename_all = "PascalCase", default)]
pub struct ControlIpCandidate<'a> {
    /// If populated, the IP address of the control server to attempt a connection to.
    #[serde(rename = "IP")]
    pub ip: Option<IpAddr>,

    /// If populated, indicates this Tailscale node should connect to the control plane using an
    /// HTTPS CONNECT request to the given hostname. If [`ControlIpCandidate::ip`] is also
    /// populated, [`ControlIpCandidate::ip`] is the IP address of the
    /// [`ControlIpCandidate::ace_host`] (not the control server) and DNS should NOT be used to
    /// look up the IP address of the ACE host.
    ///
    /// ACE requires the hostname even if an IP address is provided because the hostname is a
    /// required part of an HTTPS CONNECT request to the control plane.
    #[serde(rename = "ACEHost", borrow)]
    pub ace_host: Option<&'a str>,

    /// Number of seconds this Tailscale node should wait between starting the overall control
    /// plane connection process, and attempting to connect to this candidate control server.
    ///
    /// This value allows the control plane to spread individual connection attempts from the
    /// same node out over time.
    #[serde_as(as = "serde_with::DurationSeconds<f64>")]
    pub dial_start_delay_sec: Duration,

    /// Number of seconds this Tailscale node should wait for a response from this candidate
    /// control server before considering it unreachable (timing out).
    ///
    /// The node should start this timer when it starts attempting to connect to this particular
    /// candidate control server.
    #[serde_as(as = "serde_with::DurationSeconds<f64>")]
    pub dial_timeout_sec: Duration,

    /// The relative priority of this candidate control server compared to other candidates.
    /// Candidates with a numerically higher priority are preferred over candidates with a lower
    /// priority; in other words, a candidate with a priority of `256` is preferred over a
    /// candidate with a priority of `1`.
    pub priority: i64,
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_SAMPLE: &str = r#"{
      "Candidates": [
        {
          "IP": "2606:b740:49::114",
          "DialTimeoutSec": 10,
          "Priority": 5
        },
        {
          "IP": "192.200.0.114",
          "DialStartDelaySec": 0.3,
          "DialTimeoutSec": 10,
          "Priority": 5
        },
        {
          "IP": "2606:b740:49::101",
          "DialStartDelaySec": 0.55,
          "DialTimeoutSec": 10,
          "Priority": 4
        },
        {
          "IP": "192.200.0.101",
          "DialStartDelaySec": 0.8,
          "DialTimeoutSec": 10,
          "Priority": 4
        },
        {
          "IP": "2606:b740:49::103",
          "DialStartDelaySec": 1.05,
          "DialTimeoutSec": 10,
          "Priority": 3
        },
        {
          "IP": "192.200.0.103",
          "DialStartDelaySec": 1.3,
          "DialTimeoutSec": 10,
          "Priority": 3
        },
        {
          "IP": "2606:b740:49::113",
          "DialStartDelaySec": 1.55,
          "DialTimeoutSec": 10,
          "Priority": 2
        },
        {
          "IP": "192.200.0.113",
          "DialStartDelaySec": 1.8,
          "DialTimeoutSec": 10,
          "Priority": 2
        },
        {
          "IP": "192.200.0.113",
          "ACEHost": "abc.def.com",
          "DialStartDelaySec": 1.8,
          "DialTimeoutSec": 10,
          "Priority": 2
        },
        {
          "ACEHost": "abc.def.com",
          "DialStartDelaySec": 1.8,
          "DialTimeoutSec": 10,
          "Priority": 2
        }
      ]
    }"#;

    #[test]
    fn dial_plan() {
        let dial_plan = serde_json::from_str::<ControlDialPlan>(TEST_SAMPLE).unwrap();

        assert_eq!(10, dial_plan.candidates.len());
        for candidate in dial_plan.candidates {
            assert!(candidate.ip.is_some() || candidate.ace_host.is_some());
        }
    }
}
