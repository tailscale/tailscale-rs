# Supported features and future roadmap

`tailscale-rs` is a work-in-progress. We're still rapidly iterating, fixing bugs, and adding new features.
We aim to keep this section up-to-date, but our [issue tracker](https://github.com/tailscale/tailscale-rs/issues) is the
best way to see the latest updates.

## Implemented features

These are features that we currently implement:

- Basics
    - Create TCP and UDP sockets on the tailnet
    - Communicate with peers via public DERP relays
    - Communicate with peers via direct connections in many cases
    - Communicate with the Tailscale Go client, `tsnet`, and `libtailscale`
- Language support
    - Rust API
    - C, Elixir, and Python bindings

## Coming Soon

These are features or efforts we have in the pipeline and are actively working towards, but provide no guarantees on
timeline or completion:

- DNS forwarding
- Integrations with more HTTP client/server libraries
- Peer lookups (addressing peers by hostname)
- Port mapping

## Unsupported

This is an incomplete list of features in the Tailscale Go client, `tsnet`, and/or `libtailscale`
that we currently *do not* support. We'd like to add all of these eventually! If there's something on this list you'd
like to see supported, or something _not_ on this list you're not sure about, please open an issue!

Unsupported features:

- Networking
    - Peer relays
    - Exit Nodes (either being one, or using one)
    - MagicDNS
    - Private DERP relays
    - Split DNS
    - Subnet Routers (either being one, or using one)
- Platforms
    - AIX
    - Android
    - BSDs
    - iOS
    - Plan9
    - QNAP
    - Synology DSM
- Observability
    - Client Metrics
    - Endpoint Collection
    - Device Posture Collection
    - Log Streaming
    - Network Flow Logs
- Other Features
    - Application Capabilities
    - Automatic Key Rotation
    - HTTPS Certificates
    - Kubernetes
    - Mullvad VPN
    - Node Sharing
    - Taildrive
    - Taildrop
    - Tailnet Lock
    - Tailscale Funnel
    - Tailscale Serve
    - Tailscale SSH
    - Tailscale Services
    - Webhooks
- Any other features not listed in previous sections.
