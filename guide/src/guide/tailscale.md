# Tailscale


[Tailscale](https://tailscale.com/) is a zero-trust, identity-based connectivity platform that replaces your legacy VPN, SASE, and PAM and connects remote teams, multi-cloud environments, CI/CD pipelines, Edge & IoT devices, and AI workloads. It enables encrypted point-to-point connections using the open source WireGuard protocol, which means only devices on your private network can communicate with each other.

Tailscale creates a peer-to-peer mesh network (known as a *tailnet*). However, you can still use Tailscale like a traditional VPN by routing all traffic through an exit node (not supported in tailscale-rs).

Some key advantages of Tailscale include secure and private connections between devices, a flexible network topology, and a streamlined setup. Tailscale is also cross-platform, infrastructure agnostic, and highly configurable. 

TODO: How it works

- [docs](https://tailscale.com/docs)
- [glossary](https://tailscale.com/docs/reference/glossary)

Tailscale is largely [open source](https://tailscale.com/opensource). The core client (mostly written in Go), some GUIs, the DERP server, and tailscale-rs (a Tailscale client library written in Rust) are open source, the coordination server, some GUIs, and some tools/products built on top of the Tailscale are not. You can find the code for the core client on [GitHub](https://github.com/tailscale/tailscale). Tailscale financially supports [Wireguard](https://www.wireguard.com/), [Let's Encrypt](https://letsencrypt.org/), and other projects and maintainers which Tailscale depends on.


## Core concepts

TODO

- tailnet
- nodes
- names, ids, addresses
- control plane and data plane
- control server
- auth key
- NATs and nat traversal
- derp and direct connections
- DNS stuff
- exit nodes?
- ...

## Tailscale clients

TODO

- What a client is/does
- The main (Go) client, tailscale demon, etc. Open source
- Tools based on Tailscale
- ts.net, libtailscale


## tailscale.rs

TODO

- in-process, stand-alone library for implementing Tailscale clients
- Rust + other languages
- a tailscale.rs client is just another client on the tailnet
