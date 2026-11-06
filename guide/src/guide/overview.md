# Overview of tailscale-rs

TODO

- What it is and does. Features/capabilities
- Rust, other languages
- optional extras: axum http, ssh
- use cases and good possible applications

Some details:

- async and Tokio (API and implementation)
- supported platforms
- nostd/embedded status
- MSRV
- versioning, compatibility

## Project status

tailscale-rs is a work-in-progress. We're still rapidly iterating, fixing bugs, and adding new features.
We aim to keep this section up-to-date, but our [issue tracker](https://github.com/tailscale/tailscale-rs/issues) is the
best way to see the latest updates.

### Important caveats

This software is still a work-in-progress! We are providing it in the open at this stage out of a belief in open-source
and to see where the community runs with it, but please be aware of a few important considerations:

- There are no compatibility guarantees at the moment. We may break dependent code in order to get things right,
  although we will try to avoid doing so gratuitously.
- Direct connections via NAT traversal is a work in progress. Communication may fall back to DERP relaying in more
  cases, with a corresponding hit to latency and throughput.
- Core networking functionality is implemented. Many other features are still either in progress or not implemented yet.
  See [features and roadmap](../reference/roadmap.md) for more details. 

We encourage you to experiment with this library and build things with it, as long as you're okay with these caveats.

## Key concepts

TODO

short explanations, links to chapters:

- lifecycle, auth
- tailnet and nodes
- keys and configuration
- netstack (TCP and UDP)
- HTTP/axum
- SSH
- build options

Internals:

- architecture (very brief overview and link to chapter)
- developing and contributing (link to issues and what we want/don't want, how to build, link to doc)
