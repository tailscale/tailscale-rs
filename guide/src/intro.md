# Introduction

tailscale-rs is a work-in-progress [Tailscale](https://tailscale.com) library written in Rust, with language bindings to C, Elixir, and Python.

> [!NOTE]
> This software is under active development. See caveats in the [overview](guide/overview.md) for more details.

Tailscale creates a peer-to-peer mesh network (known as a *tailnet*). It enables encrypted point-to-point connections using the open-source WireGuard protocol. Tailscale has multiple options for NAT traversal,  a network control plane, and many extension features.

tailscale-rs is a Rust library for implementing Tailscale clients. It supports connecting to a tailnet and communicating with other nodes. tailscale-rs offers multi-language support, currently supported languages are Rust, C/C++, Python, and Elixir. tailscale-rs is designed to be flexible and configurable, but also easy to use: the details of the implementation such as protocols and cryptography are purely internal. tailscale-rs includes implementations of TCP and UDP sockets which allow it to be slotted-in as the networking layer under many applications and frameworks.

tailscale-rs is intended to be industrial-strength, suitable for adding Tailscale support to production software. Our goals are to be:

- secure,
- performant,
- interoperable with other Tailscale clients,
- support many languages,
- be high-quality, bug-free software.

The project is in active development and currently making progress towards those goals.


## About this guide

This guide should get you started with tailscale-rs and help you understand it in depth. We don't assume any prior knowledge of Tailscale, but do assume you are familiar with [Rust](https://doc.rust-lang.org/book/) and networking fundamentals.

The [Getting started](getting-started.md) chapter will get you up and going with tailscale-rs, it covers installing tailscale-rs and a quickstart guide.

The rest of the guide is in two parts: the 'guide' section is a tutorial intended to be read mostly in order. The 'reference' section contains chapters which either cover specialist topics which most users won't need to know, or chapters you might want to dip in and out of.

- If you're new to Tailscale, start with the [Tailscale](guide/tailscale.md) chapter.
- If you're familiar with Tailscale and want to find out about tailscale-rs, see the [overview of tailscale-rs](guide/overview.md) and the [examples]().
- For language support, see [using tailscale-rs from other languages]().
- To help solve problems, the [API docs]() or [FAQ](reference/faq.md) might be useful.
- For details on the project status and future plans, see [supported features and future roadmap](reference/roadmap.md).
- For information on the internals of tailscale-rs, see the [Architecture]() chapter.


## Quick links

- tailscale-rs on [crates.io](https://crates.io/crates/tailscale).
- API docs on [docs.rs](https://docs.rs/tailscale).
- Source code on [GitHub](https://github.com/tailscale/tailscale-rs).


## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
