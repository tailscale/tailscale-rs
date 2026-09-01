A secure packet tunnel over UDP.

This crate implements _part_ of [WireGuard](https://www.wireguard.com/), specifically the handshake cryptography and
general session lifecycle of an endpoint communicating to multiple peers.

DO NOT USE THIS CRATE if you are looking for a complete WireGuard implementation. This is a building block that lacks
several of WireGuard's security properties and features, which _you_ must provide. If you're looking for a
complete implementation, please consult [the WireGuard website](https://www.wireguard.com) for up-to-date documentation
on available implementations and how to use them.

## Sans I/O

This crate is implemented in the [Sans I/O](https://sans-io.readthedocs.io/) style: an `Endpoint` can process packets
that are provided to it, but it does not juggle network sockets or perform any I/O itself. The caller feeds packet bytes
into an `Endpoint`, and gets back a set of actions that it should perform (e.g. deliver decrypted packets to the local
system, transmit encrypted packets to a peer, schedule a timeout callback).

This separation decouples the protocol's state machine from the minutia of performing I/O, and allows the caller to
select the appropriate I/O strategy for their needs (e.g. std::thread, tokio, embassy, pcap replay, in-memory unit
tests).

## Security limitations

The code in this crate has been reviewed by third-party security experts. However, it's still relatively young code
that's still being worked on, so depending on your comfort level you may want to conduct your own evaluation.

As stated above, this crate by itself is NOT a complete implementation of WireGuard, and should not be used as one.

In particular, this crate operates on packets with no awareness of IP protocols. Packets are opaque byte sequences to
be encrypted/decrypted/queued/dropped as specified by the session and handshake state machines. This means that this
crate does not implement aspects of WireGuard that requires awareness of IP networking. These aspects must be provided
by the caller to be a complete implementation of the protocol:

### Cryptokey routing

A complete WireGuard implementation enforces a 1:1 association between an IP address and a peer's cryptographic
identity: received packets must be sourced from an allowed IP of the sending peer, and transmitted packets are
automatically routed to the correct peer based on destination IP.

This crate does _not_ enforce this unique association. The caller tags packets to be sent with the destination peer ID,
and received packets are similarly tagged with the originating peer ID. It is up to the caller to select the correct
peer when sending, and to validate the source IP when receiving.

### Packet padding

A complete WireGuard implementation pads cleartext packets before encryption, to complicate traffic analysis.

This crate does not handle packet padding. It is the caller's responsibility to pad outgoing packets appropriately,
and to strip any padding from received packets from peers. The padding removal in particular requires parsing received
IP datagrams to find what the correct packet length should be.

### Underlay addressing & roaming

A complete WireGuard implementation tracks the underlay IP address for each peer, so that it knows where on the internet
to send handshakes and encapsulated packets. Additionally, it allows the peer to roam to a new address mid-session, by
remembering the last endpoint address from which a valid message was received, and transmitting future packets to that
address.

This crate does not deal with underlay networking in any way. Wire messages to be sent are tagged by destination peer
ID, and it is up to the caller to track endpoint location and deliver the packet appropriately. This is a useful
separation of concerns for Tailscale, since we provide more complex underlay network routing with additional features
(e.g. path discovery with NAT traversal, fallback relaying through DERP) that should be kept separate from the core
cryptographic state machines.