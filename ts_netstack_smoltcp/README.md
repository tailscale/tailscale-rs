# ts_netstack_smoltcp

Userspace netstack built as an opinionated wrapper around [`smoltcp`].

# Example

NB: compare the examples from [`netcore`] and [`netsock`]:

```rust
#![cfg(feature = "std")]

extern crate ts_netstack_smoltcp as netstack;

use core::time::Duration;
use netstack::{smoltcp, HasChannel, CreateSocket};

fn main() {
    let (mut stack, mut pipe) = netstack::piped(Default::default());
    let command_channel = stack.command_channel();

    // Run the netstack in the background to process the socket commands:
    stack.spawn_threaded(Duration::from_millis(10));

    // Bind a socket and send a packet:
    let sock = command_channel.udp_bind_blocking(([127, 0, 0, 1], 1000).into()).unwrap();
    sock.send_to_blocking(([1, 2, 3, 4], 80).into(), b"hello");

    // Receive the packet from the pipe device:
    let packet = pipe.rx.recv().unwrap();
    println!("packet: {packet:?}");

    // Sanity-check that the packet we got back is shaped correctly:
    assert_eq!(packet.len(), smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + b"hello".len());
    assert_eq!(packet[0] >> 4, 4); // ipv4 packet
    assert!(packet.ends_with(b"hello"));
}
```

# Crate layout

The core netstack is implemented in [`netcore`]. This is a minimal channel-based command API. It
doesn't provide ergonomic socket types, just the commands to manipulate them.

[`netsock`] provides a sockets implementation around [`netcore`], i.e. it has `UdpSocket`, 
`TcpStream`, etc. types.

The top-level crate namespace provides [`Netstack`], which is essentially a runner that adapts a
[`smoltcp::phy::Device`] onto the core logic and exposes the methods required to construct the
sockets from [`netsock`].

The crate is laid out this way to allow users to replace components if desired. [`netcore`] has no
knowledge of and does not depend on any of the internals of [`netsock`]; ditto from [`netsock`] to
the root crate.
