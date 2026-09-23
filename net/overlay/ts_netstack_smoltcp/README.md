# ts_netstack_smoltcp

Userspace netstack built as an opinionated wrapper around [`smoltcp`].

# Example

Compare the examples from [`ts_netstack_smoltcp_core`] and [`ts_netstack_smoltcp_socket`]:

```rust
#![cfg(feature = "std")]

extern crate ts_netstack_smoltcp as netstack;

use core::time::Duration;
use netstack::{netcore::smoltcp, HasChannel, CreateSocket};

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
