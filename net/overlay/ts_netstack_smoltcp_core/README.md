# ts_netstack_smoltcp_core (netcore)

Command-channel-driven userspace network stack.

This is an opinionated wrapper around [`smoltcp`] that provides an easier-to-integrate,
more-portable API.

## Organization

This is the `core` crate, which just provides a [`Netstack`] type that contains the
required state and logic to drive the contained [`smoltcp::iface::Interface`] to process
commands received over a [`Channel`]. The ergonomic sockets API around the
remote end of that channel is provided by `ts_netstack_smoltcp_socket`.

The whole thing is integrated along with runtime functionality in `ts_netstack_smoltcp`.

## Motivation

- Usage of `smoltcp` sockets requires access to their backing
  [`SocketSet`][smoltcp::iface::SocketSet] (buffer storage). This functionally attaches
  them to the lifetime of that storage, meaning that synchronous access across threads
  would require passing around `Arc<Mutex<SocketSet>>` and grabbing locks everywhere
  that's used. Instead, this crate uses a channel-oriented approach, converting the
  socket function call API into a set of RPC-style request/response messages.

- Lack of direct integration with `async`: the command-channel paradigm means that this
  is straightforward in our implementation: a task or thread drives the netstack, and
  sockets enjoy asynchronous semantics by polling on channel sends and receives. Because
  the channel library we're using ([`flume`]) supports both sync and async operation,
  this means that sockets work naturally in sync contexts as well.

- Lack of features: `smoltcp` is a minimal core crate -- it doesn't provide TCP accept
  logic, any commitments re: allocation, a complete polling loop, garbage collection of
  closed TCP connections, or a way to block until e.g. a TCP connection is established.

## Example

```rust
extern crate ts_netstack_smoltcp_core as netcore;

use core::net::SocketAddr;
use bytes::Bytes;
use smoltcp::time::Instant;
use smoltcp::phy::Medium;
use netcore::{Response, udp, HasChannel};

fn main() -> Result<(), netcore::Error> {
    // Construct a new netstack:
    let mut stack = netcore::Netstack::new(netcore::Config::default(), Instant::ZERO);

    // Grab a channel through which we can send commands:
    let channel = stack.command_channel();

    // Process the upcoming bind and send commands in the background (request() blocks
    // for a response, hence the thread)
    let thread = std::thread::spawn(move || {
        for i in 0..2 {
            let cmd = stack.wait_for_cmd_blocking(None).unwrap();
            stack.process_one_cmd(cmd);
        }

        stack
    });

    // Send a command to bind a UDP socket:
    let endpoint = SocketAddr::from(([127, 0, 0, 1], 1000));
    let Response::Udp(udp::Response::Bound { handle, local }) = channel.request_blocking(None, udp::Command::Bind {
        endpoint
    })? else {
        unreachable!();
    };
    println!("bound udp socket to {local}");

    // Issue a command to send a UDP packet over the channel:
    channel.request_nonblocking(Some(handle), udp::Command::Send {
        endpoint: SocketAddr::from(([1, 2, 3, 4], 80)),
        buf: Bytes::copy_from_slice(b"hello"),
    })?;
    println!("sent udp packet");

    // Wait for the thread started above to finish processing the two UDP port commands:
    let mut stack = thread.join().unwrap();

    // Pump the netstack to produce the IP packet that needs to be sent out on the network:
    let (end1, end2) = netcore::Pipe::unbounded();
    stack.poll_device_io(Instant::ZERO, &mut netcore::PipeDev {
        pipe: end1,
        medium: Medium::Ip,
        mtu: 1500,
    });

    // Receive the packet from the pipe device:
    let packet = end2.rx.recv().unwrap();
    println!("packet: {packet:?}");

    // Sanity-check that the packet we got back is shaped correctly:
    assert_eq!(packet.len(), smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + b"hello".len());
    assert_eq!(packet[0] >> 4, 4); // ipv4 packet
    assert!(packet.ends_with(b"hello"));

    Ok(())
}
```

Compare the examples in `ts_netstack_smoltcp_socket` and `ts_netstack_smoltcp` (which
do the same thing as this example) for an indication of the abstraction that crate
provides.
