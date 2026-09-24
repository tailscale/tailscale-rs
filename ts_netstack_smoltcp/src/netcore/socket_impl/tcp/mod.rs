use alloc::vec;

use smoltcp::socket::tcp;

use crate::netcore;

mod listener;
mod stream;

pub use listener::{ListenerHandle, TcpListenerState};

impl netcore::Netstack {
    fn tcp_buffer(&self) -> tcp::SocketBuffer<'static> {
        tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size])
    }
}
