use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {
    type Addr;
}

impl ProxyStream for tokio::fs::File {
    type Addr = PathBuf;
}

impl<A> ProxyStream for Box<dyn ProxyStream<Addr = A>> {
    type Addr = A;
}
