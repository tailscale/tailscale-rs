//! Dump route tables on macOS.

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    use futures_util::StreamExt;
    use ts_netmon::bsd::{
        RouteSocket,
        net_table::{Address, MessageHeader},
    };
    use zerocopy::IntoBytes;

    #[derive(clap::Parser)]
    struct Args {}

    ts_cli_util::init_tracing();
    let _args = Args::parse();

    let sock = RouteSocket::new()?;
    let mut raw_stream = sock.raw_msg_stream();

    while let Some(msg) = raw_stream.next().await {
        let msg = msg?;

        let (rest, (ty, msg)) = MessageHeader::parse(msg.as_bytes())
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let mut iter = nom::combinator::iterator(rest, Address::parse::<_, nom::error::Error<_>>());

        let addrs = msg.addrs().into_iter().zip(&mut iter).collect::<Vec<_>>();
        iter.finish()
            .map_err(|e| e.to_string())
            .map_err(std::io::Error::other)?;

        tracing::info!(?ty, ?msg, ?addrs);
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("error: this example only runs on macOS")
}
