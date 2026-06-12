#![cfg(target_os = "macos")]

//! macOS-specific tests.
//!
//! Might expand to BSD later once the routed code is made more generic.

use nom::Parser;
use ts_netmon::bsd::net_table;

/// Sample captured from a mac using
/// [`DumpType::Interface2`][ts_netmon::bsd::net_table::DumpType::Interface2].
///
/// It has been scrubbed to randomize identifying info like IPv6 GUAs and MAC addresses – these may
/// not be sensical addresses, though they should be syntactically valid.
const SAMPLE_IFACE2: &[u8] = include_bytes!("macos_iface2.dat");

#[test]
fn iface2_chunks() {
    let (rest, result) = nom::multi::many0(net_table::msg_chunk())
        .parse_complete(SAMPLE_IFACE2)
        .unwrap();

    assert!(rest.is_empty());
    println!("n chunks: {}", result.len());
}

#[tracing_test::traced_test]
#[test]
fn iface2_msgs() {
    let (_, msgs) = nom::multi::many0(net_table::msg_chunk())
        .parse_complete(SAMPLE_IFACE2)
        .unwrap();

    for msg in msgs {
        let (rest, (ty, hdr)) = net_table::MessageHeader::parse(msg).unwrap();
        tracing::info!(?ty, ?hdr);

        let (rest, addrs) =
            nom::multi::many0(net_table::partial_sockaddr::<_, nom::error::Error<_>>())
                .parse_complete(rest)
                .unwrap();

        assert!(rest.is_empty());

        for addr in addrs {
            let addr = addr.unwrap();
            tracing::info!(?addr);
        }
    }
}
