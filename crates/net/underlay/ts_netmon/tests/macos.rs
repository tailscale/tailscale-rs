//! macOS-specific tests.
//!
//! Might expand to BSD later once the code is made more generic.

#![cfg(target_os = "macos")]

use nom::{Parser, combinator::complete};
use ts_netmon::{
    FamilyOrBoth,
    bsd::{
        Message, net_table,
        net_table::{DumpType, MessageHeader},
    },
};

/// Sample captured from a mac using
/// [`DumpType::Interface2`][ts_netmon::bsd::net_table::DumpType::Interface2].
///
/// It has been scrubbed to randomize identifying info like IPv6 GUAs and MAC addresses – these may
/// not be sensical addresses, though they should be syntactically valid.
const SAMPLE_IFACE2: &[u8] = include_bytes!("macos_if2_san.dat");

/// Sample captured from a mac using
/// [`DumpType::Interface`][ts_netmon::bsd::net_table::DumpType::Interface].
///
/// It has been scrubbed to randomize identifying info like IPv6 GUAs and MAC addresses – these may
/// not be sensical addresses, though they should be syntactically valid.
const SAMPLE_IFACE: &[u8] = include_bytes!("macos_if_san.dat");

/// Sample captured from a mac using
/// [`DumpType::Route2`][ts_netmon::bsd::net_table::DumpType::Route2].
///
/// It has been scrubbed to randomize identifying info like IPv6 GUAs and MAC addresses – these may
/// not be sensical addresses, though they should be syntactically valid.
const SAMPLE_ROUTE2: &[u8] = include_bytes!("macos_rt2_san.dat");

/// Sample captured from a mac using
/// [`DumpType::Route`][ts_netmon::bsd::net_table::DumpType::Route].
///
/// It has been scrubbed to randomize identifying info like IPv6 GUAs and MAC addresses – these may
/// not be sensical addresses, though they should be syntactically valid.
const SAMPLE_ROUTE: &[u8] = include_bytes!("macos_rt_san.dat");

const ALL_SAMPLES: &[(&str, &[u8])] = &[
    ("route2", SAMPLE_ROUTE2),
    ("route", SAMPLE_ROUTE),
    ("iface2", SAMPLE_IFACE2),
    ("iface", SAMPLE_IFACE),
];

/// Verify that deframing all the messages in the dumps comes out cleanly.
#[test]
fn chunks() {
    for (name, sample) in ALL_SAMPLES {
        let (rest, result) = nom::multi::many0(complete(net_table::msg_chunk()))
            .parse_complete(*sample)
            .unwrap();

        assert!(
            rest.is_empty(),
            "{name} did not parse completely ({} bytes remaining)",
            rest.len()
        );
        println!("{name}: n chunks: {}", result.len());
    }
}

#[tracing::instrument(skip_all, fields(name = %_name))]
#[track_caller]
fn assert_parse_internal(_name: &str, sample: &[u8]) {
    let (_, msgs) = nom::multi::many0(complete(net_table::msg_chunk()))
        .parse_complete(sample)
        .unwrap();

    for msg in msgs {
        let (rest, (ty, hdr)) = MessageHeader::parse(msg).unwrap();
        tracing::info!(?ty, ?hdr);

        let (rest, addrs) = nom::multi::many0(complete(net_table::Address::parse::<
            _,
            nom::error::Error<_>,
        >()))
        .parse_complete(rest)
        .unwrap();

        assert!(rest.is_empty());

        for addr in addrs {
            let addr = addr.unwrap();
            tracing::info!(addr = ?format_args!("{addr:x?}"));
        }
    }
}

#[tracing_test::traced_test]
#[test]
fn parse_internal() {
    for (name, msg) in ALL_SAMPLES {
        assert_parse_internal(name, msg);
    }
}

#[tracing::instrument(skip_all, fields(name = %_name))]
#[track_caller]
fn assert_parse_messages(_name: &str, sample: &[u8]) {
    let (_, _msgs) = nom::multi::many0(complete(Message::parse))
        .parse_complete(sample)
        .unwrap();
}

#[tracing_test::traced_test]
#[test]
fn parse_full() {
    for (name, sample) in ALL_SAMPLES {
        assert_parse_messages(name, sample);
    }
}

/// Live dump should also work, though unpredictable.
#[tracing_test::traced_test]
#[test]
fn dump() {
    for ty in DumpType::all() {
        let dump = net_table::dump(FamilyOrBoth::Both, *ty, 0).unwrap();
        assert_parse_messages(&format!("dump_{ty:?}"), &dump);
    }
}
