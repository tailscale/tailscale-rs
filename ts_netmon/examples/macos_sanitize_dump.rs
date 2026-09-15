//! Sanitize a BSD route/interface dump by replacing all system IP and MAC addresses
//! with dummy values.
//!
//! Usage:
//!
//! ```shell
//! $ macos_dump_route -o dump.dat
//! $ macos_sanitize_dump < dump.dat > dump_san.dat
//! ```

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        collections::HashSet,
        io::{Read, Write, stdin, stdout},
        net::IpAddr,
    };

    use nom::{Parser, combinator::complete, multi::many0};
    use ts_netmon::bsd::Message;

    const FILL_BYTE: u8 = 0xb5;

    fn addr_octets(addr: &IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }

    ts_cli_util::init_tracing();

    let mut buf = vec![];
    stdin().read_to_end(&mut buf)?;

    let (_rest, msgs) = many0(complete(Message::parse))
        .parse_complete(&buf)
        .map_err(|e| format!("{e}"))?;
    let mut patterns = HashSet::new();

    for msg in msgs {
        if let Some(addr) = msg.dest_addr() {
            patterns.insert(addr_octets(&addr.addr()));
        }

        if let Some(addr) = msg.gateway() {
            patterns.insert(addr_octets(&addr));
        }

        if let Some(la) = msg.interface_name() {
            patterns.insert(la.addr);
        }

        if let Some(addr) = msg.interface_addr() {
            patterns.insert(addr_octets(&addr.addr()));
        }
    }

    patterns.retain(|x| {
        x.len() >= 4
            && !x.starts_with(&[0])
            && !x.iter().all(|b| *b == FILL_BYTE || *b == 0 || *b == 1)

            // Ignore broadcast address
            && x != &[0xff, 0xff, 0xff, 0xff]

            // Ignore ff01::, ff02::, ff00:: fe80::, fe80::1
            && x != (&[&[0xffu8, 0x02], &[0u8; 14][..]].concat())
            && x != (&[&[0xffu8, 0x01], &[0u8; 14][..]].concat())
            && x != (&[&[0xffu8], &[0u8; 15][..]].concat())
            && x != (&[&[0xfeu8, 0x80], &[0u8; 14][..]].concat())
            && x != (&[&[0xfeu8, 0x80], &[0u8; 13][..], &[1u8]].concat())
    });
    let mut patterns = patterns.into_iter().collect::<Vec<_>>();
    patterns.sort_by_key(|a| -(a.len() as isize));

    for pattern in &patterns {
        let mut pattern = pattern.as_slice();

        eprintln!("remove: {pattern:x?}");

        // Chop off fe80:$KAME?:0:0
        if pattern.starts_with(&[0xfe, 0x80]) && pattern[2..8] == [0; 6] {
            pattern = &pattern[8..];
            eprintln!("\ttruncate: {pattern:x?}");

            // If this was truncated before, it won't have been filtered out above, manually skip
            if pattern.iter().all(|x| x == &FILL_BYTE || x == &0) {
                continue;
            }
        }

        let finder = bstr::Finder::new(pattern);

        while let Some(x) = finder.find(&buf) {
            buf[x..x + pattern.len()].fill(FILL_BYTE);
        }
    }

    stdout().write_all(&buf)?;

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("error: this example only runs on macOS")
}
