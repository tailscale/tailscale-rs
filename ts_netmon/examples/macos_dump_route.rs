#![cfg(target_os = "macos")]

//! Dump route tables on macOS.

use std::{io::Read, path::PathBuf};

use clap::Parser;
use nom::combinator::ParserIterator;
use ts_netmon::{
    FamilyOrBoth,
    bsd::{
        net_table,
        net_table::{DumpType, partial_sockaddr},
    },
};

#[derive(clap::Parser)]
struct Args {
    /// Rather than querying the OS for a RIB, read the file instead.
    #[arg(short = 'i', long, conflicts_with_all = ["out_file", "interface2", "interface", "route2", "route"])]
    in_file: Option<PathBuf>,

    /// Write out the RIB data received from the OS to the specified file.
    #[arg(short = 'o', long, conflicts_with("in_file"))]
    out_file: Option<PathBuf>,

    #[command(flatten)]
    ty: Ty,
}

#[derive(clap::Args, Debug)]
#[group(multiple = false)]
struct Ty {
    /// Fetch the IFMIB in `NET_RT_IFLIST2` format.
    #[clap(long = "if2")]
    interface2: bool,

    /// Fetch the IFMIB in `NET_RT_IFLIST` format.
    #[clap(long = "if")]
    interface: bool,

    /// Fetch the RIB in `NET_RT_DUMP2` format.
    #[clap(long = "rt2")]
    route2: bool,

    /// Fetch the RIB in `NET_RT_DUMP` RIB format.
    #[clap(long = "rt")]
    route: bool,
}

impl Ty {
    fn get(&self) -> Option<DumpType> {
        if self.interface2 {
            Some(DumpType::Interface2)
        } else if self.interface {
            Some(DumpType::Interface)
        } else if self.route2 {
            Some(DumpType::Route2)
        } else if self.route {
            Some(DumpType::Route)
        } else {
            None
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ts_cli_util::init_tracing();

    let args = Args::parse();

    let rib = load_rib(&args)?;
    tracing::debug!(rib_len = rib.len());

    let mut iter = nom::combinator::iterator(
        rib.as_slice(),
        nom::combinator::complete(net_table::msg_chunk()),
    );
    for chunk in &mut iter {
        let (rest, (_ty, hdr)) =
            net_table::MessageHeader::parse(chunk).map_err(|e| format!("{e}"))?;

        tracing::info!(?hdr);

        let mut iter =
            nom::combinator::iterator(rest, nom::combinator::complete(partial_sockaddr()));

        for (addr, flag) in (&mut iter).zip(hdr.addrs().iter()) {
            tracing::info!(?flag, ?addr, "ADDR");
        }

        let rest = finish_iter(iter)?;
        assert!(rest.is_empty());
    }

    let rest = finish_iter(iter)?;
    assert!(rest.is_empty());

    Ok(())
}

fn load_rib(args: &Args) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(in_file) = &args.in_file {
        let mut rib = vec![];

        let mut f = std::fs::File::open(in_file)?;
        f.read_to_end(&mut rib)?;

        Ok(rib)
    } else {
        let rib = net_table::dump(
            FamilyOrBoth::Both,
            args.ty.get().unwrap_or(DumpType::Interface2),
            0,
        )?;

        if let Some(out_file) = &args.out_file {
            use std::io::Write;
            let mut f = std::fs::File::create(out_file)?;
            f.write_all(&rib)?;
        }

        Ok(rib)
    }
}

fn finish_iter<'i, F>(
    iter: ParserIterator<&'i [u8], nom::error::Error<&'i [u8]>, F>,
) -> Result<&'i [u8], nom::Err<nom::error::Error<Vec<u8>>>> {
    match iter.finish() {
        Err(ref e @ (nom::Err::Error(ref inner) | nom::Err::Failure(ref inner)))
            if !inner.input.is_empty() =>
        {
            panic!("{e}");
        }
        Err(e) => {
            tracing::warn!("{e}");
            Ok(&[])
        }
        x => x.map(|x| x.0).map_err(|e| e.to_owned()),
    }
}
