use std::io::Read;

fn load_prefixes() -> Vec<ipnet::IpNet> {
    // This is the same prefixes file that bart uses.
    const PREFIXES: &[u8] = include_bytes!("prefixes.txt.gz");

    let mut content = String::new();
    let mut decoder = flate2::read::GzDecoder::new(PREFIXES);
    decoder.read_to_string(&mut content).unwrap();

    let mut result = content
        .lines()
        .map(|line| line.trim())
        .map(|line| line.parse::<ipnet::IpNet>().unwrap().trunc())
        .collect::<Vec<_>>();

    result.sort_by(|x, y| {
        let xa = x.addr();
        let ya = y.addr();

        // IPv4 first, then by prefix len, then by address
        xa.is_ipv4()
            .cmp(&ya.is_ipv4())
            .reverse()
            .then(x.prefix_len().cmp(&y.prefix_len()))
            .then(xa.cmp(&ya))
    });

    let pre_dedup_len = result.len();
    result.dedup();
    if pre_dedup_len != result.len() {
        eprintln!(
            "warn: deduplication of prefixes eliminated {} duplicates",
            pre_dedup_len - result.len()
        );
    }

    result
}

lazy_static::lazy_static! {
    pub static ref PREFIXES: Vec<ipnet::IpNet> = load_prefixes();

    pub static ref PREFIXES_V4: Vec<ipnet::IpNet> = {
        PREFIXES.iter().filter(|x| x.addr().is_ipv4()).copied().collect()
    };

    pub static ref PREFIXES_V6: Vec<ipnet::IpNet> = {
        PREFIXES.iter().filter(|x| x.addr().is_ipv6()).copied().collect()
    };
}

#[allow(dead_code)]
pub type TableContents = ();
#[allow(dead_code)]
pub type Node<Storage> = ts_bart::Node<TableContents, Storage>;

#[allow(dead_code)]
pub type SimpleTable<Storage> = ts_bart::table::SimpleTable<Node<Storage>>;
#[allow(dead_code)]
pub type Table<Storage> = ts_bart::table::SplitStackTable<Node<Storage>>;

#[allow(dead_code)]
pub const fn dummy_contents() -> TableContents {
    // core::net::IpAddr::V4(core::net::Ipv4Addr::new(0, 0, 0, 0))
}

macro_rules! mk_table {
    ($name:ident, $table:ty, $pfxs:expr) => {
        lazy_static::lazy_static! {
            pub static ref $name: $table = {
                let mut table: $table = ::core::default::Default::default();

                for &pfx in &*$pfxs {
                    use ::ts_bart::RoutingTable;
                    table.insert(pfx, dummy_contents());
                }

                table
            };
        }
    };
}

// smallvecs can't be sized with inline storage
#[cfg(not(feature = "smallvec"))]
mod _inline {
    use super::*;

    mk_table!(
        SIMPLE_INLINE_V4,
        SimpleTable<ts_bart::InlineStorage>,
        PREFIXES_V4
    );
    mk_table!(
        SIMPLE_INLINE_V6,
        SimpleTable<ts_bart::InlineStorage>,
        PREFIXES_V6
    );

    mk_table!(TABLE_INLINE_V4, Table<ts_bart::InlineStorage>, PREFIXES_V4);
    mk_table!(TABLE_INLINE_V6, Table<ts_bart::InlineStorage>, PREFIXES_V6);
    mk_table!(TABLE_INLINE_FULL, Table<ts_bart::InlineStorage>, PREFIXES);
}
#[cfg(not(feature = "smallvec"))]
pub use _inline::*;

mod _boxed {
    use super::*;

    mk_table!(SIMPLE_BOX_V4, SimpleTable<ts_bart::BoxStorage>, PREFIXES_V4);
    mk_table!(SIMPLE_BOX_V6, SimpleTable<ts_bart::BoxStorage>, PREFIXES_V6);

    mk_table!(TABLE_BOX_V4, Table<ts_bart::BoxStorage>, PREFIXES_V4);
    mk_table!(TABLE_BOX_V6, Table<ts_bart::BoxStorage>, PREFIXES_V6);
    mk_table!(TABLE_BOX_FULL, Table<ts_bart::BoxStorage>, PREFIXES);
}
pub use _boxed::*;
