use alloc::{collections::BTreeMap, vec::Vec};

use ipnet::IpNet;
use serde::Deserializer;
use ts_peercapability::Name;

/// Grants application capabilities for a set of destination IP prefixes in a
/// [`FilterRule`][crate::FilterRule].
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CapGrant<'a> {
    /// The destination prefixes that this grant matches.
    pub dsts: Vec<IpNet>,

    /// The capabilities granted to traffic originating from
    /// [`ApplicationRule::src_ips`][crate::AppRule::src_ips] and destined
    /// for [`dsts`][CapGrant::dsts].
    #[serde(borrow, rename = "CapMap", serialize_with = "cap_map::serialize")]
    pub peer_caps: ts_peercapability::Map<'a>,
}

impl<'a, 'de: 'a> serde::Deserialize<'de> for CapGrant<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct DeserCapGrant<'a> {
            dsts: Vec<IpNet>,

            #[serde(borrow, default)]
            caps: Vec<Name<'a>>,

            #[serde(borrow, default)]
            cap_map: BTreeMap<Name<'a>, Option<Vec<&'a serde_json::value::RawValue>>>,
        }

        let DeserCapGrant {
            caps,
            cap_map,
            dsts,
        } = DeserCapGrant::deserialize(deserializer)?;

        let peer_caps = cap_map
            .into_iter()
            .map(|(cap, val)| {
                (
                    cap,
                    val.unwrap_or_default()
                        .into_iter()
                        .map(|x| x.get())
                        .collect(),
                )
            })
            .chain(caps.into_iter().map(|cap| (cap, Vec::new())))
            .collect::<BTreeMap<_, _>>();

        Ok(Self { dsts, peer_caps })
    }
}

mod cap_map {
    use serde::ser::{Error, SerializeMap, SerializeSeq};

    pub fn serialize<S>(cap_map: &ts_peercapability::Map, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        struct SeqRawJsonSer<'a, 's>(&'a [&'s str]);

        impl<'a, 's> serde::Serialize for SeqRawJsonSer<'a, 's> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut ser = serializer.serialize_seq(Some(self.0.len()))?;

                for &s in self.0 {
                    let value = serde_json::from_str::<&serde_json::value::RawValue>(s)
                        .map_err(S::Error::custom)?;

                    ser.serialize_element(value)?;
                }

                ser.end()
            }
        }

        let mut mapser = serializer.serialize_map(Some(cap_map.len()))?;
        for (k, v) in cap_map {
            mapser.serialize_entry(k, &SeqRawJsonSer(v))?;
        }

        mapser.end()
    }
}

#[cfg(test)]
mod test {
    use alloc::collections::BTreeMap;

    use super::*;

    const TEST_CAP_MAP: &str = r#"
    {
        "Dsts": [],
        "CapMap": {
            "a": null, 
            "b": ["some value", null, 12, 1234.5678, false, {}, []]
        }
    }
    "#;

    const TEST_CAPS: &str = r#"
    {
        "Dsts": [],
        "Caps": ["c", "d"]
    }
    "#;

    const TEST_BOTH: &str = r#"
    {
        "Dsts": [],
        "CapMap": {
            "a": null,
            "b": ["some value"]
        },
        "Caps": ["c", "d"]
    }
    "#;

    fn assert_deserialize(
        test_str: &str,
        caps: impl IntoIterator<Item = (&'static str, &'static [&'static str])>,
    ) {
        let grant = serde_json::from_str::<CapGrant>(test_str).unwrap();

        let expected_peercaps = caps
            .into_iter()
            .map(|(k, v)| (Name::from(k), v.to_vec()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            CapGrant {
                dsts: alloc::vec![],
                peer_caps: expected_peercaps,
            },
            grant
        );
    }

    #[test]
    fn deserialize_cap_map() {
        assert_deserialize(
            TEST_CAP_MAP,
            [
                ("a", &[][..]),
                (
                    "b",
                    &[
                        "\"some value\"",
                        "null",
                        "12",
                        "1234.5678",
                        "false",
                        "{}",
                        "[]",
                    ][..],
                ),
            ],
        );
    }

    #[test]
    fn deserialize_caps() {
        assert_deserialize(TEST_CAPS, [("c", &[][..]), ("d", &[][..])]);
    }

    #[test]
    fn deserialize_caps_and_cap_map() {
        assert_deserialize(
            TEST_BOTH,
            [
                ("a", &[][..]),
                ("b", &["\"some value\""][..]),
                ("c", &[][..]),
                ("d", &[][..]),
            ],
        );
    }
}
