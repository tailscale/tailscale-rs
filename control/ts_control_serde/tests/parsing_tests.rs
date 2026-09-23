#![allow(missing_docs)]

use ts_control_serde::{DerpMap, MapResponse, Node};

#[test]
fn test_map_response_parse() {
    const TEST_MAP_RESPONSE: &str = include_str!("data/map_response.json");

    let resp = serde_json::from_str::<MapResponse>(TEST_MAP_RESPONSE)
        .expect("could not parse MapResponse");
    println!("{resp:#?}");
}

#[test]
fn test_node_parse() {
    const TEST_NODE: &str = include_str!("data/node.json");

    let node = serde_json::from_str::<Node>(TEST_NODE).expect("could not parse Node");
    println!("{node:#?}");
}

/// Validates that a `DerpMap` with "omitDefaultRegions" set is properly parsed.
#[test]
fn test_derp_map_omit_default_regions() {
    const TEST_DERP_MAP: &str = include_str!("data/derp_map_odr.json");

    let map = serde_json::from_str::<DerpMap>(TEST_DERP_MAP)
        .expect("could not parse DerpMap with omit_default_regions");
    assert!(
        map.omit_default_regions,
        "omit_default_regions should be true"
    );
}
