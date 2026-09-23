//! Print routes gathered using iphlpapi.

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    use ts_netmon::{FamilyOrBoth, Route, windows::RouteTable};

    ts_cli_util::init_tracing();

    let start = Instant::now();
    let mut rt = RouteTable::get(FamilyOrBoth::Both)?;

    const MEASURE_TIMING: bool = false;

    for row in rt.iter_mut() {
        ts_netmon::windows::populate_route(row)?;

        let route = Route::from(&*row);

        if MEASURE_TIMING {
            core::hint::black_box(route);
        } else {
            tracing::info!(?route);
        }
    }
    let elapsed = start.elapsed();

    // On my machine each route costs about 70µs to load in release mode. The most expensive part of
    // that (~45μs) is loading the route itself, getting the interface metric costs about 10μs, so
    // I don't think it's worth caching.
    tracing::info!(?elapsed, per_route = ?(elapsed / rt.len() as u32), "dumped routes");

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("this example is a no-op on non-windows targets")
}
