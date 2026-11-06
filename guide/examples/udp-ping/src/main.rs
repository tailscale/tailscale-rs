use std::{net::Ipv4Addr, time::Duration};

use tailscale::{Config, Device};

#[tokio::main]
async fn main() {
    // A `Config` contains details about the node on the tailnet being created.
    let config = Config::default();

    // Open a new connection to the tailnet.
    let device = Device::new(
        &config,
        // The auth key gives the device access to the tailnet.
        Some("YOUR_AUTH_KEY_HERE".to_owned()),
    )
    .await
    .unwrap();

    // Bind a UDP socket on our tailnet IP, port 1234.
    let socket_address = (device.ipv4_addr().await.unwrap(), 1234).into();
    let socket = device.udp_bind(socket_address).await.unwrap();

    // Send to `100.64.0.1:5678`.
    let dest_address = (Ipv4Addr::new(100, 64, 0, 1), 5678).into();
    // Send a packet containing "ping" once per second.
    loop {
        socket.send_to(dest_address, b"ping").await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
