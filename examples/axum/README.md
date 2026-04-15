# Example: Axum

> [!NOTE] See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

An `axum`-based HTTP server that serves a simple webpage over the tailnet. This example requires
`tailscale-rs` to be compiled with the `axum` feature:

```sh
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example axum --features axum -- --auth-key $AUTH_KEY --key-file key_file.json
...
INFO axum: http server listening url=http://<tailnet IP>:80/index.html
```

To test, ensure your local Tailscale client is connected to the same tailnet as the `axum` example,
then visit "http://<tailnet IP>:80/index.html" in your browser.

If you can't connect, verify the tailnet policy is configured to allow your local machine access to
the example's tailnet IP address on TCP port 80.
