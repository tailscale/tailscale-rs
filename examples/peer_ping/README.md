# Example: Peer Ping

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A UDP client that sends "hello" to a tailnet peer on a configurable interval.

To run this example, it's easiest to first determine your local machine's tailnet IP address (with
`ip addr` or similar), then use netcat (`nc`) to listen for incoming messages from the running
example:

```sh
# Terminal 1
$ ip addr
...
2: tailscale0: ...
   inet <tailnet IP>
...
$ nc -lu <tailnet IP> 5678
```

Then, in another terminal, run the example:

```sh
# Terminal 2
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example peer_ping -- --auth-key $AUTH_KEY --key-file tsrs_keys.json --peer <tailnet IP>:5678 
...
INFO ts_runtime::multiderp: new home derp region selected region_id=1 latency_ms=12.223305702209473
...
```

Back in the first terminal, you should see "hello" messages appear! If not, verify the tailnet
policy allows the example's tailnet IP address to access your local machine on UDP port 5678. 