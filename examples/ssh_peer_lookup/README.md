# example: ssh peer lookup

Run an SSH server hosting a TUI that lets connecting clients look up info about peers in the
tailnet.

Please be aware there's currently no auth checking implemented beyond what's globally provided by
tailscale-rs and network packet filters. The ssh policy file block is not consulted.

The server key is randomized on each start, so you will likely want to connect using
`-o StrictHostKeyChecking=no`.

## Example usage

```shell
$ cargo run --example ssh_peer_lookup --features ssh -- -k $MY_AUTH_KEY -c $MY_CONFIG_FILE
...
INFO tailscale::ssh: ssh server listening listen_addr=$TAILNET_IP:1234
...

# in another terminal:
$ ssh $TAILNET_IP -p 1234 -o StrictHostKeyChecking=no
```
