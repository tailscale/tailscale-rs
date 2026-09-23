# Tailscale

Experimental bindings to [`tailscale-rs`](https://github.com/tailscale/tailscale-rs) in Elixir.

This software is under active development; we may break the API as we iterate. Please see the [Caveats section of our
README](https://github.com/tailscale/tailscale-rs#caveats) for more information.

## code sample

```elixir
# Connect to tailscale:
{:ok, dev} = Tailscale.connect("tsrs_keys.json", auth_key: "YOUR_AUTH_KEY")
# Fetch our tailnet IPv4:
{:ok, ip} = Tailscale.ipv4_addr(dev)

# Bind a udp socket:
{:ok, sock} = Tailscale.Udp.bind(dev, ip, 1234)
# Send a udp message over the tailnet
:ok = Tailscale.Udp.send(sock, "100.64.0.1", 5678, "hello")
```
