# Tailscale

Experimental bindings to [`tailscale-rs`](https://github.com/tailscale/tailscale-rs) in Elixir.
Please see the warnings there: in short, this is early-days, unstable software containing unaudited
cryptography. **Do not** build production code around this, and please understand that we may break
the API as we iterate.

## code sample

```elixir
# Connect to tailscale:
{:ok, dev} = Tailscale.connect("tsrs_keys.json", "YOUR_AUTH_KEY")
# Fetch our tailnet IPv4:
{:ok, ip} = Tailscale.ip4(dev)

# Bind a udp socket:
{:ok, sock} = Tailscale.Udp.bind(dev, ip, 1234)
# Send a udp message over the tailnet
:ok = Tailscale.Udp.send(sock, "100.64.0.1", 5678, "hello")
```