# Example: TCP Echo

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A TCP server that listens on the tailnet and echoes input back to the sender.

For this example, you can use netcat (`nc`) to test the server. First, start the example:

```sh
# Terminal 1
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example tcp_echo -- --auth-key $AUTH_KEY --key-file tsrs_keys.json 
...
INFO tcp_echo: listening_addr=<tailnet IP>:1234
...
```

Then, in another terminal, connect to it with `nc`, type a message, and hit enter:

```sh
# Terminal 2
$ nc <tailnet IP> 1234
hello, tailscale-rs!
hello, tailscale-rs!
```

After hitting enter, you should see your message echoed back to you in netcat!

If you can't connect to the example with netcat, verify the tailnet policy allows your local
machine to connect to the example's tailnet IP address on TCP port 1234.
