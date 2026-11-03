# Example: TCP

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A TCP echo server and client. The [server](server.ts) listens on a port and, for each connection,
sends back every line it receives in upper case; the [client](client.ts) connects to the server
over the tailnet, sends it each line typed into the terminal, and prints the replies.

To run the example, first, build the node.js package (see [Developing](../../README.md#developing)),
then start the server:

```sh
# Terminal 1
$ ./server.ts $AUTH_KEY_1 5678
...
listening: tailscale.TcpListener(<server IPv4>:5678)
```

Then, in another terminal, start the client and type some lines:

```sh
# Terminal 2
$ ./client.ts $AUTH_KEY_2 <server IPv4> 5678
...
connected: tailscale.TcpStream(<client IPv4>:<port> -> <server IPv4>:5678)
hello
HELLO
```

Press Ctrl-D to close the connection, and Ctrl-C to stop the server.

If you can't get the client and server to communicate, verify the tailnet policy allows the client
access to the server's tailnet IP address on TCP port 5678.
