# Example: UDP

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A UDP sender and receiver. The [sender](send.ts) binds to a port and sends datagrams to the [receiver](recv.ts)
over a tailnet; the receiver binds to a port and prints any messages it receives.

First, build the package (see [Developing](../../README.md#developing)), then start the receiver:

```sh
# Terminal 1
$ ./recv.ts $AUTH_KEY_1 5678
...
[<recv IPv4>:5678] udp bound, local endpoint: tailscale.UdpSocket(<recv IPv4>:5678)
...
```

Then, in another terminal, start the sender:

```sh
# Terminal 2
$ ./send.ts $AUTH_KEY_2 <recv IPv4> 5678
...
[<send IPv4>:1234] udp bound, local endpoint: tailscale.UdpSocket(<send IPv4>:1234)
[<send IPv4>:1234-><recv IPv4>:5678|0001] sent message: HELLO
[<send IPv4>:1234-><recv IPv4>:5678|0002] sent message: HELLO
...
```

After a short period of time, you should start seeing the following messages in the receiver terminal:

```sh
# Terminal 1
...
[<recv IPv4>:5678<-<send IPv4>:1234|0082] received message: HELLO
[<recv IPv4>:5678<-<send IPv4>:1234|0083] received message: HELLO
```

If you can't get the sender and receiver to communicate, verify the tailnet policy allows the sender
access to the receiver's tailnet IP address on UDP port 5678.
