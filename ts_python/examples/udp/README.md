# Example: UDP

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A UDP sender and receiver. The [sender](send.py) binds to a port and sends datagrams to the [receiver](recv.py) over the
tailnet; the receiver binds to a port and prints any messages it receives.

First, start the receiver:

```sh
# Terminal 1
$ TS_RS_EXPERIMENT=this_is_unstable_software ./recv.py $AUTH_KEY_1 5678
...
[<recv IPv4>:5678] udp bound, local endpoint: ('<recv IPv4>', 5678)
...
```

Then, in another terminal, start the sender:

```sh
# Terminal 2
$ TS_RS_EXPERIMENT=this_is_unstable_software ./send.py $AUTH_KEY_2 <recv IPv4> 5678 
...
[<send IPv4>:1234] udp bound, local endpoint: ('<send IPv4>', 1234)
[<send IPv4>:1234-><recv IPv4>:5678|0001] sent message: b'HELLO'
[<send IPv4>:1234-><recv IPv4>:5678|0002] sent message: b'HELLO'
...
```

After a short period of time, you should start seeing the following messages in the receiver terminal:

```sh
# Terminal 1
...
[<recv IPv4>:5678<-<send IPv4>:1234|0082] received message: b'HELLO'
[<recv IPv4>:5678<-<send IPv4>:1234|0083] received message: b'HELLO'
```

If you can't get the sender and receiver to communicate, verify the tailnet policy allows the sender
access to the receiver's tailnet IP address on UDP port 5678.
