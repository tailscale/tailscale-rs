# `ts_nodejs`

Node.js (TypeScript or JavaScript) bindings for `tailscale-rs`, using [napi-rs](https://napi.rs).

Currently exposes facilities for connecting to a tailnet and binding network sockets with access to
a tailnet.

## Example

```ts
import { setTimeout as sleep } from "node:timers/promises";
import { connect } from "tailscale-rs";

// connect to the tailnet:
const dev = await connect({ keyFile: "tsrs_keys.json", authKey: "tskey-auth-$MY_AUTH_KEY" });

// bind a udp socket on this node's ipv4 address:
const tailnetIpv4 = await dev.ipv4Address();
const udpSock = await dev.udpBind({ address: tailnetIpv4, port: 1234 });
console.log(`udp bound, local endpoint: ${udpSock}`);

// send a message to a peer once per second
while (true) {
  await udpSock.sendTo({ address: "1.2.3.4", port: 5678 }, "HELLO");
  console.log("sent message to peer");
  await sleep(1000);
}
```

See [`examples`](examples/README.md) for more.

## Usage

### Setup

TODO: tailscale-rs is not yet published.

```sh
$ npm install tailscale-rs
```

The package ships its own TypeScript definitions. They use Node's `Buffer` and `stream` types, so
TypeScript projects need [`@types/node`](https://www.npmjs.com/package/@types/node):

```sh
$ npm install --save-dev typescript @types/node
```

The package works with both ES modules and CommonJS, and with any of TypeScript's
`"moduleResolution"` settings: `"nodenext"` / `"node16"` or `"bundler"`.

```ts
// ES modules (`.ts` with `"type": "module"`, or `.mts`):
import { connect, KeyState, type Device } from "tailscale-rs";

// CommonJS (`.cts`, or `.ts` without `"type": "module"`), compiled with `tsc`:
import tailscale = require("tailscale-rs");
```

### Exports

| Export                                       | Kind            | Description                                                                                 |
| -------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------- |
| `connect(options?)`                          | function        | Connect to a tailnet; returns `Promise<Device>`                                             |
| `ConnectOptions`                             | interface       | `keyFile`, `authKey`, `controlServerUrl`, `hostname`, `tags`, `keys`, `ephemeral`, `signal` |
| `Device`                                     | class           | A connected tailscale node: bind sockets, look up peers                                     |
| `UdpSocket`                                  | class           | `sendTo`, `recvFrom`, `address`, `close`; async iterable of `Datagram`s                     |
| `Datagram`                                   | interface       | `{ data: Buffer, from: AddressInfo }`, returned by `UdpSocket.recvFrom`                     |
| `TcpListener`                                | class           | `accept`, `address`, `close`; async iterable of `TcpStream`s                                |
| `TcpStream`                                  | class           | A `stream.Duplex`, with `net.Socket`'s address properties                                   |
| `SocketAddress`                              | interface       | `{ address: string, port: number }`, passed to the library                                  |
| `AddressInfo`                                | interface       | `{ address: string, family: "IPv4" \| "IPv6", port: number }`, returned by the library      |
| `AbortOptions`                               | interface       | `{ signal?: AbortSignal }`                                                                  |
| `NodeInfo`                                   | interface       | Information about a node, returned by `Device.selfNode`, `Device.peerByName`, etc.          |
| `KeyState`                                   | class           | A node's keys; `new KeyState()` generates fresh ones                                        |
| `KeyStateInit`, `KeyStateJSON`, `PublicKeys` | interfaces      | Keys passed to and returned from `KeyState`                                                 |
| `TailscaleError`                             | class           | The `Error` subclass thrown by the library                                                  |
| `ErrorCode`                                  | object and type | The `code`s of `TailscaleError`s                                                            |

IP addresses are strings. DNS names aren't supported yet, so addresses must be IP addresses. Data
can be passed as a `Uint8Array` (including a `Buffer`) or a string, which is UTF-8 encoded. Data is
returned as a `Buffer`. Peer lookups (e.g. `Device.peerByName`) resolve to `null` if there's no such
peer.

### Sockets

UDP sockets and TCP listeners are async iterables, which end when the socket is closed:

```ts
const sock = await dev.udpBind({ address: await dev.ipv4Address(), port: 5678 });
for await (const { data, from } of sock) {
  await sock.sendTo(from, data);
}

const listener = await dev.tcpListen({ address: await dev.ipv4Address(), port: 80 });
for await (const conn of listener) {
  conn.pipe(conn);
}
```

`TcpStream` is a `stream.Duplex`, so it works with `pipe`, `stream.pipeline`, `readline`,
`for await`, and so on:

```ts
import { text } from "node:stream/consumers";

const conn = await dev.tcpConnect({ address: "100.64.0.2", port: 80 });
conn.write("GET / HTTP/1.0\r\n\r\n");
// The server closes the connection after responding, which ends the stream.
console.log(await text(conn));
```

`end()` closes the sending half of the connection once written data has been sent, but data can
still be read until the peer closes its half. Like a `net.Socket` with `allowHalfOpen: false`, a
`TcpStream` ends its sending half automatically when the peer closes its half.

### Closing resources

Devices, sockets, and listeners can be closed explicitly with `close()` (or `destroy()` for a
`TcpStream`), or with `await using` (TypeScript 5.2+, or Node.js 24+). If not
closed, they will be closed when garbage collected, but you shouldn't rely on this.

Closing a socket rejects its pending operations with a `TailscaleError` with code
`ERR_SOCKET_CLOSED`, and ends any iteration over it. `Device.close()` disconnects from the tailnet.

### Cancellation

`connect`, `Device.tcpConnect`, `TcpListener.accept` and `UdpSocket.recvFrom` take an
`AbortSignal`. When it's aborted, the operation is cancelled and rejects with `signal.reason`. If
the operation has already completed by then, it resolves as usual, so that, e.g., an accepted
connection or a received datagram isn't lost. E.g.,

```ts
// Wait at most 5 seconds for a datagram.
const datagram = await sock.recvFrom({ signal: AbortSignal.timeout(5000) });
```

### Error handling

Errors from tailscale operations are `TailscaleError`s, whose `code` is an `ErrorCode`:

| `ErrorCode`       | `code`                            | Meaning                                                            |
| ----------------- | --------------------------------- | ------------------------------------------------------------------ |
| `AuthKeyRejected` | `ERR_TAILSCALE_AUTH_KEY_REJECTED` | The control server rejected the auth key                           |
| `KeyFileRead`     | `ERR_TAILSCALE_KEY_FILE_READ`     | The key file couldn't be read or parsed                            |
| `KeyFileWrite`    | `ERR_TAILSCALE_KEY_FILE_WRITE`    | The key file couldn't be written                                   |
| `Timeout`         | `ERR_TAILSCALE_TIMEOUT`           | An operation timed out                                             |
| `ConnectionReset` | `ECONNRESET`                      | A connection was reset, or couldn't be established                 |
| `BadRequest`      | `ERR_TAILSCALE_BAD_REQUEST`       | The request was rejected, e.g. sending to IPv6 from an IPv4 socket |
| `SocketClosed`    | `ERR_SOCKET_CLOSED`               | The socket or device was closed                                    |
| `Internal`        | `ERR_TAILSCALE_INTERNAL`          | An internal error, likely a bug                                    |

Invalid arguments are reported as a `TypeError` or `RangeError`, with a `code` such as
`ERR_INVALID_ARG_TYPE`, `ERR_INVALID_IP_ADDRESS`, `ERR_SOCKET_BAD_PORT` or `ERR_INVALID_URL`.
Functions which return a promise reject it, rather than throwing.

### Logging

Enable logging by setting the `RUST_LOG` environment variable, e.g. `RUST_LOG=info`. See
[`tracing_subscriber`'s docs](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
for the syntax.

## Developing

### Setup

1. Install an appropriate Rust toolchain for your platform.
2. Install [Node.js](https://nodejs.org/) 22.13 or later. Using the package only needs Node.js
   18.18, but the development tools (ESLint, napi-rs's CLI) need 22.13.
3. Clone the `tailscale-rs` repository.
4. Install the build tooling ([`@napi-rs/cli`](https://www.npmjs.com/package/@napi-rs/cli),
   TypeScript, Prettier, ESLint) using `npm install`. Build using `npm run build:debug`.

### Design

The package has two layers:

- **The native layer** (`src/`, Rust): a napi-rs addon wrapping the `tailscale` crate. Building it
  produces `tailscale.<platform>.node` (the addon), `native.js` (its loader) and `native.d.ts`
  (its TypeScript definitions). This layer is internal, and isn't designed to be idiomatic JS.
- **The public API** (`lib/`, TypeScript): wraps the native layer in idiomatic JS.

The native layer can only give errors a napi status as their `code`, so it puts the real code at the
start of the message instead (see `src/error.rs`); `lib/errors.ts` converts them into
`TailscaleError`s etc.

### Testing

Use `npm run typecheck` to type-check the bindings, tests, and examples. Then, `npm test` to run tests.

`test/types.test.ts` holds compile-time assertions about the public API's types; add to it when
changing the API.

`test/net.test.ts` needs a tailnet, so is skipped unless `TS_RS_TEST_NET=1`, with a reusable auth
key in `TS_RS_TEST_AUTHKEY`.

### Formatting and linting

Use `npm run format` to format code using [Prettier](https://prettier.io), or `npm run format:check`
to check formatting.

Use `npm run lint` to lint using [ESLint](https://eslint.org) and
[typescript-eslint](https://typescript-eslint.io).

CI requires formatting and linting to pass.
