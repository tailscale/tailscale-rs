// The public API of the `tailscale-rs` package.

export { connect, type ConnectOptions, Device, type NodeInfo } from "./device.js";
export { ErrorCode, TailscaleError } from "./errors.js";
export { KeyState, type KeyStateInit, type KeyStateJSON, type PublicKeys } from "./keys.js";
export { TcpListener, TcpStream } from "./tcp.js";
export type { AbortOptions, AddressInfo, SocketAddress } from "./types.js";
export { type Datagram, UdpSocket } from "./udp.js";
