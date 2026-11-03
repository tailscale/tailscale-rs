// Types used throughout the public API.

/** An IP address and port, e.g. `{ address: "100.64.0.1", port: 1234 }`. */
export interface SocketAddress {
  /** IP address, in string form. DNS names are not yet supported. */
  address: string;
  /** Port number. */
  port: number;
}

/** An IP address, address family, and port, like Node's `net.AddressInfo`. */
export interface AddressInfo extends SocketAddress {
  /** Address family. */
  family: "IPv4" | "IPv6";
}

/** Options for operations which can be cancelled. */
export interface AbortOptions {
  /** Cancels the operation, rejecting it with `signal.reason`. */
  signal?: AbortSignal;
}
