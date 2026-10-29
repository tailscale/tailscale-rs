// Helpers shared by the wrapper classes. Nothing here is part of the public API.

import { isIP } from "node:net";

import * as native from "../native.js";
import { argError, convertError } from "./errors.js";
import type { AddressInfo, SocketAddress } from "./types.js";

/**
 * Call a native operation, converting its errors and, if `signal` is given, cancelling it when
 * `signal` is aborted. If the operation has already completed by then, its result is returned.
 */
export async function call<T>(
  op: (cancel?: native.CancelToken) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal === undefined) {
    try {
      return await op();
    } catch (e) {
      throw convertError(e);
    }
  }

  signal.throwIfAborted();
  const token = new native.CancelToken();
  const onAbort = () => {
    token.cancel();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    return await op(token);
  } catch (e) {
    throw signal.aborted ? signal.reason : convertError(e);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

/** Validate an IP address argument. */
export function checkIp(ip: unknown, name: string): string {
  if (typeof ip !== "string") {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", `${name} must be a string`);
  }
  if (isIP(ip) === 0) {
    throw argError(TypeError, "ERR_INVALID_IP_ADDRESS", `Invalid IP address: ${ip}`);
  }
  return ip;
}

/** Validate a socket address argument. */
//
// Arguments are `unknown` because JS callers may pass anything, whatever the declared types say.
export function checkAddress(addr: unknown): native.SocketAddress {
  if (typeof addr !== "object" || addr === null) {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", "address must be an object");
  }
  const { address, port } = addr as Partial<Record<keyof SocketAddress, unknown>>;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 0 || port > 65535) {
    throw argError(
      RangeError,
      "ERR_SOCKET_BAD_PORT",
      `Port should be >= 0 and < 65536. Received ${String(port)}.`,
    );
  }
  return { address: checkIp(address, "address.address"), port };
}

/** Validate a data argument, encoding strings as UTF-8. */
export function checkData(data: unknown): Uint8Array {
  if (typeof data === "string") {
    return Buffer.from(data);
  }
  if (!(data instanceof Uint8Array)) {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", "data must be a string or Uint8Array");
  }
  return data;
}

/** Format an address as `ip:port`, bracketing IPv6 addresses. */
export function formatAddress({ address, family, port }: AddressInfo): string {
  return family === "IPv6" ? `[${address}]:${port}` : `${address}:${port}`;
}
