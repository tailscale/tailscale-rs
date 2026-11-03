import { inspect } from "node:util";

import * as native from "../native.js";
import { argError, convertError } from "./errors.js";

/** Keys for a {@link KeyState}. Any which are omitted are randomly generated. */
export interface KeyStateInit {
  /** Machine private key (32 bytes). */
  machine?: Uint8Array;
  /** Node (device) private key (32 bytes). */
  node?: Uint8Array;
  /** Network lock private key (32 bytes). */
  networkLock?: Uint8Array;
}

/** The JSON form of a {@link KeyState}: its private keys, hex-encoded. */
export interface KeyStateJSON {
  /** Machine private key. */
  machine: string;
  /** Node (device) private key. */
  node: string;
  /** Network lock private key. */
  networkLock: string;
}

/** A node's public keys, hex-encoded. */
export interface PublicKeys {
  /** Machine public key. */
  machine: string;
  /** Node (device) public key. */
  node: string;
  /** Network lock public key. */
  networkLock: string;
}

const KEY_LENGTH = 32;

/**
 * A node's private keys.
 *
 * `toString` and `util.inspect` (and so `console.log`) only show public keys; the private keys are
 * available from the properties and `toJSON`.
 */
export class KeyState {
  readonly #keys: native.Keys;

  /**
   * Create a key state from the given keys, randomly generating any which are omitted.
   *
   * @throws {RangeError} If a key isn't 32 bytes long.
   */
  constructor(init: KeyStateInit = {}) {
    // Only generate keys if some are missing.
    let generated: native.Keys | undefined;
    const generate = () => (generated ??= native.generateKeys());
    this.#keys = {
      machine: copyKey(init.machine, "machine") ?? generate().machine,
      node: copyKey(init.node, "node") ?? generate().node,
      networkLock: copyKey(init.networkLock, "networkLock") ?? generate().networkLock,
    };
  }

  /**
   * Create a key state from its JSON form, as produced by `toJSON` (and so `JSON.stringify`).
   *
   * @throws {TypeError} If a key isn't a string.
   * @throws {RangeError} If a key isn't 32 bytes of hex.
   */
  static fromJSON(json: KeyStateJSON): KeyState {
    return new KeyState({
      machine: fromHex(json.machine, "machine"),
      node: fromHex(json.node, "node"),
      networkLock: fromHex(json.networkLock, "networkLock"),
    });
  }

  /** Machine private key. */
  get machine(): Buffer {
    return Buffer.from(this.#keys.machine);
  }

  /** Node (device) private key. */
  get node(): Buffer {
    return Buffer.from(this.#keys.node);
  }

  /** Network lock private key. */
  get networkLock(): Buffer {
    return Buffer.from(this.#keys.networkLock);
  }

  /** The public keys, hex-encoded. */
  get publicKeys(): PublicKeys {
    try {
      return native.publicKeys(this.#keys);
    } catch (e) {
      throw convertError(e);
    }
  }

  /**
   * The private keys, hex-encoded. Note that this means `JSON.stringify` includes the private keys.
   */
  toJSON(): KeyStateJSON {
    return {
      machine: this.#keys.machine.toString("hex"),
      node: this.#keys.node.toString("hex"),
      networkLock: this.#keys.networkLock.toString("hex"),
    };
  }

  /** Describe the key state, showing only public keys. */
  toString(): string {
    const { machine, node, networkLock } = this.publicKeys;
    return `tailscale.KeyState(machine=${machine}, node=${node}, networkLock=${networkLock})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }

  /** @internal The keys, for passing to the native layer. */
  get raw(): native.Keys {
    return this.#keys;
  }
}

function copyKey(key: unknown, name: string): Buffer | undefined {
  if (key === undefined) {
    return undefined;
  }
  if (!(key instanceof Uint8Array)) {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", `${name} key must be a Uint8Array`);
  }
  if (key.length !== KEY_LENGTH) {
    throw argError(
      RangeError,
      "ERR_INVALID_ARG_VALUE",
      `${name} key must be ${KEY_LENGTH} bytes, got ${key.length}`,
    );
  }
  return Buffer.from(key);
}

function fromHex(hex: unknown, name: string): Buffer {
  if (typeof hex !== "string") {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", `${name} key must be a string`);
  }
  // `Buffer.from` would silently ignore a trailing odd digit, or anything after a non-hex digit.
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
    throw argError(RangeError, "ERR_INVALID_ARG_VALUE", `${name} key must be hex`);
  }
  return Buffer.from(hex, "hex");
}
