import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";

import { KeyState, type KeyStateJSON } from "../dist/index.js";

test("new KeyState() generates 32-byte keys", () => {
  const keys = new KeyState();
  for (const key of [keys.machine, keys.node, keys.networkLock]) {
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  }
});

test("KeyState uses the keys it's given, generating the rest", () => {
  const machine = new Uint8Array(32).fill(1);
  const keys = new KeyState({ machine });
  assert.deepEqual(keys.machine, Buffer.from(machine));
  assert.notDeepEqual(keys.node, Buffer.alloc(32));
});

test("KeyState copies keys in and out", () => {
  const machine = Buffer.alloc(32, 1);
  const keys = new KeyState({ machine });
  machine.fill(2);
  keys.machine.fill(3);
  assert.deepEqual(keys.machine, Buffer.alloc(32, 1));
});

test("KeyState round-trips through its getters", () => {
  const keys = new KeyState();
  const copy = new KeyState({
    machine: keys.machine,
    node: keys.node,
    networkLock: keys.networkLock,
  });
  assert.deepEqual(copy.toJSON(), keys.toJSON());
  assert.equal(copy.toString(), keys.toString());
});

test("KeyState round-trips through JSON", () => {
  const keys = new KeyState();
  const json = JSON.parse(JSON.stringify(keys)) as KeyStateJSON;
  assert.match(json.machine, /^[0-9a-f]{64}$/);
  const copy = KeyState.fromJSON(json);
  assert.deepEqual(copy.machine, keys.machine);
  assert.deepEqual(copy.node, keys.node);
  assert.deepEqual(copy.networkLock, keys.networkLock);
});

test("KeyState's string forms only show public keys", () => {
  const keys = new KeyState();
  const publicKeys = keys.publicKeys;
  for (const s of [keys.toString(), inspect(keys), String(keys)]) {
    assert.equal(
      s,
      `tailscale.KeyState(machine=${publicKeys.machine}, node=${publicKeys.node}, networkLock=${publicKeys.networkLock})`,
    );
    for (const key of [keys.machine, keys.node, keys.networkLock]) {
      assert.ok(!s.includes(key.toString("hex")));
    }
  }
});

test("KeyState rejects keys of the wrong length", () => {
  assert.throws(() => new KeyState({ node: Buffer.from([1]) }), {
    name: "RangeError",
    code: "ERR_INVALID_ARG_VALUE",
  });
  assert.throws(() => KeyState.fromJSON({ machine: "00", node: "00", networkLock: "00" }), {
    name: "RangeError",
  });
});

test("KeyState.fromJSON rejects keys which aren't hex", () => {
  const valid = new KeyState().toJSON();
  for (const machine of ["xyz", `${valid.machine}f`, `${valid.machine.slice(0, 63)}x`]) {
    assert.throws(() => KeyState.fromJSON({ ...valid, machine }), {
      name: "RangeError",
      code: "ERR_INVALID_ARG_VALUE",
    });
  }
  assert.throws(() => KeyState.fromJSON({ ...valid, machine: 1 as unknown as string }), {
    name: "TypeError",
    code: "ERR_INVALID_ARG_TYPE",
  });
});
