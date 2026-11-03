import assert from "node:assert/strict";
import { test } from "node:test";

import { connect, ErrorCode, KeyState, TailscaleError } from "../dist/index.js";

test("ErrorCode values follow Node's conventions", () => {
  for (const code of Object.values(ErrorCode)) {
    assert.match(code, /^(ERR_[A-Z_]+|E[A-Z]+)$/);
  }
  assert.equal(ErrorCode.ConnectionReset, "ECONNRESET");
});

test("TailscaleError is a real Error class", () => {
  const e = new TailscaleError(ErrorCode.Timeout, "timed out");
  assert.ok(e instanceof Error);
  assert.ok(e instanceof TailscaleError);
  assert.equal(e.name, "TailscaleError");
  assert.equal(e.code, "ERR_TAILSCALE_TIMEOUT");
  assert.equal(e.message, "timed out");
  assert.match(String(e.stack), /^TailscaleError: timed out/);
});

test("connect rejects an invalid control server URL with ERR_INVALID_URL", async () => {
  await assert.rejects(connect({ controlServerUrl: "not a url" }), {
    name: "TypeError",
    code: "ERR_INVALID_URL",
  });
});

test("connect rejects keys which aren't a KeyState", async () => {
  const keys = { machine: Buffer.alloc(32), node: Buffer.alloc(32), networkLock: Buffer.alloc(32) };
  // @ts-expect-error Keys must be a KeyState.
  await assert.rejects(connect({ keys }), { name: "TypeError", code: "ERR_INVALID_ARG_TYPE" });
});

test("connect rejects with the signal's reason when aborted before starting", async () => {
  const reason = new Error("stop");
  await assert.rejects(connect({ signal: AbortSignal.abort(reason) }), (e) => e === reason);
});

test("connect rejects with the signal's reason when aborted while connecting", async () => {
  // Nothing listens on the discard port, so connecting never completes.
  const promise = connect({
    keys: new KeyState(),
    controlServerUrl: "http://127.0.0.1:9",
    signal: AbortSignal.timeout(100),
  });
  await assert.rejects(promise, { name: "TimeoutError" });
});
