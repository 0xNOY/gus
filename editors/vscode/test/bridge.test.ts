import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";

import { startProviderBridge } from "../src/bridge.js";
import { decodeProviderRequest, type ProviderRegistrationRequest } from "../src/ipc.js";
import type { ProviderScheduler } from "../src/provider.js";

const REPOSITORY = "22".repeat(32);

class FakeProcess extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;

  kill(): boolean {
    this.killed = true;
    return true;
  }
}

class Scheduler implements ProviderScheduler {
  setInterval(): unknown {
    return 1;
  }
  clearInterval(): void {}
  setTimeout(): unknown {
    return 2;
  }
  clearTimeout(): void {}
}

function registration(): ProviderRegistrationRequest {
  return {
    kind: "vscode",
    editor_session_id: "window-1",
    host_instance: "11".repeat(32),
    repositories: [REPOSITORY],
    capabilities: ["profile_quick_pick", "status"],
  };
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

test("bridge spawns without a shell and owns each provider write", async () => {
  const process = new FakeProcess();
  const invocations: unknown[][] = [];
  const failures: Error[] = [];
  const chunks: Buffer[] = [];
  process.stdin.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));

  const client = startProviderBridge({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: registration(),
    picker: { pick: async () => undefined },
    scheduler: new Scheduler(),
    onStatus: () => {},
    onFatal: (error) => failures.push(error),
  }, (executable, commandArguments) => {
    invocations.push([executable, [...commandArguments]]);
    return process as unknown as ChildProcessWithoutNullStreams;
  });
  await settle();

  assert.deepEqual(invocations, [[
    "/opt/gus/bin/gus-provider-bridge",
    ["--runtime-dir", "/run/user/1000/gus"],
  ]]);
  assert.equal(chunks.length, 1);
  assert.equal(decodeProviderRequest(chunks[0]!).message.type, "register");
  assert.deepEqual(failures, []);
  client.close();
  assert(process.killed);
});

test("bridge rejects relative executable and runtime paths before spawn", () => {
  let spawned = false;
  assert.throws(() => startProviderBridge({
    bridgePath: "gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: registration(),
    picker: { pick: async () => undefined },
    scheduler: new Scheduler(),
    onStatus: () => {},
    onFatal: () => {},
  }, () => {
    spawned = true;
    return new FakeProcess() as unknown as ChildProcessWithoutNullStreams;
  }), /must be absolute/u);
  assert.equal(spawned, false);
});

test("unexpected bridge exit closes the provider exactly once", async () => {
  const process = new FakeProcess();
  const failures: Error[] = [];
  startProviderBridge({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: registration(),
    picker: { pick: async () => undefined },
    scheduler: new Scheduler(),
    onStatus: () => {},
    onFatal: (error) => failures.push(error),
  }, () => process as unknown as ChildProcessWithoutNullStreams);
  await settle();
  process.exitCode = 1;
  process.emit("exit", 1, null);
  process.emit("exit", 1, null);
  assert.equal(failures.length, 1);
  assert.match(failures[0]?.message ?? "", /code 1/u);
});

test("transport errors terminate the bridge and report one fatal error", async () => {
  const process = new FakeProcess();
  const failures: Error[] = [];
  startProviderBridge({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: registration(),
    picker: { pick: async () => undefined },
    scheduler: new Scheduler(),
    onStatus: () => {},
    onFatal: (error) => failures.push(error),
  }, () => process as unknown as ChildProcessWithoutNullStreams);
  await settle();

  process.stdin.emit("error", new Error("pipe failed"));
  process.stdin.emit("error", new Error("duplicate"));

  assert(process.killed);
  assert.equal(failures.length, 1);
  assert.match(failures[0]?.message ?? "", /pipe failed/u);
});
